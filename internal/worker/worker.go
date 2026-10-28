// Package worker serves the requests of each Unix account from a process of its own.
//
// The front process (weed) terminates TLS, authenticates requests and maps each
// identity to a local account, but never touches the exported files. It hands every
// WebDAV request to the worker of its account: a "weed worker <account>" process
// started with the account's UID, GID and groups, no capabilities and no_new_privs.
// The kernel checks every file access as for the account, and ps, top, /proc and
// cgroups show what each account is doing.
//
// The front process talks HTTP to a worker over socket pairs, passing one end of each
// to the worker through a control socket that the worker inherits. Nothing else can
// connect to a worker, so it trusts the identity that the front process states in
// request headers. Workers report back over the control socket: first that they are
// ready, then the changes to their metrics, which the front process serves.
package worker

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/labkode/weed/internal/auth"
	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/fsuser"
	"github.com/labkode/weed/internal/logger"
)

var errUnsupported = errors.New("only supported on Linux")

// Settings are what the front process starts a worker with
type Settings struct {
	// User is the account the worker must be running as
	User fsuser.User
	// Config is the configuration it serves with, which holds no credentials
	Config config.Config
}

// Info describes a worker process
type Info struct {
	Account  string    `json:"account"`
	UID      int       `json:"uid"`
	PID      int       `json:"pid"`
	Started  time.Time `json:"started"`
	Requests int       `json:"requests"` // in progress
	Retired  bool      `json:"retired"`  // finishing its requests, taking no new ones
}

// Messages from the front process to a worker over the control socket, after the settings
const (
	msgConnection = 0   // with a file descriptor: a new connection
	msgReload     = 'R' // re-read what was read at startup
)

// Headers in which the front process states facts about the requests it forwards
const (
	headerPrefix     = "X-Weed-"
	headerIdentity   = "X-Weed-Identity"
	headerRequestID  = "X-Weed-Request-Id"
	headerRemoteAddr = "X-Weed-Remote-Addr"
	headerTLS        = "X-Weed-Tls"
)

// identity is what a worker learns about who sent a request
type identity struct {
	Username    string   `json:"username"`
	Method      string   `json:"method"`
	NoOverwrite bool     `json:"no_overwrite,omitempty"`
	Directories []string `json:"directories,omitempty"`
}

// stripHeaders removes the headers in which the front process states facts, so that
// clients cannot supply them
func stripHeaders(h http.Header) {
	for k := range h {
		if len(k) >= len(headerPrefix) && strings.EqualFold(k[:len(headerPrefix)], headerPrefix) {
			delete(h, k)
		}
	}
}

// describe states the facts about r, which has been authenticated, in out
func describe(out http.Header, r *http.Request) {
	stripHeaders(out)
	var id identity
	if info, ok := auth.GetAuthInfoFromContext(r.Context()); ok {
		id = identity{Username: info.Username, Method: info.Method, NoOverwrite: info.NoOverwrite, Directories: info.Directories}
	}
	b, _ := json.Marshal(id)
	out.Set(headerIdentity, string(b))
	out.Set(headerRequestID, logger.GetRequestID(r.Context()))
	out.Set(headerRemoteAddr, r.RemoteAddr)
	if r.TLS != nil {
		out.Set(headerTLS, "1")
	}
}

// Handler serves the requests that the front process forwards with next, as they
// were received and authenticated by the front process; u is the worker's account
func Handler(next http.Handler, u *fsuser.User) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var id identity
		if err := json.Unmarshal([]byte(r.Header.Get(headerIdentity)), &id); err != nil || id.Username == "" {
			http.Error(w, "Request without an identity", http.StatusInternalServerError)
			return
		}
		ctx := logger.WithRequestID(r.Context(), r.Header.Get(headerRequestID))
		ctx = auth.SetAuthInfoInContext(ctx, &auth.AuthInfo{
			Username: id.Username, Method: id.Method, NoOverwrite: id.NoOverwrite, Directories: id.Directories, Unix: u,
		})
		r = r.WithContext(ctx)
		r.RemoteAddr = r.Header.Get(headerRemoteAddr)
		if r.Header.Get(headerTLS) != "" {
			// Only whether it was set matters (e.g. for the scheme of Destination URLs)
			r.TLS = &tls.ConnectionState{HandshakeComplete: true}
		}
		stripHeaders(r.Header)
		next.ServeHTTP(w, r)
	})
}

// checkStatus checks the identity and privileges of a thread, from its
// /proc/<pid>/task/<tid>/status: all its user and group IDs (real, effective, saved
// and filesystem) must be u's, its supplementary groups u's groups, and it must have
// no capabilities and no_new_privs set
func checkStatus(status string, u *fsuser.User) error {
	fields := make(map[string]string)
	for _, line := range strings.Split(status, "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			fields[k] = strings.TrimSpace(v)
		}
	}
	ids := func(name string, want int) error {
		got := strings.Fields(fields[name])
		if len(got) != 4 {
			return fmt.Errorf("cannot read its %s IDs", strings.ToLower(name))
		}
		for _, id := range got {
			if id != strconv.Itoa(want) {
				return fmt.Errorf("%s IDs are %s, not all %d", strings.ToLower(name), strings.Join(got, " "), want)
			}
		}
		return nil
	}
	if err := ids("Uid", u.UID); err != nil {
		return err
	}
	if err := ids("Gid", u.GID); err != nil {
		return err
	}
	var groups []int
	for _, g := range strings.Fields(fields["Groups"]) {
		id, err := strconv.Atoi(g)
		if err != nil {
			return fmt.Errorf("cannot read its groups: %q", fields["Groups"])
		}
		groups = append(groups, id)
	}
	want := slices.Clone(u.Groups)
	slices.Sort(groups)
	slices.Sort(want)
	if !slices.Equal(slices.Compact(groups), slices.Compact(want)) {
		return fmt.Errorf("groups are %v, not %v", groups, want)
	}
	for _, set := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
		v, ok := fields[set]
		if !ok && set == "CapAmb" {
			continue // before Linux 4.3, which has no ambient capabilities
		}
		if caps, err := strconv.ParseUint(v, 16, 64); err != nil || caps != 0 {
			return fmt.Errorf("has capabilities (%s: %s)", set, v)
		}
	}
	if fields["NoNewPrivs"] != "1" {
		return errors.New("no_new_privs is not set")
	}
	return nil
}
