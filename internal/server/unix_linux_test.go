//go:build linux

package server

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/fsuser"
	"github.com/labkode/weed/internal/testutil"
)

// Run as root: go test -exec sudo -run UnixUsers ./internal/server

var unixAccounts = map[string]*fsuser.User{
	"alice": {Name: "alice", UID: 6001, GID: 6001, Groups: []int{6001}},
	"bob":   {Name: "bob", UID: 6002, GID: 6002, Groups: []int{6002}},
	"carol": {Name: "carol", UID: 6003, GID: 6003, Groups: []int{6003, 6100}},
}

func TestUnixUsers(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (go test -exec sudo)")
	}
	iss := testutil.NewIssuer(t)
	issuers := iss.WriteIssuers(tokenAudience, "/")
	n := newNode(t, func(cfg *config.Config, _ string) {
		cfg.TokenIssuers = issuers
		cfg.TokenCAPath = iss.CAFile
		cfg.UnixUsers = true
	})
	n.srv.AuthStore.LookupUnixUser = func(name string) (*fsuser.User, error) {
		if u, ok := unixAccounts[name]; ok {
			return u, nil
		}
		return nil, errors.New("no such account")
	}
	// The users must be able to reach the exported directory
	for p := n.dir; p != os.TempDir() && p != "/"; p = filepath.Dir(p) {
		os.Chmod(p, 0755)
	}
	local := func(p string) string { return filepath.Join(n.dir, filepath.FromSlash(p)) }
	setup := func(p string, mode os.FileMode, uid, gid int) {
		if strings.HasSuffix(p, "/") {
			os.Mkdir(local(p), mode)
		} else {
			os.WriteFile(local(p), []byte(p), mode)
		}
		os.Chmod(local(p), mode)
		os.Chown(local(p), uid, gid)
	}
	setup("/alice/", 0755, 6001, 6001)
	setup("/alice/private", 0600, 6001, 6001)
	setup("/alice/public", 0644, 6001, 6001)
	setup("/shared/", 0775, 6002, 6100)
	setup("/shared/bobs", 0644, 6002, 6100)
	setup("/shared/team", 0640, 6002, 6100)

	owner := func(p string) [2]int {
		fi, err := os.Stat(local(p))
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		st := fi.Sys().(*syscall.Stat_t)
		return [2]int{int(st.Uid), int(st.Gid)}
	}
	// alice authenticates with her password (the default), the others with tokens
	as := func(user string) []string {
		return bearer(iss.Token(tokenAudience, "storage.read:/ storage.modify:/", map[string]interface{}{"sub": user}))
	}

	for _, c := range []struct {
		user, method, path string
		headers            []string
		want               int
	}{
		{"alice", "PUT", "/alice/new", nil, 201},
		{"alice", "MKCOL", "/alice/dir", nil, 201},
		{"alice", "COPY", "/alice/public", []string{"Destination", "/webdav/alice/copy"}, 201},
		{"bob", "GET", "/alice/public", nil, 200},
		{"bob", "GET", "/alice/private", nil, 403},
		{"bob", "PUT", "/alice/x", nil, 403},
		{"bob", "MKCOL", "/alice/d", nil, 403},
		{"bob", "DELETE", "/alice/public", nil, 403},
		{"bob", "MOVE", "/alice/public", []string{"Destination", "/webdav/shared/moved"}, 403},
		{"carol", "GET", "/shared/team", nil, 200}, // through a supplementary group
		{"alice", "GET", "/shared/team", nil, 403},
		{"carol", "PUT", "/shared/new", nil, 201},     // group-writable directory
		{"carol", "PUT", "/shared/bobs", nil, 403},    // ...but bob's file is not writable by carol
		{"mallory", "GET", "/alice/public", nil, 403}, // no account
		// A lock would keep the owner from writing
		{"bob", "LOCK", "/alice/public", nil, 403},
		{"bob", "LOCK", "/alice/", nil, 403},
		{"carol", "LOCK", "/shared/", nil, 200},
		{"alice", "LOCK", "/alice/public", nil, 200},
	} {
		headers := c.headers
		if c.user != "alice" {
			headers = append(headers, as(c.user)...)
		}
		body := ""
		switch c.method {
		case "PUT":
			body = c.user + "'s data"
		case "LOCK":
			body = `<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>`
		}
		if resp, msg := n.do(c.method, c.path, body, headers...); resp.StatusCode != c.want {
			t.Errorf("%s: %s %s = %d %q, want %d", c.user, c.method, c.path, resp.StatusCode, msg, c.want)
		}
	}
	for p, want := range map[string][2]int{
		"/alice/new": {6001, 6001}, "/alice/dir": {6001, 6001}, "/alice/copy": {6001, 6001},
		"/shared/new": {6003, 6003}, "/shared/bobs": {6002, 6100},
	} {
		if got := owner(p); got != want {
			t.Errorf("%s owned by %v, want %v", p, got, want)
		}
	}
	if content, _ := n.read("/shared/bobs"); content != "/shared/bobs" {
		t.Errorf("bob's file replaced: %q", content)
	}

	if _, body := n.do("GET", n.ts.URL+"/proc/whoami", ""); !strings.Contains(body, "Unix Account: alice (uid 6001") {
		t.Errorf("whoami: %q", body)
	}

	// Third-party copies access the local file as the user too
	remote := newNode(t, nil)
	remote.write("/f", "remote data")
	remoteAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(basicUser+":"+basicPass))
	code, body := copyTPC(t, n, "/alice/pulled", "Source", remote.url("/f"), "TransferHeaderAuthorization", remoteAuth)
	expectSuccess(t, code, body)
	if got := owner("/alice/pulled"); got != [2]int{6001, 6001} {
		t.Errorf("pulled file owned by %v", got)
	}
	code, body = copyTPC(t, n, "/alice/stolen", append([]string{"Source", remote.url("/f"), "TransferHeaderAuthorization", remoteAuth}, as("bob")...)...)
	expectFailure(t, code, body, "permission denied")

	code, body = copyTPC(t, n, "/alice/private", "Destination", remote.url("/pushed"), "TransferHeaderAuthorization", remoteAuth)
	expectSuccess(t, code, body)
	if content, _ := remote.read("/pushed"); content != "/alice/private" {
		t.Errorf("pushed %q", content)
	}
	code, body = copyTPC(t, n, "/alice/private", append([]string{"Destination", remote.url("/leaked"), "TransferHeaderAuthorization", remoteAuth}, as("bob")...)...)
	expectFailure(t, code, body, "permission denied")
	if _, ok := remote.read("/leaked"); ok {
		t.Error("bob pushed alice's private file")
	}
}
