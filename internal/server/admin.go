package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/labkode/weed/internal/admin"
	"github.com/labkode/weed/internal/bans"
	"github.com/labkode/weed/internal/logger"
)

// The control plane (see internal/admin): operations of weed utils on the running weed

// startAdmin serves the control plane on admin.socket, if set, until stop is called
func (s *Server) startAdmin() (stop func(), err error) {
	if s.Config.AdminSocket == "" {
		return func() {}, nil
	}
	ln, err := admin.Listen(s.Config.AdminSocket)
	if err != nil {
		return nil, fmt.Errorf("control plane: %w", err)
	}
	srv := &http.Server{
		Handler:           s.adminHandler(),
		ConnContext:       admin.ConnContext,
		ErrorLog:          logger.ErrorLog(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	slog.Info("serving the control plane", "socket", s.Config.AdminSocket)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("control plane failed", "error", err)
		}
	}()
	return func() { srv.Close() }, nil // which removes the socket
}

func (s *Server) adminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/bans", s.adminBans)
	mux.HandleFunc("PUT /v1/bans/{user}", s.adminBan)
	mux.HandleFunc("DELETE /v1/bans/{user}", s.adminUnban)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		adminError(w, http.StatusNotFound, fmt.Sprintf("no operation %s %s (is this weed older than weed utils?)", r.Method, r.URL.Path))
	})
	return mux
}

func adminReply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func adminError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(admin.Error{Error: msg})
}

// bannableUser checks the name of a user to ban: what credentials can map to
func bannableUser(name string) error {
	if name == "" || len(name) > 256 || strings.ContainsFunc(name, func(r rune) bool { return unicode.IsSpace(r) || !unicode.IsPrint(r) }) {
		return fmt.Errorf("%q is not a user name", name)
	}
	return nil
}

func (s *Server) adminBans(w http.ResponseWriter, r *http.Request) {
	adminReply(w, admin.Bans{Bans: s.Bans.All()})
}

// adminBan bans a user, and stops its worker processes at once
func (s *Server) adminBan(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	if err := bannableUser(user); err != nil {
		adminError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req admin.BanRequest
	if r.ContentLength != 0 {
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
		dec.DisallowUnknownFields() // an option that this weed does not know is not ignored
		if err := dec.Decode(&req); err != nil {
			adminError(w, http.StatusBadRequest, "invalid request: "+err.Error())
			return
		}
	}
	peer := admin.PeerOf(r.Context())
	ban := bans.Ban{User: user, Since: time.Now().UTC().Truncate(time.Second), Reason: req.Reason, By: peer.String()}
	added, err := s.Bans.Add(ban)
	res := admin.BanResult{Ban: ban, Added: added}
	if !added {
		res.Ban, _ = s.Bans.Get(user)
	}
	if err != nil {
		res.Warning = fmt.Sprintf("the ban lasts only until weed stops: %v", err)
		slog.Error("cannot save the bans", "error", err)
	}
	// Also when banned already: a request may have started a worker since (see
	// worker.Options.Refused)
	if s.Workers != nil {
		res.WorkersKilled = s.Workers.Kill(user)
	}
	if added {
		slog.Warn("user banned", "user", user, "reason", req.Reason, "by", peer, "workers_killed", res.WorkersKilled)
	}
	adminReply(w, res)
}

func (s *Server) adminUnban(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	removed, err := s.Bans.Remove(user)
	res := admin.UnbanResult{User: user, Removed: removed}
	if err != nil {
		res.Warning = fmt.Sprintf("the user is banned again when weed restarts: %v", err)
		slog.Error("cannot save the bans", "error", err)
	}
	if removed {
		slog.Warn("ban lifted", "user", user, "by", admin.PeerOf(r.Context()))
	}
	adminReply(w, res)
}
