package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/logger"
	"github.com/labkode/weed/internal/metrics"
	"github.com/labkode/weed/internal/version"
)

// captureLog sends the log records to the returned buffer until the test ends
func captureLog(t *testing.T) *bytes.Buffer {
	var out bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&out, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &out
}

// fromFile starts a server from a configuration file, as weed does
// bansIn is a section of a configuration file with a bans file of the test's, rather
// than the machine's (/var/lib/weed/bans.json, which may be root's)
func bansIn(t *testing.T) string {
	return "[admin]\nbans = \"" + filepath.Join(t.TempDir(), "bans.json") + "\"\n"
}

func fromFile(t *testing.T, content string) (*Server, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "weed.toml")
	writeFile(t, path, content)
	cfg, src, err := config.Read(path)
	if err == nil {
		err = cfg.Validate()
	}
	if err != nil {
		t.Fatal(err)
	}
	s := newServer(cfg)
	s.SetSource(src)
	if err := s.Initialize(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, path
}

// writeFile replaces a file, with a modification time that differs from the last one
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	next := time.Now().Add(time.Duration(len(content)) * time.Second)
	if fi, err := os.Stat(path); err == nil && !fi.ModTime().Before(next) {
		next = fi.ModTime().Add(time.Second)
	}
	os.Chtimes(path, next, next)
}

func pendingNow(s *Server) map[string]pendingRestart {
	s.checkRestart()
	s.run.mu.Lock()
	defer s.run.mu.Unlock()
	m := make(map[string]pendingRestart)
	for k, v := range s.run.pending {
		m[k] = v
	}
	return m
}

// A restart is pending when the configuration file says something else than what
// runs, or would not start weed at all
func TestRestartPendingConfig(t *testing.T) {
	dir := t.TempDir()
	content := "[server]\naddress = \"127.0.0.1\"\nport = 9000\ndir = \"" + dir + "\"\n" + bansIn(t)
	s, path := fromFile(t, content)
	s.run.executable = ""
	log := captureLog(t)

	if p := pendingNow(s); len(p) != 0 {
		t.Fatalf("pending at startup: %v", p)
	}
	writeFile(t, path, content+"# a comment\n")
	if p := pendingNow(s); len(p) != 0 {
		t.Errorf("pending after a comment: %v", p)
	}

	writeFile(t, path, strings.Replace(content, "port = 9000", "port = 9001", 1)+"[tpc]\nenabled = true\n")
	p := pendingNow(s)[restartConfig]
	if p.level != slog.LevelWarn || p.why != "the configuration file has changed: server.port, tpc.enabled" {
		t.Errorf("changed port: %+v", p)
	}
	if line := s.StatusLine(); !strings.Contains(line, "restart pending: the configuration file has changed: server.port") {
		t.Errorf("status line %q", line)
	}
	if m := scrapeServer(t, s); !strings.Contains(m, `weed_restart_pending{reason="config"} 1`) || !strings.Contains(m, `weed_restart_pending{reason="binary"} 0`) {
		t.Errorf("metrics:\n%s", grepLines(m, "weed_restart_pending"))
	}
	pendingNow(s)
	if n := strings.Count(log.String(), "server.port"); n != 1 {
		t.Errorf("logged %d times:\n%s", n, log)
	}

	for name, bad := range map[string]string{"syntax": content + "[server\n", "unknown key": content + "prot = 1\n"} {
		writeFile(t, path, bad)
		if p := pendingNow(s)[restartConfig]; p.level != slog.LevelError || !strings.Contains(p.why, "weed would not start with it") {
			t.Errorf("%s: %+v", name, p)
		}
	}
	os.Remove(path)
	if p := pendingNow(s)[restartConfig]; p.level != slog.LevelError || !strings.Contains(p.why, "no such file") {
		t.Errorf("removed: %+v", p)
	}

	writeFile(t, path, content)
	if p := pendingNow(s); len(p) != 0 {
		t.Errorf("pending after restoring the file: %v", p)
	}
	if !strings.Contains(log.String(), "restart no longer pending") || !strings.Contains(log.String(), "level=ERROR") {
		t.Errorf("log:\n%s", log)
	}
}

// A restart is pending when weed's executable has been replaced by another build
func TestRestartPendingBinary(t *testing.T) {
	s := New(&config.Config{Directory: t.TempDir()})
	running := version.Current()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	s.run.executable = filepath.Join(t.TempDir(), "weed")
	install := func(content []byte) {
		t.Helper()
		// As upgrades do: a new file renamed over the old one
		if err := os.WriteFile(s.run.executable+".new", content, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(s.run.executable+".new", s.run.executable); err != nil {
			t.Fatal(err)
		}
	}
	install(binary)
	if p := pendingNow(s); len(p) != 0 {
		t.Fatalf("pending with the running binary: %v", p)
	}

	// Another build: the same binary with another build ID
	id := []byte(strings.TrimPrefix(running.Build, "go:"))
	other := bytes.Clone(id)
	other[0] ^= 1
	install(bytes.ReplaceAll(binary, id, other))
	p := pendingNow(s)[restartBinary]
	if p.level != slog.LevelWarn || !strings.Contains(p.why, "is now "+running.Version) || !strings.HasSuffix(p.why, "build go:"+string(other)) {
		t.Errorf("another build: %+v", p)
	}
	install([]byte("#!/bin/sh\n"))
	if p := pendingNow(s)[restartBinary]; p.level != slog.LevelError || !strings.Contains(p.why, "would not restart") {
		t.Errorf("not weed: %+v", p)
	}
	install(binary)
	if p := pendingNow(s); len(p) != 0 {
		t.Errorf("pending after reinstalling the running binary: %v", p)
	}
}

func scrapeServer(t *testing.T, s *Server) string {
	t.Helper()
	w := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	return w.Body.String()
}

func grepLines(s, substr string) string {
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, substr) {
			lines = append(lines, l)
		}
	}
	return strings.Join(lines, "\n")
}

// /status and the metrics say what runs: which build, since when, with which
// configuration, and how the last reload went
func TestStatus(t *testing.T) {
	dir := t.TempDir()
	htpasswd := filepath.Join(t.TempDir(), "htpasswd")
	os.WriteFile(htpasswd, []byte("alice:$2y$04$ShRnxLOs.q4Wv3J1cKnMA.ZB2xEj9Sut9ENu5pZsSb4Wdm9lYv1y6\n"), 0600)
	s, path := fromFile(t, "[server]\nport = 9000\ndir = \""+dir+"\"\n[basic]\nenabled = true\nhtpasswd = \""+htpasswd+
		"\"\n[macaroons]\nenabled = true\nsecret_key = \"0123456789abcdef0123456789abcdef\"\n"+bansIn(t))
	_, src, _ := config.Read(path)

	get := func() (st status) {
		t.Helper()
		w := httptest.NewRecorder()
		s.MetricsHandler().ServeHTTP(w, httptest.NewRequest("GET", "/status", nil))
		if w.Code != 200 || w.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("/status: %d %s", w.Code, w.Header())
		}
		if strings.Contains(w.Body.String(), "0123456789abcdef") {
			t.Errorf("/status shows a secret:\n%s", w.Body)
		}
		if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
			t.Fatal(err)
		}
		return st
	}
	st := get()
	if st.Version != version.Current() || st.PID != os.Getpid() || !st.Started.Equal(startTime) || st.Uptime == "" {
		t.Errorf("process: %+v", st)
	}
	if st.Config.File != path || st.Config.SHA256 != src.SHA256 || st.Config.Settings["server"]["port"] != 9000.0 ||
		st.Config.Settings["macaroons"]["secret_key"] != "<redacted>" || st.Config.Settings["server"]["reload_interval"] != "1h" {
		t.Errorf("config: %+v", st.Config)
	}
	if !st.Reload.Last.IsZero() || !st.Reload.LastSuccess.Equal(startTime) || !st.Reload.Successful || len(st.RestartPending) != 0 || st.Workers == nil {
		t.Errorf("at startup: %+v", st)
	}

	m := scrapeServer(t, s)
	for _, want := range []string{
		`weed_config_info{file="` + path + `",sha256="` + src.SHA256 + `"} 1`,
		`weed_build_info{version="` + st.Version.Version + `",revision="` + st.Version.Revision + `",modified="`,
		`build="` + st.Version.Build + `"} 1`,
		"\nprocess_start_time_seconds ",
		"\nweed_reload_last_successful 1\n",
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %s:\n%s", want, grepLines(m, "weed_"))
		}
	}

	// A reload that cannot read a file is recorded, and so is the next complete one
	captureLog(t)
	os.Remove(htpasswd)
	s.Reload()
	st = get()
	if st.Reload.Last.IsZero() || st.Reload.Successful || !st.Reload.LastSuccess.Equal(startTime) {
		t.Errorf("after a partial reload: %+v", st.Reload)
	}
	if m := scrapeServer(t, s); !strings.Contains(m, "\nweed_reload_last_successful 0\n") {
		t.Errorf("metrics:\n%s", grepLines(m, "reload_last"))
	}
	os.WriteFile(htpasswd, []byte("bob:$2y$04$ShRnxLOs.q4Wv3J1cKnMA.ZB2xEj9Sut9ENu5pZsSb4Wdm9lYv1y6\n"), 0600)
	s.Reload()
	if st = get(); !st.Reload.Successful || !st.Reload.LastSuccess.Equal(st.Reload.Last) || !st.Reload.LastSuccess.After(startTime) {
		t.Errorf("after a complete reload: %+v", st.Reload)
	}
}

// Under systemd (Type=notify), weed says it is ready once it listens, and that it stops
func TestRunNotifiesSystemd(t *testing.T) {
	sockDir, err := os.MkdirTemp("", "sd") // short: socket paths are limited
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	addr := &net.UnixAddr{Name: filepath.Join(sockDir, "notify"), Net: "unixgram"}
	sock, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	t.Setenv("NOTIFY_SOCKET", addr.Name)
	read := func() string {
		t.Helper()
		sock.SetReadDeadline(time.Now().Add(10 * time.Second))
		b := make([]byte, 4096)
		n, err := sock.Read(b)
		if err != nil {
			t.Fatal(err)
		}
		return string(b[:n])
	}
	captureLog(t)

	// A port in use: weed fails, and never says it is ready
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	port := busy.Addr().(*net.TCPAddr).Port
	s := newServer(&config.Config{Directory: t.TempDir(), Address: "127.0.0.1", Port: port, Anonymous: true})
	if err := s.Initialize(); err != nil {
		t.Fatal(err)
	}
	if err := s.Run(t.Context()); err == nil || !strings.Contains(err.Error(), "address already in use") {
		t.Fatalf("port in use: %v", err)
	}
	sock.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if n, err := sock.Read(make([]byte, 100)); err == nil {
		t.Fatalf("notified %d bytes", n)
	}

	s = newServer(&config.Config{Directory: t.TempDir(), Address: "127.0.0.1", Anonymous: true})
	if err := s.Initialize(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	if got := read(); !strings.HasPrefix(got, "READY=1\nSTATUS=Serving since ") || !strings.Contains(got, ": weed "+version.Current().Version) {
		t.Errorf("ready: %q", got)
	}
	cancel()
	if got := read(); got != "STOPPING=1" {
		t.Errorf("stopping: %q", got)
	}
	if err := <-done; err != nil {
		t.Error(err)
	}
}

// Without a configuration file, the main port also serves /metrics and /status:
// its clients are local, and can already do anything. Otherwise only
// server.metrics_address serves them.
func TestQuickStartMonitoring(t *testing.T) {
	get := func(cfg *config.Config, path string) *httptest.ResponseRecorder {
		t.Helper()
		cfg.Directory = t.TempDir()
		cfg.BansFile = filepath.Join(t.TempDir(), "bans.json") // not the machine's
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		s := newServer(cfg)
		s.MonitorOnMainPort = cfg.Anonymous // main sets it for QuickStart, which is anonymous
		if err := s.Initialize(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		w := httptest.NewRecorder()
		s.SetupRoutes().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}
	captureLog(t)
	if w := get(config.QuickStart(), "/status"); w.Code != 200 || !strings.Contains(w.Body.String(), `"build": "`+version.Current().Build+`"`) {
		t.Errorf("quickstart /status: %d %s", w.Code, w.Body)
	}
	if w := get(config.QuickStart(), "/metrics"); w.Code != 200 || !strings.Contains(w.Body.String(), "\nweed_build_info{") {
		t.Errorf("quickstart /metrics: %d %s", w.Code, w.Body)
	}
	for _, path := range []string{"/status", "/metrics"} {
		if w := get(config.Default(), path); w.Code != 404 {
			t.Errorf("configured server's main port serves %s: %d", path, w.Code)
		}
	}
}

// Every request on the main port is logged once and counted once, whatever it is for:
// WebDAV, the index page, /healthz, unknown paths, and /status and /metrics there
func TestEveryRequestLogged(t *testing.T) {
	n := newNode(t, nil)
	n.srv.MonitorOnMainPort = true // as without a configuration file
	n.ts.Config.Handler = n.srv.SetupRoutes()
	log := captureLog(t)
	for _, c := range []struct {
		method, path, user string
		code               int
	}{
		{"PUT", "/webdav/f", basicUser, 201},
		{"GET", "/webdav/f", basicUser, 200},
		{"GET", "/", logger.Nobody, 200},
		{"GET", "/healthz", logger.Nobody, 200},
		{"GET", "/status", logger.Nobody, 200},
		{"GET", "/metrics", logger.Nobody, 200},
		{"GET", "/nothing-here", logger.Nobody, 404},
		{"GET", "/proc/whoami", basicUser, 200},
	} {
		before := metrics.HTTPRequests.Get(metrics.Method(c.method), strconv.Itoa(c.code))
		log.Reset()
		auth := []string{"Authorization", "none"}
		if c.user != logger.Nobody {
			auth = nil
		}
		if code := n.status(c.method, n.ts.URL+c.path, "data", auth...); code != c.code {
			t.Errorf("%s %s: %d", c.method, c.path, code)
		}
		records := grepLines(log.String(), "msg=request ")
		if strings.Count(records, "msg=request ") != 1 || !strings.Contains(records, " path="+c.path+" ") ||
			!strings.Contains(records, " user="+c.user+" ") || !strings.Contains(records, " status="+strconv.Itoa(c.code)+" ") {
			t.Errorf("%s %s logged as:\n%s", c.method, c.path, records)
		}
		if got := metrics.HTTPRequests.Get(metrics.Method(c.method), strconv.Itoa(c.code)) - before; got != 1 {
			t.Errorf("%s %s counted %d times", c.method, c.path, got)
		}
	}
}
