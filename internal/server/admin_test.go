package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/labkode/weed/internal/admin"
	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/logger"
)

// socketPath returns a path for a Unix socket: short enough (108 bytes), which one in
// t.TempDir() may not be
func socketPath(t testing.TB) string {
	dir, err := os.MkdirTemp("", "weed")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "run", "admin.sock")
}

// newAdminNode is newNode with its control plane, and a client of it
func newAdminNode(t *testing.T, bansFile string, mod func(cfg *config.Config)) (*node, *admin.Client) {
	t.Helper()
	socket := socketPath(t)
	n := newNode(t, func(cfg *config.Config, _ string) {
		cfg.AdminSocket, cfg.BansFile = socket, bansFile
		if mod != nil {
			mod(cfg)
		}
	})
	stop, err := n.srv.startAdmin()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	return n, admin.NewClient(socket)
}

func TestBan(t *testing.T) {
	bansFile := filepath.Join(t.TempDir(), "state", "bans.json")
	n, c := newAdminNode(t, bansFile, nil)
	fi, err := os.Stat(n.srv.Config.AdminSocket)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket: %v, %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Dir(n.srv.Config.AdminSocket)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("socket directory: %v, %v", fi, err)
	}
	if code := n.status("PUT", "/f", "data"); code != 201 {
		t.Fatalf("PUT before the ban: %d", code)
	}

	log := captureLog(t)
	var res admin.BanResult
	if err := c.Do("PUT", "/v1/bans/"+basicUser, admin.BanRequest{Reason: "compromised"}, &res); err != nil {
		t.Fatal(err)
	}
	if !res.Added || res.User != basicUser || res.Reason != "compromised" || !strings.HasPrefix(res.By, "uid ") || res.Since.IsZero() || res.Warning != "" {
		t.Errorf("ban: %+v", res)
	}
	if !strings.Contains(log.String(), `msg="user banned" user=alice reason=compromised by="uid `) {
		t.Errorf("ban logged as:\n%s", log)
	}

	// Refused whatever the request, and logged as the user
	for _, method := range []string{"GET", "PUT", "PROPFIND"} {
		log.Reset()
		if code := n.status(method, "/f", "data"); code != 403 {
			t.Errorf("%s by a banned user: %d", method, code)
		}
		if r := grepLines(log.String(), "msg=request "); !strings.Contains(r, " user=alice ") || !strings.Contains(r, " status=403 ") {
			t.Errorf("%s by a banned user logged as:\n%s", method, log)
		}
	}
	if code := n.status("GET", n.ts.URL+"/auth/basic", ""); code != 403 {
		t.Errorf("/auth/basic of a banned user: %d", code)
	}

	// Banning again keeps the first ban
	if err := c.Do("PUT", "/v1/bans/"+basicUser, nil, &res); err != nil || res.Added || res.Reason != "compromised" {
		t.Errorf("banned again: %+v, %v", res, err)
	}
	var list admin.Bans
	if err := c.Do("GET", "/v1/bans", nil, &list); err != nil || len(list.Bans) != 1 || list.Bans[0].User != basicUser {
		t.Errorf("bans: %+v, %v", list, err)
	}
	if body := serve(n.srv.MetricsHandler(), "/status"); !strings.Contains(body, `"banned_users": 1`) {
		t.Errorf("/status: %s", body)
	}
	if body := serve(n.srv.MetricsHandler(), "/metrics"); !strings.Contains(body, "\nweed_banned_users 1\n") {
		t.Errorf("/metrics: %q", grepLines(body, "banned"))
	}

	// Saved for the next start
	again, _ := newAdminNode(t, bansFile, nil)
	if code := again.status("GET", "/f", ""); code != 403 {
		t.Errorf("banned user after a restart: %d", code)
	}

	var un admin.UnbanResult
	if err := c.Do("DELETE", "/v1/bans/"+basicUser, nil, &un); err != nil || !un.Removed {
		t.Errorf("unban: %+v, %v", un, err)
	}
	if code := n.status("GET", "/f", ""); code != 200 {
		t.Errorf("GET after the ban is lifted: %d", code)
	}
	if err := c.Do("DELETE", "/v1/bans/"+basicUser, nil, &un); err != nil || un.Removed {
		t.Errorf("unban twice: %+v, %v", un, err)
	}
	if b, _ := os.ReadFile(bansFile); strings.Contains(string(b), basicUser) {
		t.Errorf("the lifted ban is still saved: %s", b)
	}
}

// Anonymous requests are nobody's, whom a ban refuses like anyone else
func TestBanAnonymous(t *testing.T) {
	n, c := newAdminNode(t, "", func(cfg *config.Config) {
		cfg.Address, cfg.Anonymous = "127.0.0.1", true
	})
	none := []string{"Authorization", "none"}
	if code := n.status("PUT", "/f", "data", none...); code != 201 {
		t.Fatalf("anonymous PUT: %d", code)
	}
	if err := c.Do("PUT", "/v1/bans/"+logger.Nobody, nil, nil); err != nil {
		t.Fatal(err)
	}
	if code := n.status("GET", "/f", "", none...); code != 403 {
		t.Errorf("anonymous GET once nobody is banned: %d", code)
	}
	if code := n.status("GET", "/f", ""); code != 200 {
		t.Errorf("alice's GET: %d", code)
	}
}

func TestAdminErrors(t *testing.T) {
	_, c := newAdminNode(t, "", nil)
	for _, e := range []struct {
		method, path string
		body         any
		want         string
	}{
		{"PUT", "/v1/bans/a%20b", nil, `"a b" is not a user name`},
		{"PUT", "/v1/bans/a%0Ab", nil, `"a\nb" is not a user name`},
		{"PUT", "/v1/bans/alice", map[string]any{"reason": "x", "until": "tomorrow"}, `invalid request: json: unknown field "until"`},
		{"POST", "/v1/bans", nil, "no operation POST /v1/bans (is this weed older than weed utils?)"},
		{"GET", "/v2/everything", nil, "no operation GET /v2/everything"},
	} {
		if err := c.Do(e.method, e.path, e.body, nil); err == nil || !strings.Contains(err.Error(), "weed: "+e.want) {
			t.Errorf("%s %s: %v", e.method, e.path, err)
		}
	}
	if err := admin.NewClient(socketPath(t)).Do("GET", "/v1/bans", nil, nil); err == nil || !strings.Contains(err.Error(), "cannot reach weed's control plane at") {
		t.Errorf("no weed: %v", err)
	}
}

// A ban that cannot be saved applies until weed stops, and says so
func TestBanUnsaved(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes anyway")
	}
	dir := t.TempDir()
	n, c := newAdminNode(t, filepath.Join(dir, "bans.json"), nil)
	os.Chmod(dir, 0o500)
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	var res admin.BanResult
	if err := c.Do("PUT", "/v1/bans/"+basicUser, nil, &res); err != nil || !res.Added || !strings.Contains(res.Warning, "the ban lasts only until weed stops: cannot save the bans") {
		t.Errorf("unsaved ban: %+v, %v", res, err)
	}
	if code := n.status("GET", "/f", ""); code != 403 {
		t.Errorf("GET by a user whose ban was not saved: %d", code)
	}
}

// A socket that weed listens on is not taken over; one left by a weed that died is
func TestAdminSocketInUse(t *testing.T) {
	n, _ := newAdminNode(t, "", nil)
	s := newServer(&config.Config{Directory: t.TempDir(), AdminSocket: n.srv.Config.AdminSocket})
	if _, err := s.startAdmin(); err == nil || !strings.Contains(err.Error(), "is in use, by another weed?") {
		t.Errorf("second weed: %v", err)
	}
}

// The bans file is checked at startup, and so by weed check
func TestInvalidBansFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bans.json")
	writeFile(t, path, "{")
	s := newServer(&config.Config{Directory: t.TempDir(), BansFile: path})
	if err := s.Check(); err == nil || !strings.Contains(err.Error(), "cannot read the banned users (admin.bans)") {
		t.Errorf("invalid bans file: %v", err)
	}
}

// serve returns what h answers to GET path
func serve(h http.Handler, path string) string {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec.Body.String()
}
