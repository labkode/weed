package server

import (
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/labkode/weed/internal/config"
)

// On macOS, which has no worker processes and is only for development, weed serves
// files in its own process, as the account that runs it, for every identity. Never as
// root, which would give every identity every file.
func TestDevelopmentMode(t *testing.T) {
	defer func(w, d bool) { workersSupported, developing = w, d }(workersSupported, developing)
	workersSupported, developing = false, true

	if os.Geteuid() == 0 {
		cfg := config.QuickStart()
		cfg.Directory = t.TempDir()
		if err := New(cfg).Initialize(); err == nil || !strings.Contains(err.Error(), "not as root") {
			t.Errorf("as root: %v", err)
		}
		return
	}
	n := newWorkerNode(t, nil)
	if !n.srv.inProcess || n.srv.Workers != nil || n.srv.AuthStore.UnixUsers {
		t.Fatalf("in process %v, workers %v, Unix accounts %v", n.srv.inProcess, n.srv.Workers, n.srv.AuthStore.UnixUsers)
	}
	// basicUser is no account of this system
	if code := n.status("PUT", "/f", "data"); code != 201 {
		t.Fatalf("PUT: %d", code)
	}
	if resp, body := n.do("GET", "/f", ""); resp.StatusCode != 200 || body != "data" {
		t.Errorf("GET: %d %q", resp.StatusCode, body)
	}

	var st status
	json.Unmarshal([]byte(serve(n.srv.MetricsHandler(), "/status")), &st)
	me, _ := user.Current()
	if me == nil || st.Development != me.Username {
		t.Errorf("/status development = %q, want %v", st.Development, me)
	}
}

// Elsewhere than on Linux and macOS, weed does not serve
func TestServingNeedsLinux(t *testing.T) {
	defer func(w, d bool) { workersSupported, developing = w, d }(workersSupported, developing)
	workersSupported, developing = false, false
	cfg := config.QuickStart()
	cfg.Directory = t.TempDir()
	if err := New(cfg).Initialize(); err == nil || !strings.Contains(err.Error(), "weed serves on Linux, and on macOS for development") {
		t.Errorf("%v", err)
	}
}

// On macOS, the files that weed keeps by default in /run/weed and /var/lib/weed,
// which weed may not write there, are in the user's cache directory
func TestDevelopmentPaths(t *testing.T) {
	c := config.QuickStart()
	if runtime.GOOS != "darwin" {
		if c.AdminSocket != "/run/weed/admin.sock" || c.BansFile != "/var/lib/weed/bans.json" {
			t.Errorf("on %s: %s, %s", runtime.GOOS, c.AdminSocket, c.BansFile)
		}
		return
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	if want := filepath.Join(dir, "weed", "admin.sock"); c.AdminSocket != want {
		t.Errorf("admin.socket = %s, want %s", c.AdminSocket, want)
	}
	if want := filepath.Join(dir, "weed", "bans.json"); c.BansFile != want {
		t.Errorf("admin.bans = %s, want %s", c.BansFile, want)
	}
	// Also from a file that sets them to the defaults, as weed config prints
	path := filepath.Join(t.TempDir(), "weed.toml")
	os.WriteFile(path, []byte("[admin]\nsocket = \"/run/weed/admin.sock\"\nbans = \"/var/lib/weed/bans.json\"\n"), 0o600)
	f, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.AdminSocket != c.AdminSocket || f.BansFile != c.BansFile {
		t.Errorf("from a file: %s, %s", f.AdminSocket, f.BansFile)
	}
}
