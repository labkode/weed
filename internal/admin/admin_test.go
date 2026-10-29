package admin

import (
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// socketPath returns a path for a Unix socket: short enough (104 bytes on macOS)
func socketPath(t *testing.T) string {
	dir, err := os.MkdirTemp("", "weed")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "run", "admin.sock")
}

// serve serves on a socket at path what the peer of each request is
func serve(t *testing.T, path string) {
	t.Helper()
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ConnContext: ConnContext, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"error": "` + PeerOf(r.Context()).String() + `"}`))
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
}

func TestListen(t *testing.T) {
	path := socketPath(t)
	serve(t, path)
	for p, perm := range map[string]os.FileMode{path: 0o600, filepath.Dir(path): 0o700} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != perm {
			t.Errorf("%s: %v, %v", p, fi, err)
		}
	}
	var out Error
	if err := NewClient(path).Do("GET", "/", nil, &out); err != nil || !strings.HasPrefix(out.Error, "uid ") {
		t.Errorf("peer: %+v, %v", out, err)
	}

	// Taken: refused
	if _, err := Listen(path); err == nil || !strings.Contains(err.Error(), "is in use") {
		t.Errorf("a socket in use: %v", err)
	}
	// Not a socket: refused
	file := filepath.Join(filepath.Dir(path), "file")
	os.WriteFile(file, nil, 0o600)
	if _, err := Listen(file); err == nil || !strings.Contains(err.Error(), "is not a socket") {
		t.Errorf("a file: %v", err)
	}
}

// The socket left by a weed that died is replaced
func TestStaleSocket(t *testing.T) {
	path := socketPath(t)
	os.MkdirAll(filepath.Dir(path), 0o700)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	ln.Close()
	serve(t, path)
	var out Error
	if err := NewClient(path).Do("GET", "/", nil, &out); err != nil || !strings.HasPrefix(out.Error, "uid ") {
		t.Errorf("after replacing a stale socket: %+v, %v", out, err)
	}
}

func TestPeerLogged(t *testing.T) {
	var b strings.Builder
	slog.New(slog.NewJSONHandler(&b, nil)).Info("x", "peer", Peer{UID: 0, PID: 42})
	if !strings.Contains(b.String(), `"peer":"uid 0, pid 42"`) {
		t.Errorf("logged as %s", b.String())
	}
}
