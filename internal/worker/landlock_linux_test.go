package worker

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labkode/weed/internal/auth"
	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/fsuser"
	"github.com/labkode/weed/internal/landlock"
	"golang.org/x/sys/unix"
)

// anyFile is what the test workers serve: a GET reads the file at the path of its
// URL, a PUT writes it, wherever it is, as a worker with a bug would; DIAL connects
// to the TCP address of the path, LISTEN listens on a port
var anyFile = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	var err error
	switch r.Method {
	case "DIAL":
		var c net.Conn
		if c, err = net.Dial("tcp", strings.TrimPrefix(r.URL.Path, "/")); err == nil {
			c.Close()
			return
		}
	case "LISTEN":
		var l net.Listener
		if l, err = net.Listen("tcp", "127.0.0.1:0"); err == nil {
			l.Close()
			return
		}
	case "GET":
		var b []byte
		if b, err = os.ReadFile(r.URL.Path); err == nil {
			w.Write(b)
			return
		}
	case "PUT":
		if err = os.WriteFile(r.URL.Path, []byte("written"), 0o644); err == nil {
			return
		}
	default:
		http.NotFound(w, r)
		return
	}
	code := http.StatusInternalServerError
	if errors.Is(err, os.ErrPermission) {
		code = http.StatusForbidden
	}
	http.Error(w, err.Error(), code)
})

// A worker reaches the exported directory, and reads the system's files, but nothing
// else, even what Unix permissions let its account read and write
func TestLandlock(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("starting workers as other accounts needs root")
	}
	if abi := landlock.ABI(); abi < landlock.MinABI {
		t.Skipf("Landlock ABI %d", abi)
	}
	defer func(d time.Duration) { dirCheckInterval = d }(dirCheckInterval)
	dirCheckInterval = 20 * time.Millisecond
	base := t.TempDir()
	export, outside := filepath.Join(base, "export"), filepath.Join(base, "outside")
	for _, dir := range []string{filepath.Dir(base), base, export, outside} {
		os.Mkdir(dir, 0o777)
		os.Chmod(dir, 0o777)
	}
	os.WriteFile(filepath.Join(export, "in"), []byte("in"), 0o644)
	os.WriteFile(filepath.Join(outside, "out"), []byte("out"), 0o644)

	p, err := New(Options{Config: config.Config{Directory: export}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close(context.Background()) })
	do := func(method, path string) (int, string) { return asNobody(p, method, path) }

	for _, c := range []struct {
		method, path string
		want         int
	}{
		{"GET", filepath.Join(export, "in"), 200},
		{"PUT", filepath.Join(export, "new"), 200},
		{"GET", "/etc/passwd", 200},
		{"GET", filepath.Join(outside, "out"), 403},
		{"PUT", filepath.Join(outside, "new"), 403},
		{"PUT", "/tmp/landlock-test", 403},
		{"GET", "/root/.bashrc", 403},
	} {
		if code, body := do(c.method, c.path); code != c.want {
			t.Errorf("%s %s = %d (%s), want %d", c.method, c.path, code, strings.TrimSpace(body), c.want)
		}
	}
	if _, err := os.Stat(filepath.Join(outside, "new")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("written outside: %v", err)
	}
	os.Remove("/tmp/landlock-test")

	// The rules name the exported directory itself: another one in its place gets
	// workers that reach it
	pid := p.Workers()[0].PID
	os.Rename(export, filepath.Join(base, "before"))
	os.Mkdir(export, 0o777)
	os.Chmod(export, 0o777)
	replaced(t, p, pid)
	if code, body := do("PUT", filepath.Join(export, "new")); code != 200 {
		t.Errorf("PUT in the new directory = %d (%s)", code, strings.TrimSpace(body))
	}
	if code, _ := do("GET", filepath.Join(base, "before", "in")); code != 403 {
		t.Errorf("GET in the directory before = %d, want 403", code)
	}
}

// A storage mounted again over the exported directory, whose root has the same device
// and inode numbers as before, but is another inode for Landlock, gets workers that
// reach it. Unmounted in between, the directory beneath gets none. It needs a
// privileged container, and mkfs.ext4.
func TestLandlockRemount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("starting workers as other accounts needs root")
	}
	if abi := landlock.ABI(); abi < landlock.MinABI {
		t.Skipf("Landlock ABI %d", abi)
	}
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("no mkfs.ext4")
	}
	defer func(d time.Duration) { dirCheckInterval = d }(dirCheckInterval)
	dirCheckInterval = 20 * time.Millisecond
	base := t.TempDir()
	os.Chmod(filepath.Dir(base), 0o755)
	os.Chmod(base, 0o755)
	img, export := filepath.Join(base, "fs.img"), filepath.Join(base, "export")
	os.Mkdir(export, 0o755)
	if out, err := exec.Command("mkfs.ext4", "-q", img, "16M").CombinedOutput(); err != nil {
		t.Fatalf("mkfs.ext4: %v: %s", err, out)
	}
	mount := func() {
		if out, err := exec.Command("mount", "-o", "loop", img, export).CombinedOutput(); err != nil {
			t.Skipf("cannot mount (not a privileged container?): %v: %s", err, out)
		}
		os.Chmod(export, 0o777)
	}
	umount := func() {
		if out, err := exec.Command("umount", export).CombinedOutput(); err != nil {
			t.Fatalf("umount: %v: %s", err, out)
		}
	}
	mount()
	before, _ := identify(unix.AT_FDCWD, export)

	lost := make(chan bool, 10)
	p, err := New(Options{Config: config.Config{Directory: export}, Unmounted: func(u bool) { lost <- u }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close(context.Background()) })
	if code, body := asNobody(p, "PUT", filepath.Join(export, "a")); code != 200 {
		t.Fatalf("PUT = %d (%s)", code, strings.TrimSpace(body))
	}
	pid := p.Workers()[0].PID
	umount()
	beneath, _ := identify(unix.AT_FDCWD, export)
	root, _ := identify(unix.AT_FDCWD, "/")
	blocked := beneath.dev == root.dev
	if !blocked {
		t.Logf("the directory beneath is not on the file system of / (%s is a tmpfs?): not blocked", base)
	} else {
		select {
		case u := <-lost:
			if !u {
				t.Fatal("Unmounted(false) first")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("no Unmounted(true) once the storage was unmounted")
		}
		if code, body := asNobody(p, "PUT", filepath.Join(export, "beneath")); code != 503 {
			t.Errorf("PUT while unmounted = %d (%s), want 503", code, strings.TrimSpace(body))
		}
		if _, err := os.Stat(filepath.Join(export, "beneath")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("written in the directory beneath: %v", err)
		}
	}
	mount()
	if blocked {
		select {
		case u := <-lost:
			if u {
				t.Fatal("Unmounted(true) again")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("no Unmounted(false) once the storage was mounted again")
		}
	}
	defer umount()
	if after, _ := identify(unix.AT_FDCWD, export); after.dev != before.dev || after.ino != before.ino {
		t.Logf("mounted again, the root is another file: %+v, %+v", before, after)
	}
	replaced(t, p, pid)
	if code, body := asNobody(p, "PUT", filepath.Join(export, "b")); code != 200 {
		t.Errorf("PUT after mounting again = %d (%s)", code, strings.TrimSpace(body))
	}
	p.Close(context.Background())
}

// asNobody has the worker of nobody serve a request
func asNobody(p *Pool, method, path string) (int, string) {
	nobody := &fsuser.User{Name: "nobody", UID: 65534, GID: 65534, Groups: []int{65534}}
	r := httptest.NewRequest(method, "http://worker"+path, strings.NewReader("x"))
	r = r.WithContext(auth.SetAuthInfoInContext(r.Context(), &auth.AuthInfo{Username: "nobody", Method: "test"}))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r, nobody)
	b, _ := io.ReadAll(w.Result().Body)
	return w.Code, string(b)
}

// replaced waits for the worker pid to be replaced, or gone
func replaced(t *testing.T, p *Pool, pid int) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if w := p.Workers(); len(w) == 0 || w[0].PID != pid {
			return
		}
	}
	t.Errorf("worker %d was not replaced", pid)
}

// Workers bind no TCP port, and connect to none unless they make third-party copies
func TestLandlockTCP(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("starting workers as other accounts needs root")
	}
	if abi := landlock.ABI(); abi < landlock.TCPABI {
		t.Skipf("Landlock ABI %d", abi)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	for _, tpc := range []bool{false, true} {
		p, err := New(Options{Config: config.Config{Directory: t.TempDir(), TPC: tpc}})
		if err != nil {
			t.Fatal(err)
		}
		want := map[bool]int{false: 403, true: 200}[tpc]
		if code, body := asNobody(p, "DIAL", "/"+l.Addr().String()); code != want {
			t.Errorf("tpc %v: connect = %d (%s), want %d", tpc, code, strings.TrimSpace(body), want)
		}
		if code, body := asNobody(p, "LISTEN", "/"); code != 403 {
			t.Errorf("tpc %v: bind = %d (%s), want 403", tpc, code, strings.TrimSpace(body))
		}
		p.Close(context.Background())
	}
}
