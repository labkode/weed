package worker

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/labkode/weed/internal/auth"
	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/fsuser"
	"github.com/labkode/weed/internal/landlock"
	"github.com/labkode/weed/internal/seccomp"
	"golang.org/x/sys/unix"
)

// testAccounts are the accounts of the starter of TestStarter: alice, and toor, root
// under another name
func testAccounts(name string) (*fsuser.User, error) {
	switch name {
	case "alice":
		return &fsuser.User{Name: "alice", UID: 6001, GID: 6001, Groups: []int{6001}}, nil
	case "toor":
		return &fsuser.User{Name: "toor", UID: 0, GID: 0, Groups: []int{0}}, nil
	}
	return nil, errors.New("no such account")
}

// as has the worker of u serve a request
func as(p *Pool, u *fsuser.User, method, path string) int {
	r := httptest.NewRequest(method, "http://worker"+path, strings.NewReader("x"))
	r = r.WithContext(auth.SetAuthInfoInContext(r.Context(), &auth.AuthInfo{Username: u.Name, Method: "test"}))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r, u)
	return w.Code
}

func status(pid int) map[string]string {
	b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	fields := make(map[string]string)
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			fields[k] = strings.TrimSpace(v)
		}
	}
	return fields
}

// launch starts this binary as the starter of dir (see TestMain)
func launch(t *testing.T, dir string) *Starter {
	t.Helper()
	env, err := LaunchStarter([]string{dir}, seccomp.UnixOnly)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(starterEnv, strings.TrimPrefix(env, starterEnv+"="))
	st, err := StarterFromEnv()
	if err != nil || st == nil {
		t.Fatalf("StarterFromEnv: %v, %v", st, err)
	}
	return st
}

// The starter starts the workers, as the accounts that it looks up itself: it has
// the privileges to, and no others; it refuses root, and accounts that are not what
// the front process has. It kills workers, and once it has gone, the front process
// learns of it.
func TestStarter(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("starting workers as other accounts needs root")
	}
	if abi := landlock.ABI(); abi < landlock.MinABI {
		t.Skipf("Landlock ABI %d", abi)
	}
	dir := t.TempDir()
	os.Chmod(filepath.Dir(dir), 0o755)
	os.Chmod(dir, 0o777)
	st := launch(t, dir)
	lost := make(chan error, 1)
	p, err := New(Options{Config: config.Config{Directory: dir}, Starter: st, Lost: func(err error) { lost <- err }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close(context.Background()) })

	s := status(st.pid)
	if s["CapPrm"] != "00000000000000e0" || s["CapEff"] != "00000000000000e0" || s["CapBnd"] != "00000000000000e0" ||
		s["NoNewPrivs"] != "1" || s["Seccomp"] != "2" {
		t.Errorf("the starter: CapPrm %s, CapEff %s, CapBnd %s, NoNewPrivs %s, Seccomp %s",
			s["CapPrm"], s["CapEff"], s["CapBnd"], s["NoNewPrivs"], s["Seccomp"])
	}

	alice, _ := testAccounts("alice")
	if code := as(p, alice, "PUT", filepath.Join(dir, "f")); code != 200 {
		t.Fatalf("PUT as alice = %d", code)
	}
	if fi, err := os.Stat(filepath.Join(dir, "f")); err != nil || fi.Sys().(*syscall.Stat_t).Uid != 6001 {
		t.Errorf("not written by alice's worker: %v", err)
	}
	w := p.Workers()
	if len(w) != 1 || status(w[0].PID)["PPid"] != strconv.Itoa(st.pid) || status(w[0].PID)["CapPrm"] != "0000000000000000" {
		t.Errorf("alice's worker is not the starter's child, without capabilities: %+v", w)
	}
	if n, err := p.Kill("alice"); n != 1 || err != nil {
		t.Errorf("Kill = %d, %v", n, err)
	}
	if err := unix.Kill(w[0].PID, 0); !errors.Is(err, unix.ESRCH) {
		t.Errorf("alice's worker after Kill: %v", err)
	}

	// The starter looks accounts up itself
	forged := &fsuser.User{Name: "alice", UID: 6001, GID: 6001, Groups: []int{6001, 0}}
	if code := as(p, forged, "PUT", filepath.Join(dir, "g")); code != 503 {
		t.Errorf("PUT as alice with group 0 = %d, want 503", code)
	}
	toor := &fsuser.User{Name: "toor", UID: 0, GID: 0, Groups: []int{0}}
	if code := as(p, toor, "PUT", filepath.Join(dir, "g")); code != 503 {
		t.Errorf("PUT as toor = %d, want 503", code)
	}
	if code := as(p, alice, "PUT", filepath.Join(dir, "g")); code != 200 {
		t.Errorf("PUT as alice again = %d", code)
	}
	if err := p.Check(); err != nil {
		t.Errorf("Check: %v", err)
	}

	unix.Kill(st.pid, unix.SIGKILL)
	select {
	case err := <-lost:
		if !strings.Contains(err.Error(), "the starter of workers has exited") || !strings.Contains(err.Error(), "killed by signal killed") {
			t.Errorf("lost: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the front process did not learn that the starter has gone")
	}
	// Workers that run serve until the front process has stopped; none starts
	if err := p.Check(); err == nil || !strings.Contains(err.Error(), "the starter of workers has exited") {
		t.Errorf("Check once the starter has gone: %v", err)
	}
}

// Closed, the pool stops its starter, once the workers have exited
func TestStarterStops(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("starting workers as other accounts needs root")
	}
	if abi := landlock.ABI(); abi < landlock.MinABI {
		t.Skipf("Landlock ABI %d", abi)
	}
	dir := t.TempDir()
	os.Chmod(filepath.Dir(dir), 0o755)
	os.Chmod(dir, 0o777)
	st := launch(t, dir)
	lost := make(chan error, 1)
	p, err := New(Options{Config: config.Config{Directory: dir}, Starter: st, Lost: func(err error) { lost <- err }})
	if err != nil {
		t.Fatal(err)
	}
	alice, _ := testAccounts("alice")
	if code := as(p, alice, "PUT", filepath.Join(dir, "f")); code != 200 {
		t.Fatalf("PUT as alice = %d", code)
	}
	worker := p.Workers()[0].PID
	p.Close(context.Background())
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if unix.Kill(st.pid, 0) != nil && unix.Kill(worker, 0) != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the starter, or its worker, runs on")
		}
	}
	select {
	case err := <-lost:
		t.Errorf("lost, once closed: %v", err)
	default:
	}
}
