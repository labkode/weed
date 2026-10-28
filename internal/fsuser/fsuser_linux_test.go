//go:build linux

package fsuser

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
)

// needRoot skips tests that switch identities unless they run as root
// (go test -exec sudo ./internal/fsuser)
func needRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
}

func owner(t *testing.T, p string) (uid, gid int) {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	return int(st.Uid), int(st.Gid)
}

// sharedDir is a directory every user may create files in
func sharedDir(t *testing.T) string {
	dir := t.TempDir()
	os.Chmod(dir, 0777)
	// t.TempDir's parents are 0700 root directories
	for p := filepath.Dir(dir); p != os.TempDir() && p != "/"; p = filepath.Dir(p) {
		os.Chmod(p, 0755)
	}
	return dir
}

func TestRunCreatesFilesAsUser(t *testing.T) {
	needRoot(t)
	dir := sharedDir(t)
	u := &User{Name: "u", UID: 4001, GID: 4002, Groups: []int{4002}}
	if err := u.Run(func() {
		if err := os.WriteFile(filepath.Join(dir, "mine"), nil, 0644); err != nil {
			t.Error(err)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if uid, gid := owner(t, filepath.Join(dir, "mine")); uid != 4001 || gid != 4002 {
		t.Errorf("created as %d:%d", uid, gid)
	}
	// The thread is back to root afterwards
	os.WriteFile(filepath.Join(dir, "after"), nil, 0644)
	if uid, _ := owner(t, filepath.Join(dir, "after")); uid != 0 {
		t.Errorf("created after Run as %d", uid)
	}
}

func TestRunEnforcesPermissions(t *testing.T) {
	needRoot(t)
	dir := sharedDir(t)
	private := filepath.Join(dir, "private")
	os.Mkdir(private, 0750)
	os.WriteFile(filepath.Join(private, "f"), []byte("x"), 0640)
	os.Chown(private, 4001, 4100)
	os.Chown(filepath.Join(private, "f"), 4001, 4100)

	read := func(u *User) error {
		var err error
		if runErr := u.Run(func() { _, err = os.ReadFile(filepath.Join(private, "f")) }); runErr != nil {
			t.Fatal(runErr)
		}
		return err
	}
	if err := read(&User{Name: "owner", UID: 4001, GID: 4001, Groups: []int{4001}}); err != nil {
		t.Errorf("owner: %v", err)
	}
	if err := read(&User{Name: "stranger", UID: 4002, GID: 4002, Groups: []int{4002}}); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("stranger: %v", err)
	}
	// Supplementary groups count
	if err := read(&User{Name: "member", UID: 4003, GID: 4003, Groups: []int{4003, 4100}}); err != nil {
		t.Errorf("group member: %v", err)
	}
	// ...and only those of the user
	if err := read(&User{Name: "stranger", UID: 4002, GID: 4002, Groups: []int{4002}}); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("stranger after a group member: %v", err)
	}
}

// Goroutines running as different users at the same time, and goroutines not using
// Run, never see each other's identity
func TestRunIsolatesGoroutines(t *testing.T) {
	needRoot(t)
	dir := sharedDir(t)
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 20 {
				name := filepath.Join(dir, fmt.Sprintf("f-%d-%d", i, j))
				write := func() {
					runtime.Gosched()
					os.WriteFile(name, nil, 0644)
				}
				if i%4 == 0 {
					write() // as root
					continue
				}
				u := &User{Name: "u", UID: 5000 + i, GID: 5000 + i, Groups: []int{5000 + i}}
				if err := u.Run(write); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	for i := range 32 {
		want := 5000 + i
		if i%4 == 0 {
			want = 0
		}
		for j := range 20 {
			name := filepath.Join(dir, fmt.Sprintf("f-%d-%d", i, j))
			if uid, gid := owner(t, name); uid != want || gid != want {
				t.Fatalf("%s created as %d:%d, want %d", name, uid, gid, want)
			}
		}
	}
}

func TestCheck(t *testing.T) {
	needRoot(t)
	if err := Check(); err != nil {
		t.Fatal(err)
	}
}
