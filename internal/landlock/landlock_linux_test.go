package landlock

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// confined runs f on a thread confined to rules, which is then discarded
func confined(t *testing.T, rules []Rule, f func()) {
	if abi := ABI(); abi < MinABI {
		t.Skipf("Landlock ABI %d", abi)
	}
	rs, err := New(rules)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread() // never unlocked: the thread ends with this goroutine
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			t.Error(err)
			return
		}
		if err := rs.Restrict(); err != nil {
			t.Error(err)
			return
		}
		f()
	}()
	<-done
}

// Beneath a directory of Write, files are made, written, renamed from one directory
// to another, and removed; beneath one of Read, read only; elsewhere, nothing. Paths
// that do not exist are left out.
func TestConfined(t *testing.T) {
	rw, ro, elsewhere := t.TempDir(), t.TempDir(), t.TempDir()
	for _, dir := range []string{ro, elsewhere} {
		os.WriteFile(filepath.Join(dir, "f"), []byte("f"), 0o644)
	}
	os.Mkdir(filepath.Join(rw, "a"), 0o755)
	os.Mkdir(filepath.Join(rw, "b"), 0o755)
	file := filepath.Join(elsewhere, "allowed")
	os.WriteFile(file, []byte("allowed"), 0o644)
	rules := []Rule{{Path: rw, Access: Write}, {Path: ro, Access: Read}, {Path: file, Access: Read},
		{Path: filepath.Join(rw, "missing"), Access: Read}}

	confined(t, rules, func() {
		mustFail := func(what string, err error) {
			if !errors.Is(err, os.ErrPermission) {
				t.Errorf("%s: %v, want a permission error", what, err)
			}
		}
		must := func(what string, err error) {
			if err != nil {
				t.Errorf("%s: %v", what, err)
			}
		}
		must("write", os.WriteFile(filepath.Join(rw, "a", "f"), []byte("new"), 0o644))
		must("rename across directories", os.Rename(filepath.Join(rw, "a", "f"), filepath.Join(rw, "b", "f")))
		must("mkdir", os.Mkdir(filepath.Join(rw, "c"), 0o755))
		must("remove", os.RemoveAll(filepath.Join(rw, "b")))
		_, err := os.ReadFile(filepath.Join(ro, "f"))
		must("read", err)
		_, err = os.ReadFile(file)
		must("read an allowed file", err)

		mustFail("write where only reading is allowed", os.WriteFile(filepath.Join(ro, "g"), nil, 0o644))
		mustFail("remove where only reading is allowed", os.Remove(filepath.Join(ro, "f")))
		_, err = os.ReadFile(filepath.Join(elsewhere, "f"))
		mustFail("read elsewhere", err)
		_, err = os.ReadDir(elsewhere)
		mustFail("list elsewhere", err)
		mustFail("symbolic link", os.Symlink("f", filepath.Join(rw, "link")))
		mustFail("rename out", os.Rename(filepath.Join(rw, "c"), filepath.Join(elsewhere, "c")))
	})

	// The rest of the process is not confined
	if _, err := os.ReadFile(filepath.Join(elsewhere, "f")); err != nil {
		t.Errorf("after: %v", err)
	}
}

// A process started from a confined thread is confined too
func TestConfinedChild(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "f"), []byte("f"), 0o644)
	confined(t, []Rule{{Path: "/", Access: Exec}}, func() {
		var attr os.ProcAttr
		p, err := os.StartProcess("/bin/sh", []string{"sh", "-c", "echo x >" + filepath.Join(dir, "g")}, &attr)
		if err != nil {
			t.Error(err)
			return
		}
		st, _ := p.Wait()
		if st.Success() {
			t.Error("the child wrote where its parent may only read")
		}
	})
	if _, err := os.Stat(filepath.Join(dir, "g")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("g: %v", err)
	}
}
