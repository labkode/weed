package landlock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// confined runs f on a thread confined to rules, and to nw, which is then discarded
func confined(t *testing.T, rules []Rule, nw Net, f func()) {
	if abi := ABI(); abi < MinABI {
		t.Skipf("Landlock ABI %d", abi)
	}
	rs, err := New(rules, nw)
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

	confined(t, rules, Net{Bind: true, Connect: true}, func() {
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
	confined(t, []Rule{{Path: "/", Access: Exec}}, Net{Bind: true, Connect: true}, func() {
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

// listenTCP listens on addr with a TCP socket. Not net.Listen, which listens with
// MPTCP where the kernel has it (Go 1.24 on): Landlock's rules of TCP do not cover
// MPTCP, nor other protocols, on recent kernels.
func listenTCP(addr string) (net.Listener, error) {
	var lc net.ListenConfig
	lc.SetMultipathTCP(false)
	return lc.Listen(context.Background(), "tcp", addr)
}

// From Landlock ABI 4 on, TCP binds and connects are refused unless allowed
func TestConfinedTCP(t *testing.T) {
	if abi := ABI(); abi < TCPABI {
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
	for _, tcp := range []Net{{}, {Connect: true}, {Bind: true, Connect: true}} {
		confined(t, nil, tcp, func() {
			c, err := net.Dial("tcp", l.Addr().String())
			if err == nil {
				c.Close()
			}
			if tcp.Connect != (err == nil) || err != nil && !errors.Is(err, os.ErrPermission) {
				t.Errorf("%+v: connect: %v", tcp, err)
			}
			l2, err := listenTCP("127.0.0.1:0")
			if err == nil {
				l2.Close()
			}
			if tcp.Bind != (err == nil) || err != nil && !errors.Is(err, os.ErrPermission) {
				t.Errorf("%+v: bind: %v", tcp, err)
			}
		})
	}
}

// Of the ports to bind TCP sockets to, Ports allows those it lists
func TestConfinedPorts(t *testing.T) {
	if abi := ABI(); abi < TCPABI {
		t.Skipf("Landlock ABI %d", abi)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	confined(t, nil, Net{Ports: []uint16{uint16(port)}}, func() {
		l, err := listenTCP(fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Errorf("port %d, allowed: %v", port, err)
		} else {
			l.Close()
		}
		if l, err := listenTCP("127.0.0.1:0"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("another port: %v, want a permission error", err)
			if err == nil {
				l.Close()
			}
		}
	})
}

// Exec executes the program again confined, on every thread: TestExec runs itself
// (LANDLOCK_EXEC=again), which confines itself and executes itself again (confined)
func TestExec(t *testing.T) {
	if abi := ABI(); abi < MinABI {
		t.Skipf("Landlock ABI %d", abi)
	}
	dir := os.Getenv("LANDLOCK_EXEC_DIR")
	switch os.Getenv("LANDLOCK_EXEC") {
	case "":
		dir := t.TempDir()
		cmd := exec.Command(os.Args[0], "-test.run=^TestExec$", "-test.v")
		cmd.Env = append(os.Environ(), "LANDLOCK_EXEC=again", "LANDLOCK_EXEC_DIR="+dir)
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "confined on every thread") {
			t.Fatalf("%v\n%s", err, out)
		}
	case "again":
		// The test's executable, and what a build with cgo (-race) loads
		rules := []Rule{{Path: dir, Access: Read}, {Path: "/proc/self/exe", Access: Exec}, {Path: "/proc", Access: Read},
			{Path: "/usr", Access: Read}, {Path: "/lib", Access: Read}, {Path: "/lib64", Access: Read}}
		if interp := Interpreter("/proc/self/exe"); interp != "" {
			rules = append(rules, Rule{Path: interp, Access: Exec})
		}
		rs, err := New(rules, Net{Bind: true, Connect: true})
		if err != nil {
			t.Fatal(err)
		}
		env := slices.DeleteFunc(os.Environ(), func(e string) bool { return strings.HasPrefix(e, "LANDLOCK_EXEC=") })
		env = append(env, "LANDLOCK_EXEC=confined")
		t.Fatal(rs.Exec(os.Args, env)) // only if it fails
	case "confined":
		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() {
				runtime.LockOSThread() // a thread of its own
				defer runtime.UnlockOSThread()
				if _, err := os.Open("/"); !errors.Is(err, os.ErrPermission) {
					t.Errorf("open /: %v, want a permission error", err)
				}
				if f, err := os.Open(dir); err != nil {
					t.Errorf("open %s, allowed: %v", dir, err)
				} else {
					f.Close()
				}
			})
		}
		wg.Wait()
		if !t.Failed() {
			fmt.Println("confined on every thread")
		}
	}
}

// What a thread confined to a ruleset cannot open, and this process can, is found
func TestUnreachable(t *testing.T) {
	if abi := ABI(); abi < MinABI {
		t.Skipf("Landlock ABI %d", abi)
	}
	in, out := t.TempDir(), t.TempDir()
	rs, err := New([]Rule{{Path: in, Access: Read}}, Net{})
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	if p, err := rs.Unreachable(in, filepath.Join(in, "missing")); p != "" || err != nil {
		t.Errorf("allowed: %q, %v", p, err)
	}
	if p, err := rs.Unreachable(in, out); p != out || err != nil {
		t.Errorf("refused: %q, %v, want %s", p, err, out)
	}
}

// Beneath a directory of Socket, Unix sockets are made; beneath one of Write, not
func TestConfinedSocket(t *testing.T) {
	w, s := t.TempDir(), t.TempDir()
	confined(t, []Rule{{Path: w, Access: Write}, {Path: s, Access: Socket}}, Net{}, func() {
		if l, err := net.Listen("unix", filepath.Join(w, "s")); !errors.Is(err, os.ErrPermission) {
			t.Errorf("socket beneath Write: %v, want a permission error", err)
			if err == nil {
				l.Close()
			}
		}
		l, err := net.Listen("unix", filepath.Join(s, "s"))
		if err != nil {
			t.Errorf("socket beneath Socket: %v", err)
			return
		}
		l.Close()
	})
}

// Rules confine to plain directories and to mount points alike: each names what its
// path leads to as it is made, and covers what is beneath, storage mounted there
// later included; not a storage mounted over it later, nor the directory that an
// unmounted storage leaves. Needs root.
func TestConfinedMounts(t *testing.T) {
	dir := t.TempDir()
	plain, mnt := filepath.Join(dir, "plain"), filepath.Join(dir, "mnt")
	for _, d := range []string{filepath.Join(plain, "sub"), mnt} {
		os.MkdirAll(d, 0o755)
	}
	mount := func(at string) error {
		err := unix.Mount("tmpfs", at, "tmpfs", 0, "")
		if err == nil {
			t.Cleanup(func() { unix.Unmount(at, unix.MNT_DETACH) })
		}
		return err
	}
	if err := mount(mnt); err != nil {
		t.Skipf("cannot mount (not root, or a container without privileges?): %v", err)
	}
	rules := []Rule{{Path: plain, Access: Write}, {Path: mnt, Access: Write}}
	confined(t, rules, Net{Bind: true, Connect: true}, func() {
		write := func(name string) error { return os.WriteFile(name, nil, 0o644) }
		// From another thread, which is not confined
		unconfined := func(f func() error) bool {
			done := make(chan error)
			go func() { done <- f() }()
			err := <-done
			if err != nil {
				t.Error(err)
			}
			return err == nil
		}
		for name, want := range map[string]error{
			filepath.Join(plain, "f"): nil, // a plain directory
			filepath.Join(mnt, "f"):   nil, // the root of a storage mounted there
		} {
			if err := write(name); !errors.Is(err, want) {
				t.Errorf("write %s: %v, want %v", name, err, want)
			}
		}
		if !unconfined(func() error { return mount(filepath.Join(plain, "sub")) }) {
			return
		}
		if err := write(filepath.Join(plain, "sub", "f")); err != nil {
			t.Errorf("in a storage mounted beneath, later: %v", err)
		}
		if !unconfined(func() error { return mount(plain) }) {
			return
		}
		if err := write(filepath.Join(plain, "g")); !errors.Is(err, os.ErrPermission) {
			t.Errorf("in a storage mounted over the directory, later: %v, want a permission error", err)
		}
		if !unconfined(func() error { return unix.Unmount(mnt, 0) }) {
			return
		}
		if err := write(filepath.Join(mnt, "g")); !errors.Is(err, os.ErrPermission) {
			t.Errorf("in the directory beneath a storage unmounted later: %v, want a permission error", err)
		}
	})
}
