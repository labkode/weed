//go:build unix

package systemd

import (
	"net"
	"os"
	"strconv"
	"syscall"
	"testing"
)

// The sockets that systemd passes become listeners; the variables that pass them are
// unset, and a process that they are not for takes none
func TestListeners(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	f, err := l.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Dup(int(f.Fd())) // as systemd passes it: a descriptor of its own
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	ls, err := fileListeners(fd, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 1 || ls[0].Addr().String() != l.Addr().String() {
		t.Fatalf("listeners %v, want one on %s", ls, l.Addr())
	}
	defer ls[0].Close()
	go func() {
		if c, err := net.Dial("tcp", l.Addr().String()); err == nil {
			c.Close()
		}
	}()
	c, err := ls[0].Accept()
	if err != nil {
		t.Fatal(err)
	}
	c.Close()

	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()+1))
	t.Setenv("LISTEN_FDS", "1")
	t.Setenv("LISTEN_FDNAMES", "https")
	if ls, err := Listeners(); err != nil || len(ls) != 0 {
		t.Errorf("for another process: %v, %v", ls, err)
	}
	for _, v := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		if _, set := os.LookupEnv(v); set {
			t.Errorf("%s still set", v)
		}
	}
}
