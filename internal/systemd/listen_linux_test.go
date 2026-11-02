package systemd

import (
	"net"
	"slices"
	"testing"
)

func TestSocketPorts(t *testing.T) {
	var fds []int
	var want []int
	for _, a := range []string{"127.0.0.1:0", "[::1]:0"} {
		l, err := net.Listen("tcp", a)
		if err != nil {
			t.Skip(err)
		}
		defer l.Close()
		f, err := l.(*net.TCPListener).File()
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		fds = append(fds, int(f.Fd()))
		want = append(want, l.Addr().(*net.TCPAddr).Port)
	}
	// Not consecutive descriptors, as systemd passes them: one at a time
	var got []int
	for _, fd := range fds {
		got = append(got, socketPorts(fd, 1)...)
	}
	if !slices.Equal(got, want) {
		t.Errorf("ports %v, want %v", got, want)
	}
}
