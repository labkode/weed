package seccomp

import (
	"errors"
	"net"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// restricted runs f on a thread filtered with s, which is then discarded
func restricted(t *testing.T, s Sockets, f func()) {
	if auditArch == 0 {
		t.Skipf("not on %s", runtime.GOARCH)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread() // never unlocked: the thread ends with this goroutine
		if err := Restrict(s); err != nil {
			t.Error(err)
			return
		}
		f()
	}()
	<-done
}

// open opens a socket, and says why it could not (nil if it could)
func open(domain, typ, proto int) error {
	fd, err := unix.Socket(domain, typ|unix.SOCK_CLOEXEC, proto)
	if err == nil {
		unix.Close(fd)
	}
	return err
}

func TestRestrict(t *testing.T) {
	const afSMC = 43
	type socket struct {
		name               string
		domain, typ, proto int
		tcpudp, unixOnly   error // what Restrict leaves of it, if the kernel opens it
	}
	refused := []socket{
		{"MPTCP", unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_MPTCP, unix.EPROTONOSUPPORT, unix.EAFNOSUPPORT},
		{"MPTCP over IPv6", unix.AF_INET6, unix.SOCK_STREAM, unix.IPPROTO_MPTCP, unix.EPROTONOSUPPORT, unix.EAFNOSUPPORT},
		{"SCTP", unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_SCTP, unix.EPROTONOSUPPORT, unix.EAFNOSUPPORT},
		{"SCTP, one to many", unix.AF_INET, unix.SOCK_SEQPACKET, unix.IPPROTO_SCTP, unix.EPROTONOSUPPORT, unix.EAFNOSUPPORT},
		{"ICMP", unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP, unix.EPROTONOSUPPORT, unix.EAFNOSUPPORT},
		{"raw IP", unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW, unix.EPROTONOSUPPORT, unix.EAFNOSUPPORT},
		{"packet", unix.AF_PACKET, unix.SOCK_RAW, 0, unix.EAFNOSUPPORT, unix.EAFNOSUPPORT},
		{"SMC", afSMC, unix.SOCK_STREAM, 0, unix.EAFNOSUPPORT, unix.EAFNOSUPPORT},
		{"vsock", unix.AF_VSOCK, unix.SOCK_STREAM, 0, unix.EAFNOSUPPORT, unix.EAFNOSUPPORT},
	}
	allowed := []socket{
		{"Unix", unix.AF_UNIX, unix.SOCK_STREAM, 0, nil, nil},
		{"Unix datagrams", unix.AF_UNIX, unix.SOCK_DGRAM, 0, nil, nil},
		{"Unix sequenced packets", unix.AF_UNIX, unix.SOCK_SEQPACKET, 0, nil, nil},
		{"netlink", unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE, nil, unix.EAFNOSUPPORT},
		{"TCP", unix.AF_INET, unix.SOCK_STREAM, 0, nil, unix.EAFNOSUPPORT},
		{"TCP, by its number", unix.AF_INET, unix.SOCK_STREAM | unix.SOCK_NONBLOCK, unix.IPPROTO_TCP, nil, unix.EAFNOSUPPORT},
		{"TCP over IPv6", unix.AF_INET6, unix.SOCK_STREAM, 0, nil, unix.EAFNOSUPPORT},
		{"UDP", unix.AF_INET, unix.SOCK_DGRAM, 0, nil, unix.EAFNOSUPPORT},
		{"UDP, by its number", unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP, nil, unix.EAFNOSUPPORT},
		{"UDP over IPv6", unix.AF_INET6, unix.SOCK_DGRAM, 0, nil, unix.EAFNOSUPPORT},
	}
	// What the kernel opens unfiltered: a socket it refuses tells nothing of the filter
	var opened []socket
	for _, s := range append(refused, allowed...) {
		if err := open(s.domain, s.typ, s.proto); err != nil {
			t.Logf("%s: not opened unfiltered either: %v", s.name, err)
			continue
		}
		opened = append(opened, s)
	}
	for _, mode := range []Sockets{TCPUDP, UnixOnly} {
		restricted(t, mode, func() {
			for _, s := range opened {
				want := s.tcpudp
				if mode == UnixOnly {
					want = s.unixOnly
				}
				if err := open(s.domain, s.typ, s.proto); !errors.Is(err, want) && (err != nil || want != nil) {
					t.Errorf("%v: %s: %v, want %v", mode, s.name, err, want)
				}
			}
			var params [120]byte // struct io_uring_params
			if _, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, 1, uintptr(unsafe.Pointer(&params)), 0); errno != unix.ENOSYS {
				t.Errorf("%v: io_uring_setup: %v, want ENOSYS", mode, errno)
			}
		})
	}
}

// Go listens with MPTCP where the kernel has it: filtered, it listens with TCP, which
// Landlock confines
func TestListenTCP(t *testing.T) {
	restricted(t, TCPUDP, func() {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Error(err)
			return
		}
		defer l.Close()
		raw, err := l.(*net.TCPListener).SyscallConn()
		if err != nil {
			t.Error(err)
			return
		}
		var proto int
		raw.Control(func(fd uintptr) { proto, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PROTOCOL) })
		if err != nil || proto != unix.IPPROTO_TCP {
			t.Errorf("the listener's protocol: %d (%v), want TCP", proto, err)
		}
	})
}

func TestFiltered(t *testing.T) {
	if Filtered(TCPUDP) || Filtered(UnixOnly) {
		t.Fatal("unfiltered, the test says it is filtered")
	}
	restricted(t, TCPUDP, func() {
		if !Filtered(TCPUDP) || Filtered(UnixOnly) {
			t.Errorf("filtered for %v: %v, %v", TCPUDP, Filtered(TCPUDP), Filtered(UnixOnly))
		}
	})
	restricted(t, UnixOnly, func() {
		if !Filtered(TCPUDP) || !Filtered(UnixOnly) {
			t.Errorf("filtered for %v: %v, %v", UnixOnly, Filtered(TCPUDP), Filtered(UnixOnly))
		}
	})
}
