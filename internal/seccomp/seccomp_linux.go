// Package seccomp keeps weed and its workers from opening the sockets that Landlock
// does not confine. Landlock's rules of TCP cover TCP alone: not MPTCP, which falls
// back to TCP with peers that do not have it, nor SCTP, SMC or raw and packet
// sockets. A filter of system calls lets a thread and what it starts open only Unix
// and netlink sockets, and of IPv4 and IPv6 only TCP and UDP ones (or none), and
// takes io_uring away, which opens sockets without socket(2).
package seccomp

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Sockets are the sockets that a filter lets a thread open (see Restrict)
type Sockets int

const (
	// TCPUDP are Unix and netlink sockets, and TCP and UDP sockets of IPv4 and IPv6
	TCPUDP Sockets = iota
	// UnixOnly are Unix sockets
	UnixOnly
)

func (s Sockets) String() string {
	if s == UnixOnly {
		return "Unix"
	}
	return "Unix, netlink, TCP and UDP"
}

// auditArch is the architecture that the kernel says system calls are of, for this
// one; the filter refuses others, such as i386's from an amd64 process
var auditArch = map[string]uint32{
	"amd64": unix.AUDIT_ARCH_X86_64,
	"arm64": unix.AUDIT_ARCH_AARCH64,
}[runtime.GOARCH]

const (
	// Offsets in struct seccomp_data, and of the low 32 bits of an argument on these
	// little-endian architectures: socket(2)'s are ints, of which the kernel reads those
	offNr   = 0
	offArch = 4
	offArg0 = 16

	sockTypeMask = 0xf // what of socket(2)'s type is the type, without SOCK_CLOEXEC and SOCK_NONBLOCK
	x32Bit       = 0x40000000
)

// Restrict filters the system calls of the calling thread, and of the processes it
// starts and executes, for good: it may open only the sockets of s, and has no
// io_uring. It sets no_new_privs, which the kernel needs. Make the thread one locked
// with runtime.LockOSThread, never given back to Go.
func Restrict(s Sockets) error {
	if auditArch == 0 {
		return fmt.Errorf("weed filters its system calls with seccomp on amd64 and arm64, not on %s", runtime.GOARCH)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("cannot set no_new_privs: %w", err)
	}
	f := filter(s)
	prog := unix.SockFprog{Len: uint16(len(f)), Filter: &f[0]}
	if err := unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&prog)), 0, 0); err != nil {
		return fmt.Errorf("cannot filter system calls with seccomp: %w", err)
	}
	return nil
}

// Filtered reports whether the calling thread may open no more sockets than those of
// s, by opening one that the filter refuses and the kernel does not: of raw IP, which
// only the filter refuses with EPROTONOSUPPORT, or for UnixOnly, of TCP. (Containers
// have filters of their own, so that the status of the thread tells nothing.)
func Filtered(s Sockets) bool {
	domain, typ, proto := unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW
	if s == UnixOnly {
		typ, proto = unix.SOCK_STREAM, 0
	}
	fd, err := unix.Socket(domain, typ|unix.SOCK_CLOEXEC, proto)
	if err == nil {
		unix.Close(fd)
	}
	return err == unix.EAFNOSUPPORT || s == TCPUDP && err == unix.EPROTONOSUPPORT
}

// filter is the program of s, in classic BPF
func filter(s Sockets) []unix.SockFilter {
	var a asm
	a.ld(offArch)
	a.jeq(auditArch, "", "kill")
	a.ld(offNr)
	if runtime.GOARCH == "amd64" {
		a.jump(unix.BPF_JGE, x32Bit, "kill", "") // the system calls of x32
	}
	a.jeq(unix.SYS_IO_URING_SETUP, "enosys", "")
	a.jeq(unix.SYS_IO_URING_ENTER, "enosys", "")
	a.jeq(unix.SYS_IO_URING_REGISTER, "enosys", "")
	a.jeq(unix.SYS_SOCKET, "", "allow")

	a.ld(offArg0) // domain
	a.jeq(unix.AF_UNIX, "allow", "")
	if s == TCPUDP {
		a.jeq(unix.AF_NETLINK, "allow", "")
		a.jeq(unix.AF_INET, "ip", "")
		a.jeq(unix.AF_INET6, "ip", "")
	}
	a.ret(unix.SECCOMP_RET_ERRNO | uint32(unix.EAFNOSUPPORT))
	if s == TCPUDP {
		// Go takes EPROTONOSUPPORT for a kernel without MPTCP, and listens with TCP
		a.label("ip")
		a.ld(offArg0 + 8) // type
		a.and(sockTypeMask)
		a.jeq(unix.SOCK_STREAM, "stream", "")
		a.jeq(unix.SOCK_DGRAM, "dgram", "")
		a.ret(unix.SECCOMP_RET_ERRNO | uint32(unix.EPROTONOSUPPORT))
		a.label("stream")
		a.ld(offArg0 + 16) // protocol
		a.jeq(0, "allow", "")
		a.jeq(unix.IPPROTO_TCP, "allow", "")
		a.ret(unix.SECCOMP_RET_ERRNO | uint32(unix.EPROTONOSUPPORT))
		a.label("dgram")
		a.ld(offArg0 + 16)
		a.jeq(0, "allow", "")
		a.jeq(unix.IPPROTO_UDP, "allow", "")
		a.ret(unix.SECCOMP_RET_ERRNO | uint32(unix.EPROTONOSUPPORT))
	}
	a.label("allow")
	a.ret(unix.SECCOMP_RET_ALLOW)
	a.label("kill")
	a.ret(unix.SECCOMP_RET_KILL_PROCESS)
	a.label("enosys")
	a.ret(unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS))
	return a.assemble()
}

// asm writes a program of classic BPF whose jumps go to labels ("": the next
// instruction)
type asm struct {
	insns  []insn
	labels map[string]int
}

type insn struct {
	unix.SockFilter
	jt, jf string
}

func (a *asm) ld(off uint32) {
	a.insns = append(a.insns, insn{SockFilter: unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: off}})
}

func (a *asm) and(k uint32) {
	a.insns = append(a.insns, insn{SockFilter: unix.SockFilter{Code: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, K: k}})
}

func (a *asm) jeq(k uint32, jt, jf string) { a.jump(unix.BPF_JEQ, k, jt, jf) }

func (a *asm) jump(op uint16, k uint32, jt, jf string) {
	a.insns = append(a.insns, insn{SockFilter: unix.SockFilter{Code: unix.BPF_JMP | op | unix.BPF_K, K: k}, jt: jt, jf: jf})
}

func (a *asm) ret(k uint32) {
	a.insns = append(a.insns, insn{SockFilter: unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: k}})
}

func (a *asm) label(name string) {
	if a.labels == nil {
		a.labels = make(map[string]int)
	}
	a.labels[name] = len(a.insns)
}

func (a *asm) assemble() []unix.SockFilter {
	offset := func(i int, label string) uint8 {
		if label == "" {
			return 0
		}
		to, ok := a.labels[label]
		if !ok || to <= i || to-i-1 > 255 {
			panic("seccomp: no jump forward to " + label)
		}
		return uint8(to - i - 1)
	}
	prog := make([]unix.SockFilter, len(a.insns))
	for i, in := range a.insns {
		prog[i] = in.SockFilter
		prog[i].Jt, prog[i].Jf = offset(i, in.jt), offset(i, in.jf)
	}
	return prog
}
