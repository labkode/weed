package landlock

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ABI is the version of Landlock of the kernel, 0 without Landlock
func ABI() int {
	v, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0
	}
	return int(v)
}

const (
	read  = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR
	write = read | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE | unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_REFER | unix.LANDLOCK_ACCESS_FS_TRUNCATE
	// fileAccess is what a rule of a file, rather than a directory, may allow
	fileAccess = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_TRUNCATE | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
)

func (a Access) rights() uint64 {
	switch a {
	case Read:
		return read
	case Exec:
		return read | unix.LANDLOCK_ACCESS_FS_EXECUTE
	case Write:
		return write
	case Socket:
		return write | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK
	}
	return 0
}

// handled is what a ruleset takes away on a kernel of Landlock abi, but what its
// rules allow: every access to files of that version
func handled(abi int) uint64 {
	h := uint64(unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM)
	if abi >= 2 {
		h |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		h |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 5 {
		h |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	return h
}

// Ruleset is rules made into what Restrict applies
type Ruleset struct{ fd int }

// New makes a ruleset of rules, leaving out those whose path does not exist, and of
// nw. From Landlock ABI 6 on, it also keeps what it confines from signalling
// processes outside.
func New(rules []Rule, nw Net) (*Ruleset, error) {
	abi := ABI()
	if abi < MinABI {
		return nil, fmt.Errorf("Landlock ABI %d, and %d is needed (Linux 5.19 or later, landlock in lsm=)", abi, MinABI)
	}
	h := handled(abi)
	attr := unix.LandlockRulesetAttr{Handled_access_fs: h}
	size := unsafe.Offsetof(attr.Handled_access_net) // what ABIs before 4 know
	if abi >= TCPABI {
		if !nw.Bind {
			attr.Handled_access_net |= unix.LANDLOCK_ACCESS_NET_BIND_TCP
		}
		if !nw.Connect {
			attr.Handled_access_net |= unix.LANDLOCK_ACCESS_NET_CONNECT_TCP
		}
		size = unsafe.Offsetof(attr.Scoped)
	}
	if abi >= 6 {
		attr.Scoped = unix.LANDLOCK_SCOPE_SIGNAL
		if !nw.AbstractUnix {
			attr.Scoped |= unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
		}
		size = unsafe.Offsetof(attr.Quiet_access_fs)
	}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), size, 0)
	if errno == unix.EINVAL && attr.Scoped&unix.LANDLOCK_SCOPE_SIGNAL != 0 {
		// RHEL 9's kernels (from 5.14.0-603.el9) say ABI 6 without the signal scope:
		// there, signals are not confined
		attr.Scoped &^= unix.LANDLOCK_SCOPE_SIGNAL
		fd, _, errno = unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), size, 0)
	}
	if errno != 0 {
		return nil, fmt.Errorf("landlock_create_ruleset: %w", errno)
	}
	rs := &Ruleset{fd: int(fd)}
	for _, rule := range rules {
		if err := rs.add(rule, h); err != nil {
			rs.Close()
			return nil, err
		}
	}
	if attr.Handled_access_net&unix.LANDLOCK_ACCESS_NET_BIND_TCP != 0 {
		for _, port := range nw.Ports {
			if err := rs.addPort(port); err != nil {
				rs.Close()
				return nil, err
			}
		}
	}
	return rs, nil
}

// netPortAttr is the kernel's landlock_net_port_attr, which x/sys does not have
type netPortAttr struct {
	allowedAccess uint64
	port          uint64
}

// ruleNetPort is LANDLOCK_RULE_NET_PORT
const ruleNetPort = 2

// addPort allows binding TCP sockets to port
func (rs *Ruleset) addPort(port uint16) error {
	attr := netPortAttr{allowedAccess: unix.LANDLOCK_ACCESS_NET_BIND_TCP, port: uint64(port)}
	_, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(rs.fd), ruleNetPort,
		uintptr(unsafe.Pointer(&attr)), 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("landlock_add_rule: TCP port %d: %w", port, errno)
	}
	return nil
}

func (rs *Ruleset) add(rule Rule, handled uint64) error {
	var fd int
	if rule.File != nil {
		fd = int(rule.File.Fd())
	} else {
		var err error
		fd, err = unix.Open(rule.Path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err == unix.ENOENT {
			return nil
		}
		if err != nil {
			return &os.PathError{Op: "open", Path: rule.Path, Err: err}
		}
		defer unix.Close(fd)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return &os.PathError{Op: "stat", Path: rule.Path, Err: err}
	}
	allowed := rule.Access.rights() & handled
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		allowed &= fileAccess
	}
	attr := unix.LandlockPathBeneathAttr{Allowed_access: allowed, Parent_fd: int32(fd)}
	_, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(rs.fd), unix.LANDLOCK_RULE_PATH_BENEATH,
		uintptr(unsafe.Pointer(&attr)), 0, 0, 0)
	if errno != 0 {
		return &os.PathError{Op: "landlock_add_rule", Path: rule.Path, Err: errno}
	}
	return nil
}

// Restrict confines the calling thread to the ruleset, for good, and so the
// processes it starts from then on. The thread needs no_new_privs (or CAP_SYS_ADMIN):
// make it one locked with runtime.LockOSThread, never given back to Go.
func (rs *Ruleset) Restrict() error {
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(rs.fd), 0, 0); errno != 0 {
		return fmt.Errorf("landlock_restrict_self: %w", errno)
	}
	return nil
}

// Exec confines the calling thread to the ruleset, with no_new_privs, and executes
// this process's executable again in its place, with argv and env: the program then
// runs confined on every thread, where Restrict confines one. It returns only if that
// fails, and leaves the thread confined.
func (rs *Ruleset) Exec(argv, env []string) error {
	runtime.LockOSThread() // never unlocked: the thread is confined
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("cannot set no_new_privs: %w", err)
	}
	if err := rs.Restrict(); err != nil {
		return err
	}
	return unix.Exec("/proc/self/exe", argv, env)
}

// Unreachable is the first of paths that this process can open, and a thread confined
// to the ruleset cannot ("" if none): on some file systems, such as Docker Desktop's
// mounts of the host, Landlock refuses everything, whatever the rules
func (rs *Ruleset) Unreachable(paths ...string) (string, error) {
	var open []string
	for _, p := range paths {
		if f, err := os.Open(p); err == nil {
			f.Close()
			open = append(open, p)
		}
	}
	type result struct {
		path string
		err  error
	}
	c := make(chan result, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread ends with this goroutine
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			c <- result{err: fmt.Errorf("cannot set no_new_privs: %w", err)}
			return
		}
		if err := rs.Restrict(); err != nil {
			c <- result{err: err}
			return
		}
		for _, p := range open {
			f, err := os.Open(p)
			if err != nil {
				c <- result{path: p}
				return
			}
			f.Close()
		}
		c <- result{}
	}()
	r := <-c
	return r.path, r.err
}

// Dup is another reference to the ruleset, to close on its own
func (rs *Ruleset) Dup() (*Ruleset, error) {
	fd, err := unix.FcntlInt(uintptr(rs.fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot duplicate the ruleset: %w", err)
	}
	return &Ruleset{fd: fd}, nil
}

// Close frees the ruleset; what it confines stays confined
func (rs *Ruleset) Close() error { return unix.Close(rs.fd) }
