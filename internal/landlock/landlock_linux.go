package landlock

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Access is what a Rule allows
type Access uint8

const (
	Read  Access = iota + 1 // read files, list directories
	Exec                    // Read, and execute files
	Write                   // Read, and write, create, rename and remove files and directories
)

// Rule allows Access beneath Path, a directory, or to Path, a file
type Rule struct {
	Path   string
	Access Access
	// File, if set, is Path open (O_PATH is enough): the rule names it, rather than
	// what Path names when New opens it
	File *os.File
}

// MinABI is the version of Landlock that New needs: before it, Landlock refuses to
// rename or link files from one directory to another, whatever the rules
const MinABI = 2

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

// New makes a ruleset of rules, leaving out those whose path does not exist. From
// Landlock ABI 6 on, it also keeps what it confines from signalling processes, and
// connecting to abstract Unix sockets, outside.
func New(rules []Rule) (*Ruleset, error) {
	abi := ABI()
	if abi < MinABI {
		return nil, fmt.Errorf("Landlock ABI %d, and %d is needed (Linux 5.19 or later, landlock in lsm=)", abi, MinABI)
	}
	h := handled(abi)
	attr := unix.LandlockRulesetAttr{Handled_access_fs: h}
	size := unsafe.Offsetof(attr.Handled_access_net) // the size that ABIs before 6 know
	if abi >= 6 {
		attr.Scoped = unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | unix.LANDLOCK_SCOPE_SIGNAL
		size = unsafe.Offsetof(attr.Quiet_access_fs)
	}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), size, 0)
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
	return rs, nil
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
