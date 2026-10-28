//go:build linux

package fsuser

import (
	"fmt"
	"os"
	"runtime"
	"slices"

	"golang.org/x/sys/unix"
)

// process is the identity every thread has outside Run
var process = func() (p struct {
	uid, gid int
	groups   []int
	err      error
}) {
	p.uid, p.gid = unix.Geteuid(), unix.Getegid()
	p.groups, p.err = unix.Getgroups()
	return p
}()

// Run calls f with the calling goroutine's filesystem identity switched to u. Only
// the calling goroutine is affected: goroutines that f starts keep the process's
// identity, so they may use files that f opened but must not open others.
//
// If the thread's identity cannot be restored afterwards, Run panics with the thread
// still locked, so that the thread ends with the goroutine (net/http recovers the
// panic and closes the connection) instead of running others as u.
func (u *User) Run(f func()) error {
	if process.err != nil {
		return fmt.Errorf("cannot read the process's groups: %w", process.err)
	}
	runtime.LockOSThread()
	if err := setIdentity(u.UID, u.GID, u.Groups); err != nil {
		restore()
		runtime.UnlockOSThread()
		return fmt.Errorf("cannot act as %s: %w", u.Name, err)
	}
	defer func() {
		restore()
		runtime.UnlockOSThread()
	}()
	f()
	return nil
}

func restore() {
	if err := setIdentity(process.uid, process.gid, process.groups); err != nil {
		panic(fmt.Sprintf("fsuser: cannot restore the thread's identity: %v", err))
	}
}

func setIdentity(uid, gid int, groups []int) error {
	// Unchanged groups are left alone: setgroups needs CAP_SETGID even then
	if cur, err := unix.Getgroups(); err != nil || !slices.Equal(cur, groups) {
		if err := unix.Setgroups(groups); err != nil {
			return fmt.Errorf("setgroups: %w", err)
		}
	}
	// setfsuid and setfsgid do not report errors: the values are read back
	unix.Setfsgid(gid)
	unix.Setfsuid(uid)
	if got, _ := unix.SetfsgidRetGid(-1); got != gid {
		return fmt.Errorf("cannot set the filesystem GID to %d", gid)
	}
	if got, _ := unix.SetfsuidRetUid(-1); got != uid {
		return fmt.Errorf("cannot set the filesystem UID to %d", uid)
	}
	return nil
}

// Writable reports whether the calling thread may write the file or directory p, by
// the kernel's rules (ACLs included). Within Run, that is whether the user may.
func Writable(p string) error {
	err := unix.Faccessat2(unix.AT_FDCWD, p, unix.W_OK, unix.AT_EACCESS)
	if err != unix.ENOSYS {
		if err != nil {
			return &os.PathError{Op: "access", Path: p, Err: err}
		}
		return nil
	}
	// Before Linux 5.8 only an open file shows it; directories cannot be opened for writing
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return &os.PathError{Op: "access", Path: p, Err: unix.EACCES}
	}
	f, err := os.OpenFile(p, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	return f.Close()
}

// Check verifies that the process can act as other users: it must run as root, or
// with the CAP_SETUID and CAP_SETGID capabilities
func Check() error {
	nobody := &User{Name: "nobody", UID: 65534, GID: 65534, Groups: []int{65534}}
	if err := nobody.Run(func() {}); err != nil {
		return fmt.Errorf("%w (run as root, or with CAP_SETUID and CAP_SETGID)", err)
	}
	return nil
}
