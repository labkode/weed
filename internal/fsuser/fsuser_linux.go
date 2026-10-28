//go:build linux

package fsuser

import (
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"

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

// overridingCapabilities bypass file permission checks. The kernel drops them from a
// thread whose filesystem UID changes from 0 to another, but not when it changes
// between two other UIDs, nor with the no_setuid_fixup securebit.
var overridingCapabilities = []struct {
	bit  uint
	name string
}{
	{unix.CAP_CHOWN, "CAP_CHOWN"},
	{unix.CAP_DAC_OVERRIDE, "CAP_DAC_OVERRIDE"},
	{unix.CAP_DAC_READ_SEARCH, "CAP_DAC_READ_SEARCH"},
	{unix.CAP_FOWNER, "CAP_FOWNER"},
	{unix.CAP_FSETID, "CAP_FSETID"},
	{unix.CAP_LINUX_IMMUTABLE, "CAP_LINUX_IMMUTABLE"},
	{unix.CAP_MAC_OVERRIDE, "CAP_MAC_OVERRIDE"},
	{unix.CAP_MKNOD, "CAP_MKNOD"},
}

// effectiveCapabilities returns the calling thread's effective capability set
func effectiveCapabilities() (uint64, error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3} // Pid 0: this thread
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return 0, fmt.Errorf("capget: %w", err)
	}
	return uint64(data[0].Effective) | uint64(data[1].Effective)<<32, nil
}

// Check verifies that the process can act as other users, which needs root or the
// CAP_SETUID and CAP_SETGID capabilities, and that acting as a user leaves it no
// capability that would bypass the user's permissions
func Check() error {
	nobody := &User{Name: "nobody", UID: 65534, GID: 65534, Groups: []int{65534}}
	var caps uint64
	var capErr error
	if err := nobody.Run(func() { caps, capErr = effectiveCapabilities() }); err != nil {
		return fmt.Errorf("%w (run as root, or with CAP_SETUID and CAP_SETGID)", err)
	}
	if capErr != nil {
		return capErr
	}
	var kept []string
	for _, c := range overridingCapabilities {
		if caps&(1<<c.bit) != 0 {
			kept = append(kept, c.name)
		}
	}
	if len(kept) > 0 {
		return fmt.Errorf("acting as a user keeps %s, which would bypass the user's file permissions: run as root without the no_setuid_fixup securebit, or as another user with only CAP_SETUID and CAP_SETGID",
			strings.Join(kept, ", "))
	}
	return nil
}
