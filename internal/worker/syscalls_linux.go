package worker

import (
	"errors"

	"golang.org/x/sys/unix"
)

// CheckSyscalls says whether a seccomp filter that weed runs under refuses system
// calls that it needs, which then fail deep in weed with ENOSYS ("function not
// implemented"): openat2(2), with which workers open files, and with cgroups,
// clone3(2), which starts each worker in its cgroup. systemd's RestrictSUIDSGID= and
// RestrictNamespaces= refuse them, which security baselines often add to units.
func CheckSyscalls(cgroups bool) error {
	how := unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS}
	if fd, err := unix.Openat2(unix.AT_FDCWD, "/", &how); err == nil {
		unix.Close(fd)
	} else if errors.Is(err, unix.ENOSYS) {
		return errors.New("a seccomp filter refuses openat2(2), with which weed's workers open files: systemd's RestrictSUIDSGID= does, or a SystemCallFilter= of weed's unit; remove it (systemctl cat weed shows the unit and its drop-ins)")
	}
	if cgroups {
		// Without arguments, clone3 fails with EINVAL, and starts nothing
		if _, _, errno := unix.Syscall(unix.SYS_CLONE3, 0, 0, 0); errno == unix.ENOSYS {
			return errors.New("a seccomp filter refuses clone3(2), which starts each worker in its cgroup (unix_users.cgroups): systemd's RestrictNamespaces= does, or a SystemCallFilter= of weed's unit; remove it (systemctl cat weed shows the unit and its drop-ins)")
		}
	}
	return nil
}
