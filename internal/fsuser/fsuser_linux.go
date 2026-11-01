//go:build linux

package fsuser

import (
	"os"

	"golang.org/x/sys/unix"
)

// WritableDir reports whether the process may write the open directory d, by the
// kernel's rules (ACLs included). Before Linux 5.8, which has no faccessat2, it says
// no: only an open file shows it, and directories cannot be opened for writing.
func WritableDir(d *os.File) error {
	err := unix.Faccessat2(int(d.Fd()), "", unix.W_OK, unix.AT_EACCESS|unix.AT_EMPTY_PATH)
	if err == unix.ENOSYS {
		err = unix.EACCES
	}
	if err != nil {
		return &os.PathError{Op: "access", Path: d.Name(), Err: err}
	}
	return nil
}
