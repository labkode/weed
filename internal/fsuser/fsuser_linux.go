//go:build linux

package fsuser

import (
	"os"

	"golang.org/x/sys/unix"
)

// Writable reports whether the process may write the file or directory p, by the
// kernel's rules (ACLs included)
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
