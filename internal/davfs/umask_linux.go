package davfs

import (
	"os"
	"syscall"
)

// umask is read once at startup (before any goroutine creates files) so that uploaded
// files get the same permissions os.OpenFile(..., 0666) would have given them
var umask = func() os.FileMode {
	m := syscall.Umask(0)
	syscall.Umask(m)
	return os.FileMode(m)
}()
