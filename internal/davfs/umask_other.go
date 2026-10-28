//go:build !unix

package davfs

import "os"

var umask os.FileMode = 0
