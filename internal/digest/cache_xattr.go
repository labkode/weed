//go:build linux || darwin

package digest

import (
	"os"

	"golang.org/x/sys/unix"
)

const xattrPrefix = "user.weed.digest."

func readCache(f *os.File, alg string, fi os.FileInfo) ([]byte, bool) {
	buf := make([]byte, 256)
	n, err := unix.Fgetxattr(int(f.Fd()), xattrPrefix+alg, buf)
	if err != nil {
		return nil, false
	}
	return parseCacheValue(string(buf[:n]), fi)
}

func writeCache(f *os.File, sums Set, fi os.FileInfo) {
	for alg, sum := range sums {
		unix.Fsetxattr(int(f.Fd()), xattrPrefix+alg, []byte(cacheValue(sum, fi)), 0)
	}
}
