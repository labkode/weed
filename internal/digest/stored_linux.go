package digest

import "os"

const xattrPrefix = "user.weed.digest."

func readStored(f File, alg string, fi os.FileInfo) ([]byte, bool) {
	buf := make([]byte, 256)
	n, err := f.Getxattr(xattrPrefix+alg, buf)
	if err != nil {
		return nil, false
	}
	return parseStoredValue(string(buf[:n]), fi)
}

func writeStored(f File, sums Set, fi os.FileInfo) {
	for alg, sum := range sums {
		f.Setxattr(xattrPrefix+alg, []byte(storedValue(sum, fi)))
	}
}
