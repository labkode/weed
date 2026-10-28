//go:build !(linux || darwin)

package digest

import "os"

// Extended attributes are not available; digests are always computed

func readCache(f *os.File, alg string, fi os.FileInfo) ([]byte, bool) { return nil, false }

func writeCache(f *os.File, sums Set, fi os.FileInfo) {}
