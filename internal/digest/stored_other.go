//go:build !(linux || darwin)

package digest

import "os"

// Extended attributes are not available: files have no stored digests

func readStored(f *os.File, alg string, fi os.FileInfo) ([]byte, bool) { return nil, false }

func writeStored(f *os.File, sums Set, fi os.FileInfo) {}
