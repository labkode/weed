package digest

import (
	"crypto/rand"
	"strings"
	"testing"
)

// Raw speed of each algorithm, and of the combinations PUT and TPC compute (adler32
// is always computed, plus what the client asks for)
func BenchmarkHasher(b *testing.B) {
	buf := make([]byte, 1<<20)
	rand.Read(buf)
	for _, algs := range [][]string{
		{Adler}, {CRC32C}, {MD5}, {SHA}, {SHA256}, {SHA512},
		{Adler, MD5}, {Adler, SHA256}, {Adler, CRC32C, MD5, SHA256},
	} {
		b.Run(strings.Join(algs, "+"), func(b *testing.B) {
			h := NewHasher(algs...)
			b.SetBytes(int64(len(buf)))
			for b.Loop() {
				h.Write(buf)
			}
		})
	}
}
