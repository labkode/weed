package digest

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	mrand "math/rand/v2"
	"testing"
	"testing/iotest"
)

// choppy returns at most a random number of bytes per Read
type choppy struct{ r io.Reader }

func (c choppy) Read(p []byte) (int, error) {
	return c.r.Read(p[:min(len(p), 1+mrand.IntN(3*chunkSize/2))])
}

type failWriter struct {
	after int64 // bytes accepted before failing
	n     int64
	short bool // fail with a short write and no error
}

func (f *failWriter) Write(p []byte) (int, error) {
	if f.n+int64(len(p)) <= f.after {
		f.n += int64(len(p))
		return len(p), nil
	}
	if f.short {
		return 1, nil
	}
	return 0, errors.New("disk full")
}

func TestCopy(t *testing.T) {
	data := make([]byte, 5*chunkSize+12345)
	rand.Read(data)
	readers := map[string]func([]byte) io.Reader{
		"whole reads":    func(b []byte) io.Reader { return bytes.NewReader(b) },
		"random reads":   func(b []byte) io.Reader { return choppy{bytes.NewReader(b)} },
		"one-byte reads": func(b []byte) io.Reader { return iotest.OneByteReader(bytes.NewReader(b)) },
	}
	for _, size := range []int{0, 1, 3000, chunkSize - 1, chunkSize, chunkSize + 1, len(data)} {
		for name, reader := range readers {
			if name == "one-byte reads" && size > 3000 {
				continue // slow, and nothing new
			}
			var dst bytes.Buffer
			h := NewHasher(Adler, MD5, SHA256)
			n, rerr, werr := Copy(&dst, reader(data[:size]), h)
			if rerr != nil || werr != nil || n != int64(size) || !bytes.Equal(dst.Bytes(), data[:size]) {
				t.Fatalf("%s, %d bytes: n=%d %v %v, copied correctly: %t", name, size, n, rerr, werr, bytes.Equal(dst.Bytes(), data[:size]))
			}
			ref := NewHasher(Adler, MD5, SHA256)
			ref.Write(data[:size])
			for alg, sum := range ref.Sums() {
				if !bytes.Equal(h.Sums()[alg], sum) {
					t.Fatalf("%s, %d bytes: %s differs", name, size, alg)
				}
			}
		}
	}

	// Read errors and write errors are told apart, and n counts what was written.
	// A body cut short (io.ErrUnexpectedEOF from net/http) is an error, not the end.
	for _, readErr := range []error{errors.New("connection reset"), io.ErrUnexpectedEOF} {
		for _, at := range []int{5, 2*chunkSize + 5} {
			src := io.MultiReader(bytes.NewReader(data[:at]), iotest.ErrReader(readErr))
			var dst bytes.Buffer
			n, rerr, werr := Copy(&dst, src, NewHasher(Adler))
			if rerr != readErr || werr != nil || n != int64(at) || !bytes.Equal(dst.Bytes(), data[:n]) {
				t.Fatalf("%v after %d bytes: n=%d %v %v", readErr, at, n, rerr, werr)
			}
		}
	}
	var n int64
	var rerr, werr error
	for _, short := range []bool{false, true} {
		fw := &failWriter{after: 2 * chunkSize, short: short}
		n, rerr, werr = Copy(fw, bytes.NewReader(data), NewHasher(Adler))
		if werr == nil || rerr != nil || n != 2*chunkSize {
			t.Fatalf("write error (short %t): n=%d %v %v", short, n, rerr, werr)
		}
	}
}
