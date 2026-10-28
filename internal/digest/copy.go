package digest

import (
	"io"
	"sync"
)

// chunkSize is the unit Copy reads, writes and hashes
const chunkSize = 1 << 20

var chunks = sync.Pool{New: func() any { b := make([]byte, chunkSize); return &b }}

// Copy copies src to dst and feeds the data to h, like io.Copy to
// io.MultiWriter(dst, h), but it reads the next chunk while the previous one is
// being written and hashed, and writes and hashes at the same time, so that
// checksums cost little more than the slowest of reading, writing and hashing.
// It returns the number of bytes written, and read and write errors separately.
func Copy(dst io.Writer, src io.Reader, h *Hasher) (written int64, readErr, writeErr error) {
	bufs := [2]*[]byte{chunks.Get().(*[]byte), chunks.Get().(*[]byte)}
	var pending chan error // the chunk being written and hashed, if any
	var pendingLen int
	wait := func() error {
		if pending == nil {
			return nil
		}
		err := <-pending
		pending = nil
		if err == nil {
			written += int64(pendingLen)
		}
		return err
	}
	// Only once nothing uses the buffers can they be reused
	defer func() {
		wait()
		chunks.Put(bufs[0])
		chunks.Put(bufs[1])
	}()

	for i := 0; ; i ^= 1 {
		n, rerr := fill(src, *bufs[i])
		if werr := wait(); werr != nil {
			return written, nil, werr
		}
		if n > 0 {
			pending, pendingLen = make(chan error, 1), n
			go func(p []byte, done chan<- error) { done <- writeAndHash(dst, h, p) }((*bufs[i])[:n], pending)
		}
		if rerr != nil {
			werr := wait()
			if rerr == io.EOF {
				rerr = nil
			}
			return written, rerr, werr
		}
	}
}

// fill reads into buf until it is full or src fails. Unlike io.ReadFull, it returns
// src's error as is: a truncated HTTP body fails with io.ErrUnexpectedEOF, which
// io.ReadFull also returns for a short read before a normal end.
func fill(src io.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		k, err := src.Read(buf[n:])
		n += k
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func writeAndHash(dst io.Writer, h *Hasher, p []byte) error {
	done := make(chan struct{})
	go func() {
		h.Write(p)
		close(done)
	}()
	n, err := dst.Write(p)
	<-done
	if err == nil && n < len(p) {
		err = io.ErrShortWrite
	}
	return err
}
