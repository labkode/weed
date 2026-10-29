package limits

import (
	"context"
	"io"
	"net/http"
)

// A Payer pays for the bytes that transfers move, and returns once the limits allow
// more (Meter, and what workers pay their third-party copies with)
type Payer interface {
	Pay(ctx context.Context, d Direction, n int) error
}

// Body pays for what is read from body, as received (an upload)
func (m *Meter) Body(ctx context.Context, body io.ReadCloser) io.ReadCloser {
	return &meteredBody{ReadCloser: body, ctx: ctx, m: m}
}

type meteredBody struct {
	io.ReadCloser
	ctx context.Context
	m   *Meter
}

func (b *meteredBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if perr := b.m.Pay(b.ctx, Ingress, n); perr != nil && err == nil {
		err = perr
	}
	return n, err
}

// ResponseWriter pays for the body written to w, as sent (a download)
func (m *Meter) ResponseWriter(ctx context.Context, w http.ResponseWriter) http.ResponseWriter {
	return &meteredWriter{ResponseWriter: w, ctx: ctx, m: m}
}

type meteredWriter struct {
	http.ResponseWriter
	ctx context.Context
	m   *Meter
}

func (w *meteredWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if perr := w.m.Pay(w.ctx, Egress, n); perr != nil && err == nil {
		err = perr
	}
	return n, err
}

// Unwrap gives http.ResponseController the ResponseWriter (to flush, hijack, ...)
func (w *meteredWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// quantum is how many bytes a reader of Reader moves before it pays
const quantum = 256 << 10

// Reader pays with p for what is read from r, in direction d, for a payer whose
// payments take time even when no limit holds them back (they are messages to
// another process): each read is of quantum bytes at most, a payment of quantum bytes
// is made while the next ones are read, and reading waits for it only once those are
// read too. What is left at the end of r is paid for without waiting: the reader is
// ahead of the rates by two quanta at most.
func Reader(ctx context.Context, r io.Reader, p Payer, d Direction) io.Reader {
	return &pacedReader{r: r, ctx: ctx, p: p, d: d}
}

type pacedReader struct {
	r      io.Reader
	ctx    context.Context
	p      Payer
	d      Direction
	owed   int
	paying chan error // the payment in progress, if any
}

func (r *pacedReader) Read(b []byte) (int, error) {
	n, err := r.r.Read(b[:min(len(b), quantum)])
	if r.owed += n; r.owed >= quantum || err != nil && r.owed > 0 {
		if r.paying != nil {
			if perr := <-r.paying; perr != nil && err == nil {
				return n, perr
			}
		}
		owed := r.owed
		r.owed = 0
		paying := make(chan error, 1)
		r.paying = paying
		go func() { paying <- r.p.Pay(r.ctx, r.d, owed) }()
	}
	return n, err
}
