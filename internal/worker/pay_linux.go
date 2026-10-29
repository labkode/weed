package worker

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"sync"

	"github.com/labkode/weed/internal/limits"
)

// The front process does not relay the connections of third-party copies, which
// workers make: a worker pays for the bytes they move by asking the front process,
// over a socket of its own (file descriptor 4), which answers once the account's
// rates and the total ones allow more (see limits.Shaper).
//
// A request is payRequestSize bytes, little-endian: an ID (uint32), the direction (a
// byte: limits.Direction) and the number of bytes (uint32). The answer is the ID.
const payRequestSize = 9

// maxPaying bounds the requests of a worker that the front process pays at once
const maxPaying = 1024

// servePayments pays for what the third-party copies of wk move, with a meter of its
// account, until the worker exits
func (p *Pool) servePayments(wk *worker, conn *net.UnixConn) {
	defer conn.Close()
	m := p.opts.Shaper.Meter(&wk.user)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sem := make(chan struct{}, maxPaying)
	buf := make([]byte, payRequestSize+1)
	for {
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return // the worker has exited
		}
		d := limits.Direction(buf[4])
		size := binary.LittleEndian.Uint32(buf[5:])
		if n != payRequestSize || (d != limits.Egress && d != limits.Ingress) || size == 0 {
			slog.Error("killing a worker that sent an invalid payment", "worker", wk)
			wk.cmd.Process.Kill()
			return
		}
		id := [4]byte(buf[:4])
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			if m.Pay(ctx, d, int(size)) == nil {
				conn.Write(id[:])
			}
		}()
	}
}

// payer pays for the bytes of a worker's third-party copies (see servePayments)
type payer struct {
	conn *net.UnixConn

	mu      sync.Mutex
	next    uint32
	waiting map[uint32]chan struct{}
	err     error // once the front process no longer answers
}

func newPayer(conn *net.UnixConn) *payer {
	p := &payer{conn: conn, waiting: make(map[uint32]chan struct{})}
	go p.receive()
	return p
}

// Pay asks the front process to pay for n bytes moved in direction d, and returns
// once it has
func (p *payer) Pay(ctx context.Context, d limits.Direction, n int) error {
	paid := make(chan struct{})
	p.mu.Lock()
	if p.err != nil {
		p.mu.Unlock()
		return p.err
	}
	id := p.next
	p.next++
	p.waiting[id] = paid
	p.mu.Unlock()

	var msg [payRequestSize]byte
	binary.LittleEndian.PutUint32(msg[:], id)
	msg[4] = byte(d)
	binary.LittleEndian.PutUint32(msg[5:], uint32(min(n, 1<<30)))
	if _, err := p.conn.Write(msg[:]); err != nil {
		p.forget(id)
		return err
	}
	select {
	case <-paid:
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.err
	case <-ctx.Done():
		p.forget(id)
		return ctx.Err()
	}
}

func (p *payer) forget(id uint32) {
	p.mu.Lock()
	delete(p.waiting, id)
	p.mu.Unlock()
}

// receive hands the answers of the front process to the payments that wait for them
func (p *payer) receive() {
	buf := make([]byte, 8)
	for {
		n, err := p.conn.Read(buf)
		if err != nil || n != 4 {
			p.mu.Lock()
			p.err = errors.New("the front process no longer answers payments for third-party copies")
			for id, paid := range p.waiting {
				close(paid)
				delete(p.waiting, id)
			}
			p.mu.Unlock()
			return
		}
		id := binary.LittleEndian.Uint32(buf)
		p.mu.Lock()
		paid := p.waiting[id]
		delete(p.waiting, id)
		p.mu.Unlock()
		if paid != nil {
			close(paid)
		}
	}
}
