package limits

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labkode/weed/internal/fsuser"
)

const chunk = 32 << 10

// transfer pays for chunks with m for d, and returns how many bytes it paid for
func transfer(m *Meter, dir Direction, d time.Duration) int64 {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	var n int64
	for m.Pay(ctx, dir, chunk) == nil {
		n += chunk
	}
	return n
}

func acct(name string) *fsuser.User {
	return &fsuser.User{Name: name, UID: 7000, GID: 7000, Groups: []int{7000}}
}

// within reports whether got is within a fraction tol of want
func within(got, want float64, tol float64) bool { return got > want*(1-tol) && got < want*(1+tol) }

func TestAccountRate(t *testing.T) {
	s := NewShaper(&Limits{Default: Account{EgressRate: 20e6}})
	m := s.Meter(acct("alice"))
	defer m.Close()
	const d = 400 * time.Millisecond
	if rate := float64(transfer(m, Egress, d)) / d.Seconds(); !within(rate, 20e6, 0.2) {
		t.Errorf("egress at %.3g B/s, want 20e6", rate)
	}
	// The other direction has no limit
	start := time.Now()
	for range 1000 {
		m.Pay(context.Background(), Ingress, chunk)
	}
	if e := time.Since(start); e > 100*time.Millisecond {
		t.Errorf("ingress, which has no limit, took %v", e)
	}
}

// Accounts that want more than the total share it by weight; one that is capped
// below its share leaves the rest to the others; one alone gets it all
func TestTotalSharedByWeight(t *testing.T) {
	alice, bob, carol := acct("alice"), acct("bob"), acct("carol")
	l := &Limits{IngressRate: 40e6, Default: Account{Weight: DefaultWeight}}
	l.Rules = []Rule{{User: "bob", Weight: 300}, {User: "carol", IngressRate: "4MB/s"}}
	for i := range l.Rules {
		if err := l.Rules[i].resolve(); err != nil {
			t.Fatal(err)
		}
	}
	s := NewShaper(l)
	const d = 600 * time.Millisecond
	run := func(users ...*fsuser.User) []float64 {
		rates := make([]float64, len(users))
		var wg sync.WaitGroup
		for i, u := range users {
			m := s.Meter(u)
			defer m.Close()
			// Two transfers per account: the account, not the transfer, gets the share
			for range 2 {
				wg.Go(func() {
					n := transfer(m, Ingress, d)
					atomicAddFloat(&rates[i], float64(n)/d.Seconds())
				})
			}
		}
		wg.Wait()
		return rates
	}

	r := run(alice, bob)
	if !within(r[0]+r[1], 40e6, 0.2) || !within(r[1]/r[0], 3, 0.3) {
		t.Errorf("alice %.3g B/s, bob (3 times the weight) %.3g B/s: want 10e6 and 30e6", r[0], r[1])
	}
	r = run(alice, carol)
	if !within(r[1], 4e6, 0.25) || !within(r[0], 36e6, 0.2) {
		t.Errorf("alice %.3g B/s, carol (capped at 4MB/s) %.3g B/s: want 36e6 and 4e6", r[0], r[1])
	}
	r = run(alice)
	if !within(r[0], 40e6, 0.2) {
		t.Errorf("alice alone %.3g B/s, want 40e6", r[0])
	}
}

var floatMu sync.Mutex

func atomicAddFloat(f *float64, v float64) {
	floatMu.Lock()
	*f += v
	floatMu.Unlock()
}

func TestSetLimits(t *testing.T) {
	s := NewShaper(&Limits{EgressRate: 1000})
	m := s.Meter(acct("alice"))
	m2 := s.Meter(acct("alice"))
	defer m2.Close()
	m.Pay(context.Background(), Egress, 10000) // owes 10 s
	done := make(chan error)
	go func() { done <- m.Pay(context.Background(), Egress, 1) }()
	time.Sleep(50 * time.Millisecond)
	if u := s.Usage(); len(u) != 1 || u[0].Account != "alice" || u[0].Held != [2]int{1, 0} {
		t.Errorf("Usage: %+v", u)
	}
	// Lifting the total lets what waits for it through
	s.SetLimits(&Limits{})
	select {
	case err := <-done:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(time.Second):
		t.Fatal("a payment still waits for a total that was lifted")
	}

	// Waiting ends with the context, and leaves the queue
	s.SetLimits(&Limits{EgressRate: 1000})
	m.Pay(context.Background(), Egress, 10000)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := m.Pay(ctx, Egress, 1); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Pay = %v, want the context's error", err)
	}
	if n := s.links[Egress].queue.Len(); n != 0 {
		t.Errorf("%d payments left in the queue", n)
	}
	if u := s.Usage(); u[0].Held != [2]int{} {
		t.Errorf("Usage after the context ended: %+v", u)
	}
	m.Close()
	if u := s.Usage(); len(u) != 1 {
		t.Errorf("Usage with one meter left: %+v", u)
	}
	m2.Close()
	if u := s.Usage(); len(u) != 0 {
		t.Errorf("Usage with no meter left: %+v", u)
	}
	m2 = s.Meter(acct("bob"))
}

func TestLimited(t *testing.T) {
	l := &Limits{Rules: []Rule{{User: "bob", EgressRate: "1MB/s"}}}
	l.Rules[0].resolve()
	s := NewShaper(l)
	if s.Limited(acct("alice")) || !s.Limited(acct("bob")) {
		t.Error("only bob has a rate")
	}
	s.SetLimits(&Limits{IngressRate: 1e6})
	if !s.Limited(acct("alice")) {
		t.Error("a total rate applies to every account")
	}
}

func TestRebase(t *testing.T) {
	s := NewShaper(&Limits{EgressRate: 1e9})
	m := s.Meter(acct("alice"))
	defer m.Close()
	s.links[Egress].vtime = 1<<40 + 10
	m.a.finish[Egress] = 1<<40 + 20
	s.dispatch(Egress)
	if v, f := s.links[Egress].vtime, m.a.finish[Egress]; v != 0 || f != 10 {
		t.Errorf("after rebase: vtime %g, finish %g; want 0, 10", v, f)
	}
}

func TestMeteredBodyAndWriter(t *testing.T) {
	s := NewShaper(&Limits{Default: Account{EgressRate: 1e6, IngressRate: 1e6}})
	m := s.Meter(acct("alice"))
	defer m.Close()
	start := time.Now()
	b := m.Body(context.Background(), io.NopCloser(strings.NewReader(strings.Repeat("x", 120e3))))
	if n, err := io.Copy(io.Discard, b); n != 120e3 || err != nil {
		t.Fatal(n, err)
	}
	// 120 kB at 1 MB/s, of which a burst of 20 kB
	if e := time.Since(start); e < 80*time.Millisecond || e > 300*time.Millisecond {
		t.Errorf("reading 120 kB at 1 MB/s took %v", e)
	}

	rec := httptest.NewRecorder()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	w := m.ResponseWriter(ctx, rec)
	if n, err := w.Write(make([]byte, 100e3)); n != 100e3 || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Write that waits beyond the context: %d, %v", n, err)
	}
	if w.(interface{ Unwrap() http.ResponseWriter }).Unwrap() != rec {
		t.Error("Unwrap")
	}
}

// slowPayer takes a while for each payment, as messages to another process do
type slowPayer struct {
	paid atomic.Int64
	busy atomic.Int32 // payments in progress
	max  atomic.Int32
}

func (p *slowPayer) Pay(ctx context.Context, d Direction, n int) error {
	if b := p.busy.Add(1); b > p.max.Load() {
		p.max.Store(b)
	}
	time.Sleep(time.Millisecond)
	p.paid.Add(int64(n))
	p.busy.Add(-1)
	return nil
}

func TestReader(t *testing.T) {
	var p slowPayer
	const size = 10<<20 + 1000 // what is left at the end is paid for too
	r := Reader(context.Background(), io.LimitReader(zeros{}, size), &p, Ingress)
	if n, err := io.CopyBuffer(io.Discard, r, make([]byte, 16<<10)); n != size || err != nil {
		t.Fatal(n, err)
	}
	time.Sleep(10 * time.Millisecond) // for the last payment
	if paid := p.paid.Load(); paid != size {
		t.Errorf("paid for %d of %d bytes", paid, size)
	}
	if m := p.max.Load(); m != 1 {
		t.Errorf("%d payments at once, want 1", m)
	}

	// A read is of a quantum at most, so that a transfer is never paid for in full
	// only at its end, without waiting
	r = Reader(context.Background(), io.LimitReader(zeros{}, size), new(slowPayer), Ingress)
	if n, _ := r.Read(make([]byte, size)); n != quantum {
		t.Errorf("read %d bytes at once, want %d", n, quantum)
	}
}

type zeros struct{}

func (zeros) Read(b []byte) (int, error) {
	clear(b)
	return len(b), nil
}
