package limits

import (
	"container/heap"
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/labkode/weed/internal/fsuser"
	"github.com/labkode/weed/internal/metrics"
)

// Direction is that of bytes, as seen from weed
type Direction int

const (
	// Egress are the bytes weed sends: downloads, and third-party copies it pushes
	Egress Direction = iota
	// Ingress are the bytes weed receives: uploads, and third-party copies it pulls
	Ingress
)

func (d Direction) String() string {
	if d == Egress {
		return "egress"
	}
	return "ingress"
}

// burst is how long, at its rate, a limit that has been idle lets bytes through
// before it delays any
const burst = 20 * time.Millisecond

// Shaper paces the bytes that weed sends and receives: those of each account at most
// at the account's rates, and all of them at most at weed's total rates. When a total
// rate is what holds transfers back, the accounts that want more than they get share
// it in proportion to their weights; when it is not, each gets what it asks for.
//
// Transfers pay for bytes once they have moved them (Meter.Pay), and wait there
// until their account and the total allow more: a rate is kept on average, with a
// lead of what each transfer moves at a time.
type Shaper struct {
	mu       sync.Mutex
	limits   *Limits
	links    [2]link
	accounts map[string]*account
}

// link is a total rate, which the accounts share by weight: start-time fair queueing,
// in which each payment gets a tag, the virtual time at which it starts when every
// account that waits gets its share. Payments are let through in the order of their
// tags, as fast as the rate allows.
type link struct {
	rate  float64   // bytes per second (0: no limit)
	free  time.Time // when the bytes let through so far have been sent, at rate
	vtime float64   // the tag of the payment let through last
	queue queue     // payments waiting, by tag
	timer *time.Timer
	seq   uint64 // orders payments with the same tag
}

// account is the state of the rates of an account with transfers in progress
type account struct {
	user   fsuser.User
	refs   int // Meters
	limits Account
	free   [2]time.Time // as link.free, at the account's rates
	finish [2]float64   // the tag of its last payment plus its share of the link
	held   [2]int       // payments held back now
}

// NewShaper returns a shaper with limits l
func NewShaper(l *Limits) *Shaper {
	s := &Shaper{limits: l, accounts: make(map[string]*account)}
	for d := range s.links {
		s.links[d].timer = time.AfterFunc(time.Hour, func() { s.dispatch(Direction(d)) })
		s.links[d].timer.Stop()
	}
	s.setTotals(l)
	return s
}

// SetLimits replaces the limits, those of transfers in progress included
func (s *Shaper) SetLimits(l *Limits) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.limits = l
	now := time.Now()
	for _, a := range s.accounts {
		prev := a.limits
		a.limits = l.For(&a.user)
		for _, d := range []Direction{Egress, Ingress} {
			if a.limits.rate(d) != prev.rate(d) {
				a.free[d] = now // what was owed at the previous rate is forgiven
			}
		}
	}
	s.setTotals(l)
}

// setTotals applies the total rates of l; payments that wait for a total that is
// lifted are let through
func (s *Shaper) setTotals(l *Limits) {
	now := time.Now()
	for d, rate := range [2]int64{Egress: l.EgressRate, Ingress: l.IngressRate} {
		k := &s.links[d]
		if float64(rate) == k.rate {
			continue
		}
		k.rate, k.free = float64(rate), now
		if rate == 0 {
			for k.queue.Len() > 0 {
				close(heap.Pop(&k.queue).(*payment).ready)
			}
			k.timer.Stop()
		} else if k.queue.Len() > 0 {
			k.timer.Reset(0)
		}
	}
}

// Limited reports whether any rate applies to u's transfers: if not, they need not
// pay
func (s *Shaper) Limited(u *fsuser.User) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.links[Egress].rate > 0 || s.links[Ingress].rate > 0 {
		return true
	}
	a := s.limits.For(u)
	return a.EgressRate > 0 || a.IngressRate > 0
}

// Meter returns what the transfers of account u pay with. Close it once they are done.
func (s *Shaper) Meter(u *fsuser.User) *Meter {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.accounts[u.Name]
	if a == nil {
		a = &account{}
		s.accounts[u.Name] = a
	}
	a.user = *u
	a.limits = s.limits.For(u)
	a.refs++
	return &Meter{s: s, a: a}
}

// A Meter is what the transfers of an account pay with
type Meter struct {
	s *Shaper
	a *account
}

// Close releases the meter
func (m *Meter) Close() {
	m.s.mu.Lock()
	defer m.s.mu.Unlock()
	if m.a.refs--; m.a.refs == 0 {
		delete(m.s.accounts, m.a.user.Name)
	}
}

// Pay pays for n bytes moved in direction d: it returns once the account's rate and
// the total rate allow more, or when ctx is done
func (m *Meter) Pay(ctx context.Context, d Direction, n int) error {
	if n <= 0 {
		return nil
	}
	s, a := m.s, m.a
	s.mu.Lock()
	var wait time.Duration
	start := time.Now()
	if rate := a.limits.rate(d); rate > 0 {
		a.free[d] = later(a.free[d], start.Add(-burst)).Add(seconds(float64(n) / float64(rate)))
		if wait = a.free[d].Sub(start); wait > 0 {
			a.held[d]++
		}
	}
	s.mu.Unlock()
	if wait > 0 {
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-ctx.Done():
		}
		t.Stop()
		delay.Add(int64(time.Since(start)), d.String(), "account")
		s.mu.Lock()
		a.held[d]--
		s.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return err
		}
	}

	s.mu.Lock()
	k := &s.links[d]
	if k.rate == 0 {
		s.mu.Unlock()
		return nil
	}
	tag := max(k.vtime, a.finish[d])
	a.finish[d] = tag + float64(n)/float64(a.limits.Weight)
	now := time.Now()
	if k.queue.Len() == 0 && !k.free.After(now) {
		k.charge(tag, n, now)
		s.mu.Unlock()
		return nil
	}
	p := &payment{n: n, tag: tag, seq: k.seq, ready: make(chan struct{})}
	k.seq++
	heap.Push(&k.queue, p)
	if k.queue.Len() == 1 {
		k.timer.Reset(k.free.Sub(now))
	}
	a.held[d]++
	s.mu.Unlock()

	var err error
	select {
	case <-p.ready:
	case <-ctx.Done():
		err = ctx.Err()
	}
	s.mu.Lock()
	if p.index >= 0 {
		heap.Remove(&k.queue, p.index)
	}
	a.held[d]--
	s.mu.Unlock()
	delay.Add(int64(time.Since(now)), d.String(), "total")
	return err
}

// dispatch lets through the payments that wait for link d, as the rate allows
func (s *Shaper) dispatch(d Direction) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := &s.links[d]
	now := time.Now()
	for k.queue.Len() > 0 && !k.free.After(now) {
		p := heap.Pop(&k.queue).(*payment)
		k.charge(p.tag, p.n, now)
		close(p.ready)
	}
	if k.queue.Len() > 0 {
		k.timer.Reset(k.free.Sub(now))
	}
	if k.vtime > 1<<40 {
		s.rebase(d)
	}
}

// charge lets n bytes with tag through the link
func (k *link) charge(tag float64, n int, now time.Time) {
	k.vtime = tag
	k.free = later(k.free, now.Add(-burst)).Add(seconds(float64(n) / k.rate))
}

// rebase subtracts the virtual time of link d from every tag, which keeps their
// order, before they grow so large that their differences are lost
func (s *Shaper) rebase(d Direction) {
	k := &s.links[d]
	v := k.vtime
	k.vtime = 0
	for _, p := range k.queue {
		p.tag -= v
	}
	for _, a := range s.accounts {
		a.finish[d] = max(a.finish[d]-v, 0)
	}
}

// Usage is what an account with transfers in progress is allowed, and how many of
// them its rates or the total ones hold back now, by direction
type Usage struct {
	Account string
	Limits  Account
	Held    [2]int
}

// Usage describes the accounts that have transfers in progress, by name
func (s *Shaper) Usage() []Usage {
	s.mu.Lock()
	defer s.mu.Unlock()
	var u []Usage
	for name, a := range s.accounts {
		u = append(u, Usage{Account: name, Limits: a.limits, Held: a.held})
	}
	slices.SortFunc(u, func(a, b Usage) int { return strings.Compare(a.Account, b.Account) })
	return u
}

// payment is one that waits for a link
type payment struct {
	n     int
	tag   float64
	seq   uint64
	index int // in the queue; -1 once let through or removed
	ready chan struct{}
}

type queue []*payment

func (q queue) Len() int { return len(q) }
func (q queue) Less(i, j int) bool {
	return q[i].tag < q[j].tag || q[i].tag == q[j].tag && q[i].seq < q[j].seq
}
func (q queue) Swap(i, j int) {
	q[i], q[j] = q[j], q[i]
	q[i].index, q[j].index = i, j
}
func (q *queue) Push(x any) {
	p := x.(*payment)
	p.index = len(*q)
	*q = append(*q, p)
}
func (q *queue) Pop() any {
	old := *q
	p := old[len(old)-1]
	old[len(old)-1] = nil
	*q = old[:len(old)-1]
	p.index = -1
	return p
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func seconds(s float64) time.Duration { return time.Duration(s * float64(time.Second)) }

// delay is how long transfers were held back, by direction and by the limit that
// held them: the account's own rates, or the total ones
var delay = metrics.NewCounter("weed_network_delay_seconds_total",
	"How long transfers waited because of network rate limits, by direction (egress, ingress) and limit: account (the account's own rate) or total (weed's total rate, which accounts share by weight). Transfers in parallel each count.",
	"direction", "limit").InSeconds()
