package davfs

import "context"

// Gate bounds the calls to the storage in progress at once, in a process: each takes
// a slot, and a call beyond waits for one, as a goroutine, without a thread. A call
// to the storage holds a thread of the process in the kernel until it returns; under
// load, when calls last longer than Go's scheduler waits for them (20µs), Go makes
// new threads for the goroutines that are ready. Without a bound, a worker serving
// thousands of requests at once ends with a thread each, and one whose storage does
// not answer piles them up until it cannot make more (cgroup pids.max, or Go's 10000),
// and dies. A slot is held for one call, or a few that follow each other (a stat and
// an open, a batch of a listing), never while waiting for a client.
type Gate struct {
	slots chan struct{}
}

// NewGate returns a gate of n slots; nil, which bounds nothing, if n < 1
func NewGate(n int) *Gate {
	if n < 1 {
		return nil
	}
	return &Gate{slots: make(chan struct{}, n)}
}

// enter takes a slot, waiting until one is free or ctx is done. With a nil ctx it
// waits however long it takes: for the calls that end what was started (close, the
// fsync and rename that commit an upload, the removal of an aborted one), which must
// happen even once the client has gone.
func (g *Gate) enter(ctx context.Context) error {
	if g == nil {
		return nil
	}
	select {
	case g.slots <- struct{}{}:
		return nil
	default:
	}
	var done <-chan struct{}
	if ctx != nil {
		done = ctx.Done()
	}
	select {
	case g.slots <- struct{}{}:
		return nil
	case <-done:
		return ctx.Err()
	}
}

// leave gives back the slot that enter took
func (g *Gate) leave() {
	if g != nil {
		<-g.slots
	}
}
