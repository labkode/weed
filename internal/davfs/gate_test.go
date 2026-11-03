package davfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGate(t *testing.T) {
	if NewGate(0) != nil {
		t.Fatal("a gate of no slot bounds")
	}
	var none *Gate // bounds nothing
	for range 3 {
		if err := none.enter(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	none.leave()

	g := NewGate(2)
	ctx := context.Background()
	g.enter(ctx)
	g.enter(ctx)
	// Full: a call waits until its request is cancelled
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := g.enter(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("enter a full gate, cancelled: %v", err)
	}
	short, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if err := g.enter(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("enter a full gate until a deadline: %v", err)
	}
	// or, without a context (commit, close), until a slot is free
	entered := make(chan struct{})
	go func() {
		g.enter(nil)
		close(entered)
	}()
	select {
	case <-entered:
		t.Fatal("entered a full gate")
	case <-time.After(20 * time.Millisecond):
	}
	g.leave()
	<-entered
	g.leave()
	g.leave()
	if len(g.slots) != 0 {
		t.Fatalf("%d slots held", len(g.slots))
	}
}

// The calls of a tree, and of its files, hold at most the gate's slots at once, and
// give them all back
func TestGateBoundsTree(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "f"), make([]byte, 1<<20), 0o644)
	os.Mkdir(filepath.Join(dir, "d"), 0o755)
	for i := range 100 {
		os.WriteFile(filepath.Join(dir, "d", string(rune('a'+i%26))+string(rune('a'+i/26))), nil, 0o644)
	}
	g := NewGate(3)
	var most atomic.Int64
	stop := make(chan struct{})
	go func() { // watches how many slots are held
		for {
			select {
			case <-stop:
				return
			default:
			}
			if n := int64(len(g.slots)); n > most.Load() {
				most.Store(n)
			}
		}
	}()
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tree, err := FS{Root: dir, Gate: g}.Open(ctx)
			if err != nil {
				t.Error(err)
				return
			}
			defer tree.Close()
			for range 20 {
				if _, err := tree.Stat(ctx, "/f"); err != nil {
					t.Error(err)
				}
				f, err := tree.Open(ctx, "/f")
				if err != nil {
					t.Error(err)
					continue
				}
				buf := make([]byte, 64<<10)
				for {
					if _, err := f.Read(buf); err != nil {
						break
					}
				}
				f.Close()
				l, err := tree.List(ctx, "/d")
				if err != nil {
					t.Error(err)
					continue
				}
				for {
					if _, err := l.Next(); err != nil {
						break
					}
				}
				l.Close()
				af, err := tree.CreateAtomic(ctx, "/u"+string(rune('a'+i)), 0o644)
				if err != nil {
					t.Error(err)
					continue
				}
				af.Write([]byte("x"))
				if err := af.Commit(); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	if n := len(g.slots); n != 0 {
		t.Errorf("%d slots held after all calls", n)
	}
	if most.Load() > 3 {
		t.Errorf("%d slots held at once", most.Load())
	}
}
