package worker

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/labkode/weed/internal/fsuser"
	"golang.org/x/sys/unix"
)

func TestThreadState(t *testing.T) {
	for stat, want := range map[string]byte{
		"249 (weed) D 1 249 249 0 -1 4194560": 'D',
		"250 (a) b (c)) S 1 250":              'S',
		"251 (weed":                           0,
		"":                                    0,
	} {
		if got := threadState([]byte(stat)); got != want {
			t.Errorf("threadState(%q) = %q, want %q", stat, got, want)
		}
	}
	if n := blockedThreads(-1); n != 0 {
		t.Errorf("blockedThreads of no process: %d", n)
	}
}

func TestUnmounted(t *testing.T) {
	root := fileID{dev: 1, ino: 2, mnt: 1}
	storage := fileID{dev: 7, ino: 2, mnt: 30}
	for _, c := range []struct {
		name         string
		storage, now fileID
		want         bool
	}{
		{"the storage unmounted: the directory beneath, on /", storage, fileID{dev: 1, ino: 40, mnt: 1}, true},
		{"the storage above unmounted: the directory gone", storage, fileID{}, true},
		{"another storage mounted in its place", storage, fileID{dev: 8, ino: 2, mnt: 31}, false},
		{"the storage mounted again", storage, fileID{dev: 7, ino: 2, mnt: 32}, false},
		{"never on a storage: a plain directory on /, replaced by another", fileID{}, fileID{dev: 1, ino: 41, mnt: 1}, false},
		{"never on a storage: a storage mounted over it", fileID{}, storage, false},
		{"never on a storage: gone", fileID{}, fileID{}, false},
	} {
		if got := unmounted(c.storage, c.now, root); got != c.want {
			t.Errorf("%s: unmounted = %v, want %v", c.name, got, c.want)
		}
	}
}

// A killed worker that does not exit, as one whose threads wait for storage that does
// not answer, is not waited for: neither by Kill (a ban) nor by Close (shutdown)
func TestKilledWorkerThatDoesNotExit(t *testing.T) {
	defer func(d time.Duration) { killWait = d }(killWait)
	killWait = 100 * time.Millisecond

	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	ctl, child, err := socketPair(unix.SOCK_SEQPACKET)
	if err != nil {
		t.Fatal(err)
	}
	child.Close()
	t.Cleanup(func() { ctl.Close() })
	ready := make(chan struct{})
	close(ready)
	// exited is never closed, as for a process whose threads do not return
	proc := &process{pid: cmd.Process.Pid, kill: cmd.Process.Kill, exited: make(chan struct{})}
	wk := &worker{user: fsuser.User{Name: "alice", UID: 6001}, ready: ready, exited: make(chan struct{}),
		proc: proc, pid: proc.pid, ctl: ctl, transport: &http.Transport{}}
	p := &Pool{workers: map[string]*worker{"alice": wk}, all: map[*worker]bool{wk: true}, done: make(chan struct{}),
		launch: noLauncher{}}

	start := time.Now()
	n, err := p.Kill("alice")
	if n != 1 || err == nil || !strings.Contains(err.Error(), "worker of alice (pid ") || !strings.Contains(err.Error(), "has not exited 100ms after being killed") {
		t.Errorf("Kill = %d, %v", n, err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Kill took %v", d)
	}
	if infos := p.Workers(); len(infos) != 1 || !infos[0].Retired {
		t.Errorf("Workers after Kill: %+v", infos)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		p.Close(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close waits for a worker that does not exit")
	}
}

// noLauncher starts no worker
type noLauncher struct{}

func (noLauncher) start(*fsuser.User, bool, *os.File, *os.File, []string) (*process, error) {
	return nil, errors.New("no launcher")
}
func (noLauncher) setLimits(*fsuser.User, []string) error { return nil }
func (noLauncher) close()                                 {}
