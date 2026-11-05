package findlimits

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// What the storage does by itself, without weed: how long the end of an upload takes
// (its fsyncs and rename), how many calls it answers at once, and how fast it writes

// Probe is what the storage did
type Probe struct {
	// An upload's end, as weed's: a file of 4 KiB written, synced, renamed into
	// place, and its directory synced; one at a time, then 16 at once
	CommitP50     float64 `json:"commit_p50_seconds"`
	CommitP99     float64 `json:"commit_p99_seconds"`
	CommitsPerSec float64 `json:"commits_per_second_16"`
	// Opens, stats and reads of 4 KiB of files, at once, as weed's calls to the
	// storage are, with each number of calls at once
	Parallel []ParallelPoint `json:"parallel"`
	// A large file written and synced
	WriteBytesPerSec float64 `json:"write_bytes_per_second"`
}

// ParallelPoint is how many calls the storage answered a second, Calls at once
type ParallelPoint struct {
	Calls     int     `json:"calls"`
	PerSecond float64 `json:"per_second"`
}

// at is the calls a second of Calls at once (0 if not measured)
func (p *Probe) at(calls int) float64 {
	for _, pt := range p.Parallel {
		if pt.Calls == calls {
			return pt.PerSecond
		}
	}
	return 0
}

type probeSize struct {
	commits   int           // one at a time
	duration  time.Duration // of each measure of calls at once
	files     int
	writeSize int64
}

var (
	probeFull  = probeSize{commits: 200, duration: 2 * time.Second, files: 2000, writeSize: 512 << 20}
	probeQuick = probeSize{commits: 20, duration: 300 * time.Millisecond, files: 200, writeSize: 16 << 20}
)

// parallelCalls is the numbers of calls at once probed: a few, and around current,
// max_storage_calls
func parallelCalls(current int) []int {
	calls := []int{1, 4, 16, 64, 256, 1024}
	for _, n := range []int{current / 4, current, current * 4} {
		if n >= 1 && n <= 4096 && !slices.Contains(calls, n) {
			calls = append(calls, n)
		}
	}
	slices.Sort(calls)
	return calls
}

// probeStorage measures the storage of dir, in a directory of its own below it,
// which it removes
func probeStorage(ctx context.Context, dir string, size probeSize, current int) (*Probe, error) {
	work, err := os.MkdirTemp(dir, "probe-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	p := &Probe{}

	// Commits, one at a time
	data := make([]byte, 4096)
	rand.NewChaCha8([32]byte{'p'}).Read(data)
	var lat []time.Duration
	for i := 0; i < size.commits && ctx.Err() == nil; i++ {
		start := time.Now()
		if err := commit(work, fmt.Sprintf("c%d", i), data); err != nil {
			return nil, err
		}
		lat = append(lat, time.Since(start))
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	slices.Sort(lat)
	p.CommitP50 = lat[len(lat)/2].Seconds()
	p.CommitP99 = lat[min(len(lat)-1, len(lat)*99/100)].Seconds()

	// 16 at once, as weed's uploads of several clients
	var n atomic.Int64
	var failed atomic.Pointer[error]
	took := atOnce(ctx, 16, size.duration, func(g, i int) {
		if err := commit(work, fmt.Sprintf("p%d-%d", g, i), data); err != nil {
			failed.CompareAndSwap(nil, &err)
			return
		}
		n.Add(1)
	})
	if e := failed.Load(); e != nil {
		return nil, *e
	}
	p.CommitsPerSec = float64(n.Load()) / took.Seconds()

	// Calls at once, of files the probe made
	files := filepath.Join(work, "files")
	if err := os.Mkdir(files, 0o755); err != nil {
		return nil, err
	}
	for i := range size.files {
		if err := os.WriteFile(filepath.Join(files, fmt.Sprintf("f%05d", i)), data, 0o644); err != nil {
			return nil, err
		}
	}
	dirfd, err := unix.Open(files, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirfd)
	names := make([]string, size.files)
	for i := range names {
		names[i] = fmt.Sprintf("f%05d", i)
	}
	for _, calls := range parallelCalls(current) {
		var ops atomic.Int64
		bufs := make([][]byte, calls)
		for g := range bufs {
			bufs[g] = make([]byte, 4096)
		}
		took := atOnce(ctx, calls, size.duration, func(g, i int) {
			buf := bufs[g]
			fd, err := unix.Openat(dirfd, names[(g*7919+i)%len(names)], unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				return
			}
			var st unix.Stat_t
			unix.Fstat(fd, &st)
			unix.Read(fd, buf)
			unix.Close(fd)
			ops.Add(1)
		})
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		p.Parallel = append(p.Parallel, ParallelPoint{Calls: calls, PerSecond: float64(ops.Load()) / took.Seconds()})
	}

	// A large file, written and synced
	big := make([]byte, 1<<20)
	rand.NewChaCha8([32]byte{'w'}).Read(big)
	f, err := os.Create(filepath.Join(work, "big"))
	if err != nil {
		return nil, err
	}
	start := time.Now()
	for written := int64(0); written < size.writeSize && ctx.Err() == nil; written += int64(len(big)) {
		if _, err := f.Write(big); err != nil {
			f.Close()
			return nil, err
		}
	}
	err = f.Sync()
	f.Close()
	if err != nil {
		return nil, err
	}
	p.WriteBytesPerSec = float64(size.writeSize) / time.Since(start).Seconds()
	return p, ctx.Err()
}

// commit writes data to a new file of dir, syncs it, renames it to name, and syncs
// dir: the end of an upload of weed
func commit(dir, name string, data []byte) error {
	tmp := filepath.Join(dir, ".tmp-"+name)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// atOnce calls op from goroutines at once for d, each with its number and the count of
// its calls so far, and returns how long they took, the calls in progress at d too
func atOnce(ctx context.Context, goroutines int, d time.Duration, op func(g, i int)) time.Duration {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Go(func() {
			for i := 0; ctx.Err() == nil; i++ {
				op(g, i)
			}
		})
	}
	wg.Wait()
	return time.Since(start)
}
