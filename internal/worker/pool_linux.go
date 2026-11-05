package worker

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/fsuser"
	"github.com/labkode/weed/internal/landlock"
	"github.com/labkode/weed/internal/logger"
	"github.com/labkode/weed/internal/metrics"
	"github.com/labkode/weed/internal/seccomp"
	"github.com/labkode/weed/internal/version"
	"golang.org/x/sys/unix"
)

const (
	// startTimeout bounds how long a new worker may take to report that it is ready
	startTimeout = 10 * time.Second
	// maxMessage bounds the messages on control sockets
	maxMessage = 64 << 10
)

// killWait bounds how long a killed worker is waited for (a variable for tests). A
// process exits once each of its threads has returned from the kernel, and a thread
// that waits for storage that does not answer, uninterruptibly (state D, e.g. in
// fsync), does not return until the storage does.
var killWait = 10 * time.Second

// Options configure a Pool
type Options struct {
	// Config is what workers serve with; it must not hold credentials
	Config config.Config
	// IdleTimeout stops a worker that has served no request for this long
	IdleTimeout time.Duration
	// MaxWorkers bounds the number of workers that take requests
	MaxWorkers int
	// Cgroups gives the workers of each account a cgroup of their own, below weed's,
	// which must have been delegated to weed (e.g. by systemd's Delegate=yes)
	Cgroups bool
	// CgroupLimits, if set, are the limits written to the cgroup of an account's
	// workers: file=value, e.g. memory.max=4G (with Cgroups)
	CgroupLimits func(u *fsuser.User) []string
	// Refused, if set, says which accounts get no worker: their requests get 403
	// (banned users, see Kill)
	Refused func(account string) bool
	// Starter, if set, starts the workers (see Starter); otherwise this process
	// does, which needs the privileges to (see errPrivileges)
	Starter *Starter
	// Lost, if set, is called once the starter has gone: workers no longer start
	Lost func(error)
	// ConfigSHA256 is that of the configuration that this process read, which the
	// starter must have read too
	ConfigSHA256 string
	// Unmounted, if set, is called with true once the storage that the exported
	// directory was on is no longer mounted (see UnmountedError), and with false once
	// it is again, and workers start
	Unmounted func(bool)
}

// UnmountedError is why workers do not start once the storage that the exported
// directory was on, at startup or mounted since, is no longer mounted: the directory is on the
// file system of / again, or gone. Never the directory beneath: it would take the
// uploads, then hidden once the storage is mounted again.
type UnmountedError struct{ Dir string }

func (e *UnmountedError) Error() string {
	return fmt.Sprintf("the storage that the exported directory %s was on is no longer mounted: requests get 503 until it is mounted again, never served from the directory beneath", e.Dir)
}

// errRefused is the error of accounts that Options.Refused refuses
var errRefused = errors.New("the account is refused")

// Pool runs the workers of the front process: one per account that is in use
type Pool struct {
	opts      Options
	launch    launcher
	closeOnce sync.Once // of launch, by the first Close that returns
	build     string    // of this executable, which workers must run (see version.Build)

	mu           sync.Mutex
	workers      map[string]*worker // by account name: the workers taking new requests
	all          map[*worker]bool   // every worker until it has exited, retired ones included
	unconfinable error              // why workers cannot start confined, if they cannot
	closed       bool
	done         chan struct{} // closed by Close
}

// worker is one worker process, as seen from the front process
type worker struct {
	user   fsuser.User
	ready  chan struct{} // closed once started, or once that failed (err)
	err    error
	exited chan struct{} // closed once the process has exited (or never started)

	check     bool // the worker of Check, as nobody
	pid       int
	started   time.Time
	dir       fileID // the exported directory that it is confined to
	proc      *process
	ctl       *net.UnixConn
	transport *http.Transport
	proxy     *httputil.ReverseProxy
	remote    metrics.Remote

	// Guarded by Pool.mu
	active   int       // requests in progress
	lastUsed time.Time // when the last request finished
	retired  bool      // takes no new requests
	closing  bool      // told to exit once its requests are done
	killed   bool      // see Kill
	blocked  bool      // idle, but threads of its requests wait in the kernel (see reap)
}

func (wk *worker) String() string {
	return fmt.Sprintf("worker of %s (pid %d)", wk.user.Name, wk.pid)
}

// LogValue identifies the worker in log records: worker.user and worker.pid (only
// once it has started)
func (wk *worker) LogValue() slog.Value {
	return slog.GroupValue(slog.String("user", wk.user.Name), slog.Int("pid", wk.pid))
}

// New creates a pool. Workers are started on demand.
func New(opts Options) (*Pool, error) {
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 10 * time.Minute
	}
	if opts.MaxWorkers <= 0 {
		opts.MaxWorkers = 256
	}
	p := &Pool{opts: opts, workers: make(map[string]*worker), all: make(map[*worker]bool), done: make(chan struct{})}
	var err error
	if p.build, err = version.ExecutableBuild(); err != nil {
		return nil, fmt.Errorf("cannot identify the build of weed's executable, which workers must run: %w", err)
	}
	if opts.Starter != nil {
		sha, cgroups, err := opts.Starter.attach(p.applyDir, opts.Lost)
		if err != nil {
			return nil, err
		}
		if sha != opts.ConfigSHA256 || cgroups != opts.Cgroups {
			opts.Starter.close()
			return nil, errors.New("the configuration or the limits file changed as weed started, between the reads of weed and of the starter of its workers: start weed again")
		}
		p.launch = opts.Starter
	} else {
		if err := privileged(); err != nil {
			return nil, err
		}
		if p.launch, err = newLocal(opts.Config, opts.Cgroups, nil, p.applyDir); err != nil {
			return nil, err
		}
	}
	go p.reap()
	return p, nil
}

// Rules are what workers may reach with Landlock: the exported directory
// (first, see confine), to
// do all that WebDAV does (not to execute, nor to make links or special files); to
// read, the system's files: /etc (CA certificates, DNS, time zones), /proc (each
// worker checks its threads), /sys/fs/cgroup (where the Go runtime reads its
// limits), and where the files that /etc links to, tpc.ca_path, SSL_CERT_FILE and
// SSL_CERT_DIR are, and /usr and /lib (time zones, libraries of builds with cgo); to
// execute, what the worker execs as it starts: weed itself, and its dynamic loader if
// it is built with cgo; and /dev/null.
func Rules(cfg *config.Config) []landlock.Rule {
	return append([]landlock.Rule{{Path: cfg.Directory, Access: landlock.Write}}, SystemRules(cfg)...)
}

// SystemRules are the rules of Rules but the exported directory: what weed's own
// process may reach of the system too
func SystemRules(cfg *config.Config) []landlock.Rule {
	rules := []landlock.Rule{
		{Path: "/etc", Access: landlock.Read},
		{Path: "/proc", Access: landlock.Read},
		{Path: "/sys/fs/cgroup", Access: landlock.Read},
		{Path: "/usr", Access: landlock.Read},
		{Path: "/lib", Access: landlock.Read},
		{Path: "/lib64", Access: landlock.Read},
		{Path: "/proc/self/exe", Access: landlock.Exec},
		{Path: "/dev/null", Access: landlock.Write},
	}
	if interp := landlock.Interpreter("/proc/self/exe"); interp != "" {
		rules = append(rules, landlock.Rule{Path: interp, Access: landlock.Exec})
	}
	paths := []string{"/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/localtime", cfg.TPCCAPath, os.Getenv("SSL_CERT_FILE")}
	paths = append(paths, filepath.SplitList(os.Getenv("SSL_CERT_DIR"))...)
	return landlock.Add(rules, landlock.Read, paths...)
}

// fileID identifies a file, and the mount it is on: a storage mounted again has the
// same device and inode numbers, but is another inode for Landlock
type fileID struct{ dev, ino, mnt uint64 }

// identify identifies the file at path, relative to the directory dirfd, or dirfd
// itself if path is "". With what the kernel has cached: a storage that does not
// answer is not asked.
func identify(dirfd int, path string) (fileID, error) {
	flags := unix.AT_STATX_DONT_SYNC
	if path == "" {
		flags |= unix.AT_EMPTY_PATH
	}
	var st unix.Statx_t
	// The unique ID (Linux 6.8) is never reused; before, the kernel gives the other
	if err := unix.Statx(dirfd, path, flags, unix.STATX_INO|unix.STATX_MNT_ID|unix.STATX_MNT_ID_UNIQUE, &st); err != nil {
		return fileID{}, err
	}
	return fileID{uint64(st.Dev_major)<<32 | uint64(st.Dev_minor), st.Ino, st.Mnt_id}, nil
}

// unmounted reports whether the exported directory, now (zero: gone), is no longer
// on the storage that it was last on (zero: never on one), as at startup or mounted
// since: on the file system of root, or gone
func unmounted(storage, now, root fileID) bool {
	return storage != (fileID{}) && storage.dev != root.dev && (now == (fileID{}) || now.dev == root.dev)
}

// applyDir learns of the exported directory that workers now start confined to, or
// of why they cannot start (err), after each look at it (see confiner): workers that
// started confined to another are replaced, and none serve while they cannot start
func (p *Pool) applyDir(dir fileID, err error) {
	p.mu.Lock()
	prev := p.unconfinable
	p.unconfinable = err
	p.mu.Unlock()
	var now, before *UnmountedError
	wasUnmounted := errors.As(prev, &before)
	switch {
	case err == nil:
		if wasUnmounted {
			slog.Info("the storage of the exported directory is mounted again: workers start", "dir", p.opts.Config.Directory)
			if p.opts.Unmounted != nil {
				p.opts.Unmounted(false)
			}
		}
	case errors.As(err, &now):
		if !wasUnmounted {
			slog.Error("the storage of the exported directory is no longer mounted: workers do not start, until it is again", "error", err)
			if p.opts.Unmounted != nil {
				p.opts.Unmounted(true)
			}
		}
	case prev == nil || prev.Error() != err.Error():
		slog.Error("cannot confine workers with Landlock: they do not start", "error", err)
	}
	// Nor do those that started before serve while workers cannot start (requests get
	// 503, with err); also those that started with the previous ruleset as this one
	// was being made
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, wk := range p.workers {
		select {
		case <-wk.ready:
		default:
			continue // starting
		}
		if wk.err != nil || err == nil && wk.dir == dir {
			continue
		}
		if err == nil {
			slog.Info("the exported directory has changed since the worker started (mounted again?): replacing the worker",
				"worker", wk, "dir", p.opts.Config.Directory)
		}
		p.retireLocked(wk)
	}
}

// Sockets are what workers may open (see seccomp), and so the starter, whose filter
// they inherit: Unix sockets alone, unless they make third-party copies, which need
// TCP, and UDP to resolve names
func Sockets(c *config.Config) seccomp.Sockets {
	if c.TPC {
		return seccomp.TCPUDP
	}
	return seccomp.UnixOnly
}

// Workers describes the worker processes that have started and not exited, by account
func (p *Pool) Workers() []Info {
	p.mu.Lock()
	var infos []Info
	for wk := range p.all {
		select {
		case <-wk.exited:
			continue
		case <-wk.ready: // pid and started are set before
			if wk.err == nil {
				infos = append(infos, Info{Account: wk.user.Name, UID: wk.user.UID, PID: wk.pid, Started: wk.started,
					Requests: wk.active, Retired: wk.retired})
			}
		default: // starting
		}
	}
	p.mu.Unlock()
	for i := range infos {
		infos[i].BlockedThreads = blockedThreads(infos[i].PID)
	}
	slices.SortFunc(infos, func(a, b Info) int { return cmp.Or(cmp.Compare(a.Account, b.Account), cmp.Compare(a.PID, b.PID)) })
	return infos
}

// Check starts a worker as nobody (65534) and stops it, so that what would keep
// workers from starting shows at startup rather than on the first request
func (p *Pool) Check() error {
	wk := &worker{user: nobody, check: true, ready: make(chan struct{}), exited: make(chan struct{}), retired: true}
	p.mu.Lock()
	p.all[wk] = true
	p.mu.Unlock()
	p.start(wk)
	if wk.err != nil {
		return wk.err
	}
	p.mu.Lock()
	p.closeLocked(wk)
	p.mu.Unlock()
	<-wk.exited
	return nil
}

// ServeHTTP forwards an authenticated request to the worker of account u, starting
// it if needed
func (p *Pool) ServeHTTP(w http.ResponseWriter, r *http.Request, u *fsuser.User) {
	wk, err := p.acquire(u)
	if errors.Is(err, errRefused) {
		slog.InfoContext(r.Context(), "the account gets no worker (Options.Refused)", "user", u.Name)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if unmounted := (*UnmountedError)(nil); errors.As(err, &unmounted) {
		w.Header().Set("Retry-After", "10")
		http.Error(w, "The storage is not mounted", http.StatusServiceUnavailable)
		return
	}
	if err != nil {
		slog.WarnContext(r.Context(), "no worker for the request", "user", u.Name, "error", err)
		w.Header().Set("Retry-After", "10")
		http.Error(w, "No worker process is available for this account", http.StatusServiceUnavailable)
		return
	}
	defer p.release(wk)
	wk.proxy.ServeHTTP(w, r)
}

// acquire returns the worker of u, counting a request in progress
func (p *Pool) acquire(u *fsuser.User) (*worker, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errors.New("shutting down")
	}
	if p.opts.Refused != nil && p.opts.Refused(u.Name) {
		p.mu.Unlock()
		return nil, errRefused
	}
	// Logged once, by checkDir, rather than a worker failing to start per request
	if unmounted := (*UnmountedError)(nil); errors.As(p.unconfinable, &unmounted) {
		err := p.unconfinable
		p.mu.Unlock()
		return nil, err
	}
	wk := p.workers[u.Name]
	if wk != nil && !sameAccount(&wk.user, u) {
		// Not wk itself, whose pid is not set while it is starting
		slog.Info("account changed, replacing its worker", "account", u, "previous", &wk.user)
		p.retireLocked(wk)
		wk = nil
	}
	if wk == nil {
		if len(p.workers) >= p.opts.MaxWorkers && !p.retireIdlestLocked() {
			p.mu.Unlock()
			return nil, fmt.Errorf("no worker for %s: the %d workers allowed (unix_users.max_workers) are all busy", u.Name, p.opts.MaxWorkers)
		}
		wk = &worker{user: *u, ready: make(chan struct{}), exited: make(chan struct{})}
		p.workers[u.Name] = wk
		p.all[wk] = true
		go p.start(wk)
	}
	wk.active++
	p.mu.Unlock()

	<-wk.ready
	if wk.err != nil {
		p.release(wk)
		return nil, wk.err
	}
	return wk, nil
}

// release counts the end of a request
func (p *Pool) release(wk *worker) {
	p.mu.Lock()
	defer p.mu.Unlock()
	wk.active--
	wk.lastUsed = time.Now()
	if wk.retired && wk.active == 0 {
		p.closeLocked(wk)
	}
}

func sameAccount(a, b *fsuser.User) bool {
	return a.UID == b.UID && a.GID == b.GID && slices.Equal(a.Groups, b.Groups)
}

// retireLocked sends no more requests to a worker, which exits once it has finished
// those it has
func (p *Pool) retireLocked(wk *worker) {
	wk.retired = true
	if p.workers[wk.user.Name] == wk {
		delete(p.workers, wk.user.Name)
	}
	if wk.active == 0 {
		p.closeLocked(wk)
	}
}

// retireIdlestLocked retires the worker that has been idle the longest, if any is,
// but not one whose threads wait in the kernel (see reap)
func (p *Pool) retireIdlestLocked() bool {
	var idlest *worker
	for _, wk := range p.workers {
		if wk.active == 0 && (idlest == nil || wk.lastUsed.Before(idlest.lastUsed)) && blockedThreads(wk.pid) == 0 {
			idlest = wk
		}
	}
	if idlest == nil {
		return false
	}
	slog.Info("stopping the idlest worker to make room (unix_users.max_workers)", "worker", idlest)
	p.retireLocked(idlest)
	return true
}

// closeLocked shuts the control socket of a worker for writing: it takes no new
// connections, and exits once the requests it has are done
func (p *Pool) closeLocked(wk *worker) {
	if wk.closing {
		return
	}
	wk.closing = true
	go func() {
		<-wk.ready
		if wk.err == nil {
			wk.ctl.CloseWrite()
			wk.transport.CloseIdleConnections()
		}
	}()
}

// reap retires the workers that have been idle for IdleTimeout. A worker whose
// threads wait in the kernel would not exit, and the account's next requests would
// go to a new worker, whose threads could get stuck as well: it is kept, and its
// requests beyond unix_users.max_requests get 503.
func (p *Pool) reap() {
	interval := min(max(p.opts.IdleTimeout/4, 10*time.Millisecond), 30*time.Second)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
		case <-p.done:
			return
		}
		p.mu.Lock()
		for _, wk := range p.workers {
			if wk.active == 0 && time.Since(wk.lastUsed) >= p.opts.IdleTimeout {
				n := blockedThreads(wk.pid)
				if n > 0 && !wk.blocked {
					slog.Warn("an idle worker keeps running: threads of its requests wait in the kernel, for storage that does not answer?",
						"worker", wk, "blocked_threads", n)
				}
				if wk.blocked = n > 0; !wk.blocked {
					slog.Info("stopping an idle worker", "worker", wk)
					p.retireLocked(wk)
				}
			}
		}
		p.mu.Unlock()
	}
}

// Reload writes the cgroup limits of the accounts that have workers again, as
// Options.CgroupLimits now gives them, and makes the running workers re-read what
// they read at startup (the CAs of TPC endpoints, their Go memory limit); those that
// are starting read it anyway. It returns why limits could not be written.
func (p *Pool) Reload() error {
	p.mu.Lock()
	var running []*worker
	for wk := range p.all {
		select {
		case <-wk.ready:
			if wk.err == nil && !wk.closing {
				running = append(running, wk)
			}
		default:
		}
	}
	p.mu.Unlock()
	var errs []error
	if p.opts.Cgroups && p.opts.CgroupLimits != nil {
		done := make(map[string]bool)
		for _, wk := range running {
			if !done[wk.user.Name] {
				done[wk.user.Name] = true
				if err := p.launch.setLimits(&wk.user, p.opts.CgroupLimits(&wk.user)); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	for _, wk := range running {
		wk.ctl.Write([]byte{msgReload})
	}
	return errors.Join(errs...)
}

// Kill stops the workers of an account at once, aborting the requests they serve (an
// upload in progress never replaces a file). It returns how many it killed, and an
// error naming those that have not exited after killWait (see kill). Once
// Options.Refused refuses the account, call Kill: no worker starts for it after.
func (p *Pool) Kill(account string) (int, error) {
	p.mu.Lock()
	var wks []*worker
	for wk := range p.all {
		if wk.user.Name == account {
			wk.killed = true
			p.retireLocked(wk)
			wks = append(wks, wk)
		}
	}
	p.mu.Unlock()
	return kill(wks)
}

// Close stops every worker: they get until ctx is done to finish their requests,
// and are killed then. It does not wait for those that do not exit (see kill).
func (p *Pool) Close(ctx context.Context) {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		close(p.done)
	}
	var all []*worker
	for wk := range p.all {
		p.retireLocked(wk)
		p.closeLocked(wk)
		all = append(all, wk)
	}
	p.mu.Unlock()
	var left []*worker
	for _, wk := range all {
		select {
		case <-wk.exited:
		case <-ctx.Done():
			left = append(left, wk)
		}
	}
	for _, wk := range left {
		slog.Warn("killing a worker that did not stop in time", "worker", wk)
	}
	if _, err := kill(left); err != nil {
		slog.Error("stopping without waiting for the workers that do not exit", "error", err)
	}
	p.closeOnce.Do(p.launch.close)
}

// kill kills the workers that have started, and waits for them to exit, for at most
// killWait. It returns how many it killed, and an error naming those that have not
// exited: their threads wait in the kernel, for storage that does not answer. Such
// a worker exits once the storage answers, which watch logs.
func kill(wks []*worker) (int, error) {
	var killed []*worker
	for _, wk := range wks {
		<-wk.ready
		if wk.err == nil { // else it did not start
			if err := wk.proc.kill(); err != nil {
				slog.Error("cannot kill a worker", "worker", wk, "error", err)
			}
			killed = append(killed, wk)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), killWait)
	defer cancel()
	var stuck []string
	for _, wk := range killed {
		select {
		case <-wk.exited:
		case <-ctx.Done():
			stuck = append(stuck, fmt.Sprintf("the %s has not exited %v after being killed: %d of its threads wait in the kernel",
				wk, killWait, blockedThreads(wk.pid)))
		}
	}
	if len(stuck) > 0 {
		return len(killed), fmt.Errorf("%s, for storage that does not answer? A worker exits once they return", strings.Join(stuck, "; "))
	}
	return len(killed), nil
}

// blockedThreads counts the threads of a process that wait in the kernel,
// uninterruptibly (state D): for a moment while they read or write files, or for as
// long as the storage they wait for does not answer. Signals do not end the wait,
// not even SIGKILL.
func blockedThreads(pid int) int {
	tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return 0
	}
	n := 0
	for _, t := range tasks {
		if stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/stat", pid, t.Name())); err == nil && threadState(stat) == 'D' {
			n++
		}
	}
	return n
}

// threadState is the state in /proc/<pid>/task/<tid>/stat: "tid (comm) state ...",
// where comm may hold spaces and parentheses
func threadState(stat []byte) byte {
	if i := bytes.LastIndexByte(stat, ')'); i >= 0 && i+2 < len(stat) {
		return stat[i+2]
	}
	return 0
}

// start starts the process of a worker, and closes wk.ready
func (p *Pool) start(wk *worker) {
	if err := p.spawn(wk); err != nil {
		wk.err = fmt.Errorf("cannot start a worker for %s: %w", wk.user.Name, err)
		slog.Error("cannot start a worker", "account", &wk.user, "error", err)
		metrics.WorkerStarts.Inc("failure")
		p.mu.Lock()
		if p.workers[wk.user.Name] == wk {
			delete(p.workers, wk.user.Name)
		}
		delete(p.all, wk)
		p.mu.Unlock()
		close(wk.exited)
		close(wk.ready)
		return
	}
	slog.Info("started a worker", "worker", wk, "account", &wk.user)
	metrics.WorkerStarts.Inc("success")
	metrics.Workers.Inc()
	close(wk.ready)
	go p.watch(wk)
}

// spawn starts the process of a worker and waits until it reports that it is ready
func (p *Pool) spawn(wk *worker) (err error) {
	ctl, child, err := socketPair(unix.SOCK_SEQPACKET)
	if err != nil {
		return err
	}
	defer child.Close()
	defer func() {
		if err != nil {
			ctl.Close()
		}
	}()
	logs, logw, err := os.Pipe()
	if err != nil {
		return err
	}
	var limits []string
	if p.opts.Cgroups && p.opts.CgroupLimits != nil {
		limits = p.opts.CgroupLimits(&wk.user)
	}
	proc, err := p.launch.start(&wk.user, wk.check, child, logw, limits)
	logw.Close()
	if err != nil {
		logs.Close()
		return err
	}
	wk.proc, wk.pid, wk.dir, wk.started = proc, proc.pid, proc.dir, time.Now()
	go relayLog(logs, wk)
	stop := func(err error) error {
		proc.kill()
		<-proc.exited
		return err
	}

	ctl.SetReadDeadline(time.Now().Add(startTimeout))
	buf := make([]byte, maxMessage)
	n, err := ctl.Read(buf)
	ctl.SetReadDeadline(time.Time{})
	if errors.Is(err, io.EOF) {
		return stop(errors.New("the worker exited during startup"))
	} else if err != nil {
		return stop(err)
	}
	// "ready <build>"; workers of builds from before the check say "ready"
	build, ready := strings.CutPrefix(string(buf[:n]), "ready")
	if !ready {
		return stop(errors.New(string(buf[:n]))) // why the worker refuses to serve
	}
	if build = strings.TrimPrefix(build, " "); build != p.build {
		if build == "" {
			build = "unknown"
		}
		return stop(fmt.Errorf("the worker runs build %s of weed, not this process's %s: "+
			"was weed's executable overwritten in place? Restart weed", build, p.build))
	}

	wk.ctl = ctl
	wk.transport = &http.Transport{
		DialContext:         func(context.Context, string, string) (net.Conn, error) { return wk.dial() },
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     90 * time.Second,
		// Bodies are relayed byte for byte
		DisableCompression: true,
		// The client is told to send the body once the worker has asked for it
		ExpectContinueTimeout: time.Second,
	}
	wk.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme, pr.Out.URL.Host = "http", "worker"
			pr.Out.Host = pr.In.Host
			describe(pr.Out.Header, pr.In)
		},
		Transport:  wk.transport,
		BufferPool: buffers,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if r.Context().Err() == nil {
				slog.WarnContext(r.Context(), "cannot forward the request to its worker", "worker", wk, "error", err)
			}
			http.Error(w, "The worker process of this account failed", http.StatusBadGateway)
		},
	}
	return nil
}

// watch applies the changes to metrics that a worker reports until it exits
func (p *Pool) watch(wk *worker) {
	buf := make([]byte, maxMessage)
	for {
		n, err := wk.ctl.Read(buf)
		if err != nil {
			break
		}
		if err := wk.remote.Apply(buf[:n]); err != nil {
			slog.Error("killing a worker that sent invalid metrics", "worker", wk, "error", err)
			if err := wk.proc.kill(); err != nil {
				slog.Error("cannot kill a worker", "worker", wk, "error", err)
			}
			break
		}
	}
	<-wk.proc.exited
	err := wk.proc.err
	wk.ctl.Close()
	wk.transport.CloseIdleConnections()
	wk.remote.Close()
	metrics.Workers.Dec()

	p.mu.Lock()
	expected, killed := wk.closing || p.closed, wk.killed
	if p.workers[wk.user.Name] == wk {
		delete(p.workers, wk.user.Name)
	}
	delete(p.all, wk)
	p.mu.Unlock()
	switch {
	case killed:
		slog.Info("worker killed", "worker", wk)
		metrics.WorkerExits.Inc("killed")
	case expected && err == nil:
		slog.Info("worker stopped", "worker", wk)
		metrics.WorkerExits.Inc("stopped")
	default:
		if err == nil {
			err = errors.New("exited without being asked to")
		}
		slog.Error("worker failed", "worker", wk, "error", err)
		metrics.WorkerExits.Inc("failed")
	}
	close(wk.exited)
}

// dial makes a connection to the worker: one end of a new socket pair, the other end
// being passed to the worker over its control socket
func (wk *worker) dial() (net.Conn, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	enlargeBuffers(fds[0])
	enlargeBuffers(fds[1])
	local := os.NewFile(uintptr(fds[0]), "worker connection")
	defer local.Close()
	defer unix.Close(fds[1])
	if _, _, err := wk.ctl.WriteMsgUnix([]byte{msgConnection}, unix.UnixRights(fds[1]), nil); err != nil {
		return nil, fmt.Errorf("cannot reach the %s: %w", wk, err)
	}
	return net.FileConn(local)
}

// socketBuffer is the size of the send and receive buffers of connections to workers:
// with the default (about 200 KiB), relaying a download costs a third of its
// throughput. No more, as a client that reads slower than the worker keeps the
// buffer full, in the kernel (twice this): with 4 MiB, a thousand slow downloads
// held 7 GB, for no more throughput than with 1 MiB (test/stress slow-download)
const socketBuffer = 1 << 20

// enlargeBuffers gives a socket buffers of socketBuffer bytes, or of net.core.wmem_max
// and rmem_max if they are smaller: beyond, that needs CAP_NET_ADMIN, which weed gives
// up, as root too (the RPM raises them, see Performance)
func enlargeBuffers(fd int) {
	for _, opt := range [][2]int{{unix.SO_SNDBUFFORCE, unix.SO_SNDBUF}, {unix.SO_RCVBUFFORCE, unix.SO_RCVBUF}} {
		if unix.SetsockoptInt(fd, unix.SOL_SOCKET, opt[0], socketBuffer) != nil {
			unix.SetsockoptInt(fd, unix.SOL_SOCKET, opt[1], socketBuffer)
		}
	}
}

// socketPair returns a connected pair of Unix sockets: one as a connection, the other
// as a file to pass to another process
func socketPair(typ int) (*net.UnixConn, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, typ|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fds[0]), "socket")
	defer f.Close()
	c, err := net.FileConn(f)
	if err != nil {
		unix.Close(fds[1])
		return nil, nil, err
	}
	return c.(*net.UnixConn), os.NewFile(uintptr(fds[1]), "socket"), nil
}

// environment is that of workers: none of weed's, which may hold secrets, only what
// Go and its TLS stack read
func environment() []string {
	env := []string{"PATH=/usr/bin:/bin"}
	for _, k := range []string{"TZ", "SSL_CERT_FILE", "SSL_CERT_DIR", "GODEBUG", "GOGC", "GOMAXPROCS", "GOMEMLIMIT", "GOTRACEBACK"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// relayLog logs what a worker writes to its standard output and error (its log
// records, see RunWorker), each record marked as the worker's
func relayLog(r *os.File, wk *worker) {
	defer r.Close()
	br := bufio.NewReaderSize(r, maxMessage)
	for {
		line, err := br.ReadSlice('\n')
		if line = bytes.TrimRight(line, "\n"); len(line) > 0 {
			logger.Relay(line, slog.Any("worker", wk))
		}
		if err != nil && err != bufio.ErrBufferFull {
			return
		}
	}
}

// buffers relay bodies between clients and workers
var buffers = &bufferPool{}

type bufferPool struct{ pool sync.Pool }

func (b *bufferPool) Get() []byte {
	if v, ok := b.pool.Get().(*[]byte); ok {
		return *v
	}
	return make([]byte, 256<<10)
}

func (b *bufferPool) Put(buf []byte) { b.pool.Put(&buf) }
