package worker

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/fsuser"
	"github.com/labkode/weed/internal/landlock"
	"github.com/labkode/weed/internal/limits"
	"github.com/labkode/weed/internal/logger"
	"github.com/labkode/weed/internal/metrics"
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
	// Shaper, if set, paces what the requests of each account send and receive, and
	// what its third-party copies move: the workers pay over a socket of their own
	Shaper *limits.Shaper
	// Refused, if set, says which accounts get no worker: their requests get 403
	// (banned users, see Kill)
	Refused func(account string) bool
	// Landlock confines the workers to the exported directory, and to reading the
	// system's files, with Landlock (see landlockRules), when the kernel has it
	Landlock bool
}

// errRefused is the error of accounts that Options.Refused refuses
var errRefused = errors.New("the account is refused")

// Pool runs the workers of the front process: one per account that is in use
type Pool struct {
	opts     Options
	cgroups  *cgroups        // nil: workers stay in weed's cgroup
	build    string          // of this executable, which workers must run (see version.Build)
	landlock []landlock.Rule // nil: workers are not confined with Landlock

	mu           sync.Mutex
	workers      map[string]*worker // by account name: the workers taking new requests
	all          map[*worker]bool   // every worker until it has exited, retired ones included
	confined     *confinement       // with landlock, once the exported directory has answered
	unconfinable error              // why workers cannot be confined with landlock, if they cannot
	closed       bool
	done         chan struct{} // closed by Close
}

// confinement is the ruleset of Landlock that workers start with, of the exported
// directory as it was when it was made
type confinement struct {
	dir   fileID
	rules *landlock.Ruleset
}

// worker is one worker process, as seen from the front process
type worker struct {
	user   fsuser.User
	ready  chan struct{} // closed once started, or once that failed (err)
	err    error
	exited chan struct{} // closed once the process has exited (or never started)

	pid       int
	started   time.Time
	dir       fileID // the exported directory when it started, with Landlock
	cmd       *exec.Cmd
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
	if opts.Cgroups {
		cg, err := newCgroups()
		if err != nil {
			return nil, err
		}
		p.cgroups = cg
	}
	if opts.Landlock {
		if abi := landlock.ABI(); abi < landlock.MinABI {
			slog.Warn("Landlock is not available (Linux 5.19 or later, with landlock in lsm=): workers are confined by Unix permissions only",
				"landlock_abi", abi)
		} else {
			p.landlock = landlockRules(&opts.Config)
			var desc []string
			for _, r := range p.landlock {
				desc = append(desc, [...]string{landlock.Read: "read ", landlock.Exec: "execute ", landlock.Write: "write "}[r.Access]+r.Path)
			}
			slog.Info("workers are confined with Landlock", "landlock_abi", abi, "rules", desc)
			first := make(chan struct{})
			go p.watchDir(first)
			select {
			case <-first:
			case <-time.After(10 * time.Second):
				slog.Warn("the exported directory does not answer: workers, confined to it with Landlock, start once it does",
					"dir", opts.Config.Directory)
			}
		}
	}
	go p.reap()
	return p, nil
}

// landlockRules is what workers may reach with Landlock: the exported directory
// (first, see confine), to
// do all that WebDAV does (not to execute, nor to make links or special files); to
// read, the system's files: /etc (CA certificates, DNS, time zones), /proc (each
// worker checks its threads), /sys/fs/cgroup (where the Go runtime reads its
// limits), and where the files that /etc links to, tpc.ca_path, SSL_CERT_FILE and
// SSL_CERT_DIR are, and /usr and /lib (time zones, libraries of builds with cgo); to
// execute, what the worker execs as it starts: weed itself, and its dynamic loader if
// it is built with cgo; and /dev/null.
func landlockRules(cfg *config.Config) []landlock.Rule {
	rules := []landlock.Rule{
		{Path: cfg.Directory, Access: landlock.Write},
		{Path: "/etc", Access: landlock.Read},
		{Path: "/proc", Access: landlock.Read},
		{Path: "/sys/fs/cgroup", Access: landlock.Read},
		{Path: "/usr", Access: landlock.Read},
		{Path: "/lib", Access: landlock.Read},
		{Path: "/lib64", Access: landlock.Read},
		{Path: "/proc/self/exe", Access: landlock.Exec},
		{Path: "/dev/null", Access: landlock.Write},
	}
	if interp := interpreter(); interp != "" {
		rules = append(rules, landlock.Rule{Path: interp, Access: landlock.Exec})
	}
	// Directories rather than files, which are replaced when they are updated
	paths := []string{"/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/localtime", cfg.TPCCAPath, os.Getenv("SSL_CERT_FILE")}
	paths = append(paths, filepath.SplitList(os.Getenv("SSL_CERT_DIR"))...)
	for _, p := range paths {
		if p == "" {
			continue
		}
		if real, err := filepath.EvalSymlinks(p); err == nil {
			p = real
		}
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			p = filepath.Dir(p)
		}
		if !slices.ContainsFunc(rules, func(r landlock.Rule) bool { return inside(p, r.Path) }) {
			rules = append(rules, landlock.Rule{Path: p, Access: landlock.Read})
		}
	}
	return rules
}

// interpreter is the dynamic loader that weed's executable names, "" if it has none
// (built without cgo)
func interpreter() string {
	f, err := elf.Open("/proc/self/exe")
	if err != nil {
		return ""
	}
	defer f.Close()
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_INTERP {
			b, err := io.ReadAll(prog.Open())
			if err != nil {
				return ""
			}
			return strings.TrimRight(string(b), "\x00")
		}
	}
	return ""
}

// inside says whether p is dir or below it
func inside(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

// fileID identifies a file, and the mount it is on: a storage mounted again has the
// same device and inode numbers, but is another inode for Landlock
type fileID struct{ dev, ino, mnt uint64 }

// identify identifies the file at path, relative to the directory dirfd, or dirfd
// itself if path is "". With what the kernel has cached: a storage that does not
// answer is not asked.
func identify(dirfd int, path string) (fileID, bool) {
	flags := unix.AT_STATX_DONT_SYNC
	if path == "" {
		flags |= unix.AT_EMPTY_PATH
	}
	var st unix.Statx_t
	// The unique ID (Linux 6.8) is never reused; before, the kernel gives the other
	if err := unix.Statx(dirfd, path, flags, unix.STATX_INO|unix.STATX_MNT_ID|unix.STATX_MNT_ID_UNIQUE, &st); err != nil {
		return fileID{}, false
	}
	return fileID{uint64(st.Dev_major)<<32 | uint64(st.Dev_minor), st.Ino, st.Mnt_id}, true
}

// dirCheckInterval is how often watchDir looks at the exported directory (a variable
// for tests)
var dirCheckInterval = 5 * time.Second

// watchDir makes the ruleset that workers start with, and makes it again whenever the
// exported directory is another than it was, then replacing the workers that started
// before: the rules of Landlock name the directories themselves, and a storage
// mounted again over the exported directory is one that they cannot reach. It alone
// touches the exported directory, so that only it waits if the storage does not
// answer, not the requests that start workers. first is closed after the first look.
func (p *Pool) watchDir(first chan<- struct{}) {
	t := time.NewTicker(dirCheckInterval)
	defer t.Stop()
	for {
		p.checkDir()
		if first != nil {
			close(first)
			first = nil
		}
		select {
		case <-t.C:
		case <-p.done:
			p.mu.Lock()
			if p.confined != nil {
				p.confined.rules.Close()
				p.confined = nil
			}
			p.mu.Unlock()
			return
		}
	}
}

func (p *Pool) checkDir() {
	dir := p.opts.Config.Directory
	id, ok := identify(unix.AT_FDCWD, dir)
	p.mu.Lock()
	c := p.confined
	p.mu.Unlock()
	if c == nil || ok && id != c.dir {
		next, err := p.confine()
		p.mu.Lock()
		prev := p.unconfinable
		p.unconfinable = err
		p.mu.Unlock()
		if err != nil {
			if prev == nil || prev.Error() != err.Error() {
				slog.Error("cannot confine workers with Landlock: they do not start", "error", err)
			}
			return
		}
		p.mu.Lock()
		p.confined = next
		p.mu.Unlock()
		if c != nil {
			c.rules.Close() // workers that start with it have a copy
		}
	}
	// Also those that started with the previous ruleset as this one was being made
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, wk := range p.workers {
		select {
		case <-wk.ready:
		default:
			continue // starting
		}
		if wk.err == nil && wk.dir != p.confined.dir {
			slog.Info("the exported directory has changed since the worker started (mounted again?): replacing the worker",
				"worker", wk, "dir", dir)
			p.retireLocked(wk)
		}
	}
}

// confine makes the ruleset of workers, with the exported directory as it now is (or
// without it, if it cannot be opened)
func (p *Pool) confine() (*confinement, error) {
	c := &confinement{}
	rules := slices.Clone(p.landlock)
	fd, err := unix.Open(rules[0].Path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		rules = rules[1:]
	} else {
		f := os.NewFile(uintptr(fd), rules[0].Path)
		defer f.Close()
		c.dir, _ = identify(fd, "")
		rules[0].File = f
	}
	if c.rules, err = landlock.New(rules); err != nil {
		return nil, err
	}
	if err := reachable(c.rules, rules[0].Path, "/proc/self/exe"); err != nil {
		c.rules.Close()
		return nil, err
	}
	return c, nil
}

// reachable checks that what this process can open, of paths, a thread confined with
// rs can open too. Landlock cannot follow every file system: on some, such as Docker
// Desktop's mounts of the host, it refuses every access, whatever the rules.
func reachable(rs *landlock.Ruleset, paths ...string) error {
	var open []string
	for _, p := range paths {
		if f, err := os.Open(p); err == nil {
			f.Close()
			open = append(open, p)
		}
	}
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread ends with this goroutine
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			errc <- fmt.Errorf("cannot set no_new_privs: %w", err)
			return
		}
		if err := rs.Restrict(); err != nil {
			errc <- err
			return
		}
		for _, p := range open {
			f, err := os.Open(p)
			if err != nil {
				if exe, err := os.Readlink(p); err == nil && p == "/proc/self/exe" {
					p = "weed's executable, " + exe + ","
				}
				errc <- fmt.Errorf("confined with Landlock, workers could not open %s which weed opens without: it is on a file system that Landlock cannot follow (such as Docker Desktop's mounts of the host): move it, or set unix_users.landlock = false", p)
				return
			}
			f.Close()
		}
		errc <- nil
	}()
	return <-errc
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
	wk := &worker{
		user:  fsuser.User{Name: "nobody", UID: 65534, GID: 65534, Groups: []int{65534}},
		ready: make(chan struct{}), exited: make(chan struct{}), retired: true,
	}
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
	if err != nil {
		slog.WarnContext(r.Context(), "no worker for the request", "user", u.Name, "error", err)
		w.Header().Set("Retry-After", "10")
		http.Error(w, "No worker process is available for this account", http.StatusServiceUnavailable)
		return
	}
	defer p.release(wk)
	if s := p.opts.Shaper; s != nil && s.Limited(u) {
		m := s.Meter(u)
		defer m.Close()
		if r.Body != nil && r.Body != http.NoBody {
			r = r.WithContext(r.Context()) // a copy, whose body is metered
			r.Body = m.Body(r.Context(), r.Body)
		}
		w = m.ResponseWriter(r.Context(), w)
	}
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
	if p.cgroups != nil && p.opts.CgroupLimits != nil {
		done := make(map[string]bool)
		for _, wk := range running {
			if !done[wk.user.Name] {
				done[wk.user.Name] = true
				if err := p.cgroups.apply(&wk.user, p.opts.CgroupLimits(&wk.user)); err != nil {
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
			wk.cmd.Process.Kill()
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
	settings, err := json.Marshal(Settings{User: wk.user, Config: p.opts.Config, Cgroup: p.cgroups != nil, Pay: p.opts.Shaper != nil,
		Landlock: p.landlock != nil})
	if err != nil {
		return err
	}
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
	extra := []*os.File{child} // file descriptor 3
	var pay *net.UnixConn
	if p.opts.Shaper != nil {
		var payChild *os.File
		if pay, payChild, err = socketPair(unix.SOCK_SEQPACKET); err != nil {
			return err
		}
		defer payChild.Close()
		defer func() {
			if err != nil {
				pay.Close()
			}
		}()
		extra = append(extra, payChild) // file descriptor 4
	}
	var rules *landlock.Ruleset
	if p.landlock != nil {
		p.mu.Lock()
		c, why := p.confined, p.unconfinable
		if c != nil {
			wk.dir = c.dir
			rules, err = c.rules.Dup()
		}
		p.mu.Unlock()
		if c == nil && why != nil {
			return fmt.Errorf("cannot confine the worker with Landlock: %w", why)
		}
		if c == nil {
			return errors.New("the exported directory has not answered yet, and workers are confined to it with Landlock")
		}
		if err != nil {
			return fmt.Errorf("cannot confine the worker with Landlock: %w", err)
		}
		defer rules.Close()
	}
	logs, logw, err := os.Pipe()
	if err != nil {
		return err
	}
	defer logw.Close()

	groups := make([]uint32, len(wk.user.Groups))
	for i, g := range wk.user.Groups {
		groups[i] = uint32(g)
	}
	cmd := &exec.Cmd{
		// The binary that is running, even if it has since been replaced on disk
		Path:       "/proc/self/exe",
		Args:       []string{"weed", "worker", wk.user.Name},
		Env:        environment(),
		Dir:        "/",
		Stdout:     logw,
		Stderr:     logw,
		ExtraFiles: extra,
		SysProcAttr: &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uint32(wk.user.UID), Gid: uint32(wk.user.GID), Groups: groups},
		},
	}
	if p.cgroups != nil {
		var cgroupLimits []string
		if p.opts.CgroupLimits != nil {
			cgroupLimits = p.opts.CgroupLimits(&wk.user)
		}
		fd, err := p.cgroups.prepare(&wk.user, cgroupLimits)
		if err != nil {
			logs.Close()
			return err
		}
		defer unix.Close(fd)
		cmd.SysProcAttr.UseCgroupFD = true
		cmd.SysProcAttr.CgroupFD = fd
	}
	if err := startConfined(cmd, rules); err != nil {
		logs.Close()
		if errors.Is(err, unix.EPERM) {
			err = fmt.Errorf("%w (weed must run as root, or with CAP_SETUID and CAP_SETGID)", err)
		}
		return err
	}
	wk.cmd, wk.pid, wk.started = cmd, cmd.Process.Pid, time.Now()
	go relayLog(logs, wk)
	stop := func(err error) error {
		cmd.Process.Kill()
		cmd.Wait()
		return err
	}

	if _, err := ctl.Write(settings); err != nil {
		return stop(err)
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
	if pay != nil {
		go p.servePayments(wk, pay)
	}
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
			wk.cmd.Process.Kill()
			break
		}
	}
	err := wk.cmd.Wait()
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
	if p.cgroups != nil {
		p.cgroups.remove(&wk.user)
	}
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

// enlargeBuffers gives a socket buffers of socketBuffer bytes. Beyond
// net.core.wmem_max and rmem_max, that needs CAP_NET_ADMIN, which root has.
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

// startConfined starts cmd from a thread that first gives up what workers must not
// inherit: capabilities other than those needed to switch to the account (which the
// kernel drops at execve), ambient and inheritable capabilities, and the ability to
// gain privileges by executing files (no_new_privs, which also covers file
// capabilities on the weed binary); and, with rules, confines itself with Landlock.
// These are attributes of threads, so the thread is discarded afterwards rather than
// returned to the Go scheduler.
func startConfined(cmd *exec.Cmd, rules *landlock.Ruleset) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread ends with this goroutine
		errc <- func() error {
			if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil && err != unix.EINVAL {
				return fmt.Errorf("cannot clear ambient capabilities: %w", err)
			}
			hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
			var data [2]unix.CapUserData
			if err := unix.Capget(&hdr, &data[0]); err != nil {
				return fmt.Errorf("cannot read capabilities: %w", err)
			}
			keep := data[0].Permitted & (1<<unix.CAP_SETUID | 1<<unix.CAP_SETGID)
			data[0] = unix.CapUserData{Effective: keep, Permitted: keep}
			data[1] = unix.CapUserData{}
			if err := unix.Capset(&hdr, &data[0]); err != nil {
				return fmt.Errorf("cannot drop capabilities: %w", err)
			}
			if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
				return fmt.Errorf("cannot set no_new_privs: %w", err)
			}
			if rules != nil {
				if err := rules.Restrict(); err != nil {
					return fmt.Errorf("cannot confine the worker with Landlock: %w", err)
				}
			}
			return cmd.Start()
		}()
	}()
	return <-errc
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
