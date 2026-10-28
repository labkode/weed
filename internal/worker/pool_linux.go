package worker

import (
	"bufio"
	"bytes"
	"context"
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
	"runtime"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/fsuser"
	"github.com/labkode/weed/internal/logger"
	"github.com/labkode/weed/internal/metrics"
	"golang.org/x/sys/unix"
)

const (
	// startTimeout bounds how long a new worker may take to report that it is ready
	startTimeout = 10 * time.Second
	// maxMessage bounds the messages on control sockets
	maxMessage = 64 << 10
)

// Options configure a Pool
type Options struct {
	// Config is what workers serve with; it must not hold credentials
	Config config.Config
	// IdleTimeout stops a worker that has served no request for this long
	IdleTimeout time.Duration
	// MaxWorkers bounds the number of workers that take requests
	MaxWorkers int
	// Cgroups gives each worker a cgroup of its own, below weed's, which must have
	// been delegated to weed (e.g. by systemd's Delegate=yes)
	Cgroups bool
	// CgroupLimits are written to the cgroup of each worker: file=value, e.g.
	// memory.max=4G (implies Cgroups)
	CgroupLimits []string
}

// Pool runs the workers of the front process: one per account that is in use
type Pool struct {
	opts    Options
	cgroups *cgroups // nil: workers stay in weed's cgroup

	mu      sync.Mutex
	workers map[string]*worker // by account name: the workers taking new requests
	all     map[*worker]bool   // every worker until it has exited, retired ones included
	closed  bool
	done    chan struct{} // closed by Close
}

// worker is one worker process, as seen from the front process
type worker struct {
	user   fsuser.User
	ready  chan struct{} // closed once started, or once that failed (err)
	err    error
	exited chan struct{} // closed once the process has exited (or never started)

	pid       int
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
	if opts.Cgroups || len(opts.CgroupLimits) > 0 {
		cg, err := newCgroups(opts.CgroupLimits)
		if err != nil {
			return nil, err
		}
		p.cgroups = cg
	}
	go p.reap()
	return p, nil
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

// retireIdlestLocked retires the worker that has been idle the longest, if any is
func (p *Pool) retireIdlestLocked() bool {
	var idlest *worker
	for _, wk := range p.workers {
		if wk.active == 0 && (idlest == nil || wk.lastUsed.Before(idlest.lastUsed)) {
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

// reap retires the workers that have been idle for IdleTimeout
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
				slog.Info("stopping an idle worker", "worker", wk)
				p.retireLocked(wk)
			}
		}
		p.mu.Unlock()
	}
}

// Reload makes the running workers re-read what they read at startup (the CAs of
// TPC endpoints); those that are starting read it anyway
func (p *Pool) Reload() {
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
	for _, wk := range running {
		wk.ctl.Write([]byte{msgReload})
	}
}

// Close stops every worker: they get until ctx is done to finish their requests,
// and are killed then
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
	for _, wk := range all {
		select {
		case <-wk.exited:
		case <-ctx.Done():
			<-wk.ready
			if wk.err == nil {
				slog.Warn("killing a worker that did not stop in time", "worker", wk)
				wk.cmd.Process.Kill()
			}
			<-wk.exited
		}
	}
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
	settings, err := json.Marshal(Settings{User: wk.user, Config: p.opts.Config})
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
		ExtraFiles: []*os.File{child}, // file descriptor 3
		SysProcAttr: &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uint32(wk.user.UID), Gid: uint32(wk.user.GID), Groups: groups},
		},
	}
	if p.cgroups != nil {
		fd, err := p.cgroups.prepare(&wk.user)
		if err != nil {
			logs.Close()
			return err
		}
		defer unix.Close(fd)
		cmd.SysProcAttr.UseCgroupFD = true
		cmd.SysProcAttr.CgroupFD = fd
	}
	if err := startConfined(cmd); err != nil {
		logs.Close()
		if errors.Is(err, unix.EPERM) {
			err = fmt.Errorf("%w (weed must run as root, or with CAP_SETUID and CAP_SETGID)", err)
		}
		return err
	}
	wk.cmd, wk.pid = cmd, cmd.Process.Pid
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
	switch {
	case errors.Is(err, io.EOF):
		return stop(errors.New("the worker exited during startup"))
	case err != nil:
		return stop(err)
	case string(buf[:n]) != "ready":
		return stop(errors.New(string(buf[:n]))) // why the worker refuses to serve
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
	expected := wk.closing || p.closed
	if p.workers[wk.user.Name] == wk {
		delete(p.workers, wk.user.Name)
	}
	delete(p.all, wk)
	p.mu.Unlock()
	if p.cgroups != nil {
		p.cgroups.remove(&wk.user)
	}
	if expected && err == nil {
		slog.Info("worker stopped", "worker", wk)
		metrics.WorkerExits.Inc("stopped")
	} else {
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
// with the default (about 200 KiB), relaying a download costs a third of its throughput
const socketBuffer = 4 << 20

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
// capabilities on the weed binary). These are attributes of threads, so the thread is
// discarded afterwards rather than returned to the Go scheduler.
func startConfined(cmd *exec.Cmd) error {
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
