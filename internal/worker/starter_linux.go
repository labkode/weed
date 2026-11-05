package worker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/fsuser"
	"github.com/labkode/weed/internal/limits"
	"github.com/labkode/weed/internal/logger"
	"github.com/labkode/weed/internal/seccomp"
	"golang.org/x/sys/unix"
)

// The starter is the process that starts the workers, as their accounts, confined,
// and kills and reaps them: "weed starter", which the front process starts before it
// confines itself and gives up its capabilities. It alone keeps those that this
// needs, CAP_SETUID, CAP_SETGID and CAP_KILL (root's, otherwise), and it decides
// what a worker is: it reads weed's configuration itself, looks the accounts up
// itself, refuses root, and makes the confinement of workers itself. The front
// process, which terminates TLS and authenticates requests, has no capabilities, and
// may only ask it for the worker of an account, and to kill workers.
//
// They talk over a SOCK_SEQPACKET socket: a JSON object per message (see message),
// and with "start", the worker's control socket and the write end of its log, as
// file descriptors. The starter is not confined with Landlock: its workers, which
// inherit its confinement, would not reach a storage mounted again at the exported
// directory. It opens the sockets of its workers alone (seccomp), and executes
// nothing but them.

// starterEnv passes the front process's end of the socket to the starter, and the
// starter's pid, to weed executed again (see StarterFromEnv): "fd pid"
const starterEnv = "WEED_STARTER"

// message is one between the front process and the starter. Op is one of:
//
//   - ready (starter): it has started, and looked at the exported directory once;
//     SHA256 of the configuration it read, and whether its workers have cgroups
//     (Cgroups), or Error, why it cannot start workers
//   - start (front): a worker of User (nobody if Check), with Limits for its cgroup,
//     and two file descriptors: its control socket, and the write end of its log
//   - started (starter): the worker of start ID, PID, confined to Dir; or Error
//   - kill (front): SIGKILL to the worker PID
//   - limits (front, then starter): write Limits to the cgroup of User's workers
//   - exited (starter): the worker PID has exited, Error saying how if it failed
//   - dir (starter): the exported directory that workers now start confined to, or
//     why they cannot start (Error, Unmounted)
//   - log (starter): a log record of the starter
type message struct {
	Op     string       `json:"op"`
	ID     uint64       `json:"id,omitempty"`
	User   *fsuser.User `json:"user,omitempty"`
	Check  bool         `json:"check,omitempty"`
	Limits []string     `json:"limits,omitempty"`
	PID    int          `json:"pid,omitempty"`
	Dir    [3]uint64    `json:"dir,omitzero"`
	Error  string       `json:"error,omitempty"`
	// Unmounted is the exported directory, when Error is an UnmountedError
	Unmounted string          `json:"unmounted,omitempty"`
	SHA256    string          `json:"sha256,omitempty"`
	Cgroups   bool            `json:"cgroups,omitempty"`
	Record    json.RawMessage `json:"record,omitempty"`
}

func (m *message) setErr(err error) {
	if err == nil {
		return
	}
	m.Error = err.Error()
	var u *UnmountedError
	if errors.As(err, &u) {
		m.Unmounted = u.Dir
	}
}

func (m *message) err() error {
	if m.Unmounted != "" {
		return &UnmountedError{Dir: m.Unmounted}
	}
	if m.Error != "" {
		return errors.New(m.Error)
	}
	return nil
}

func wireDir(d fileID) [3]uint64 { return [3]uint64{d.dev, d.ino, d.mnt} }
func dirOf(w [3]uint64) fileID   { return fileID{w[0], w[1], w[2]} }

// starterBuffer bounds the messages from the starter (log records, mostly)
const starterBuffer = 256 << 10

// send sends m over conn, with fds, as one message
func send(conn *net.UnixConn, mu *sync.Mutex, m message, fds ...int) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	var oob []byte
	if len(fds) > 0 {
		oob = unix.UnixRights(fds...)
	}
	mu.Lock()
	defer mu.Unlock()
	_, _, err = conn.WriteMsgUnix(b, oob, nil)
	return err
}

// LaunchStarter starts the starter, "weed starter args...", with of this process's
// capabilities CAP_SETUID, CAP_SETGID and CAP_KILL alone, no_new_privs, and the
// sockets s alone (seccomp): those of its workers, which it cannot give more. It
// returns the variable of the environment that passes the socket to it, and its pid,
// on to weed executed again (see StarterFromEnv); the socket is not closed on exec.
func LaunchStarter(args []string, s seccomp.Sockets) (string, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	child := os.NewFile(uintptr(fds[1]), "front")
	defer child.Close()
	var env []string
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "WEED_") {
			env = append(env, e)
		}
	}
	cmd := &exec.Cmd{
		Path: "/proc/self/exe",
		Args: append([]string{"weed", "starter"}, args...),
		Env:  env,
		// In this process's working directory, as weed reads its configuration: the
		// starter goes to / once it has (see RunStarter)
		Stderr:     os.Stderr, // what the Go runtime writes; log records go over the socket
		ExtraFiles: []*os.File{child},
	}
	// The starter inherits no other file of this process: not the sockets that
	// systemd passed (socket activation), which weed keeps as it executes itself again
	inherited := inheritedFDs()
	for _, fd := range inherited {
		unix.CloseOnExec(fd)
	}
	defer func() {
		for _, fd := range inherited {
			unix.FcntlInt(uintptr(fd), unix.F_SETFD, 0)
		}
	}()
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread ends with this goroutine
		errc <- func() error {
			if err := KeepCapabilities(starterCaps); err != nil {
				return err
			}
			if err := seccomp.Restrict(s); err != nil {
				return err
			}
			return cmd.Start()
		}()
	}()
	if err := <-errc; err != nil {
		unix.Close(fds[0])
		return "", fmt.Errorf("cannot start the starter of workers: %w", err)
	}
	if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_SETFD, 0); err != nil {
		unix.Close(fds[0])
		cmd.Process.Kill()
		return "", err
	}
	return fmt.Sprintf("%s=%d %d", starterEnv, fds[0], cmd.Process.Pid), nil
}

// inheritedFDs are the file descriptors of this process beyond 0, 1 and 2 that are
// not closed on exec
func inheritedFDs() []int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil
	}
	var fds []int
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil || fd < 3 {
			continue
		}
		if flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil && flags&unix.FD_CLOEXEC == 0 {
			fds = append(fds, fd)
		}
	}
	return fds
}

// Starter is the front process's end of the starter
type Starter struct {
	conn *net.UnixConn
	pid  int // 0: not this process's child
	wmu  sync.Mutex

	mu      sync.Mutex
	nextID  uint64
	pending map[uint64]chan reply
	procs   map[int]*process // started, until they have exited
	gone    error            // once the starter has gone
	closing bool             // see close
	onDir   func(fileID, error)
	lost    func(error)
	ready   chan message
}

type reply struct {
	m message
	p *process // started
}

// StarterFromEnv is the starter that LaunchStarter started, if it did; it removes it
// from the environment
func StarterFromEnv() (*Starter, error) {
	v, ok := os.LookupEnv(starterEnv)
	os.Unsetenv(starterEnv)
	if !ok {
		return nil, nil
	}
	f, p, _ := strings.Cut(v, " ")
	fd, err1 := strconv.Atoi(f)
	pid, err2 := strconv.Atoi(p)
	if err := errors.Join(err1, err2); err != nil {
		return nil, fmt.Errorf("invalid %s: %q", starterEnv, v)
	}
	unix.CloseOnExec(fd)
	return NewStarter(os.NewFile(uintptr(fd), "starter"), pid)
}

// NewStarter is the starter at the other end of f, a SOCK_SEQPACKET socket, whose
// process is the child pid of this one (0: not a child)
func NewStarter(f *os.File, pid int) (*Starter, error) {
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return nil, err
	}
	conn, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, errors.New("the starter's socket is not a Unix socket")
	}
	return &Starter{conn: conn, pid: pid, pending: make(map[uint64]chan reply), procs: make(map[int]*process),
		ready: make(chan message, 1)}, nil
}

// attach reads from the starter from now on, and waits until it is ready: onDir
// learns of the exported directory, and lost that the starter has gone
func (s *Starter) attach(onDir func(fileID, error), lost func(error)) (sha256 string, cgroups bool, err error) {
	s.mu.Lock()
	s.onDir, s.lost = onDir, lost
	s.mu.Unlock()
	go s.read()
	select {
	case m := <-s.ready:
		return m.SHA256, m.Cgroups, m.err()
	case <-time.After(time.Minute):
		return "", false, errors.New("the starter of workers did not answer")
	}
}

func (s *Starter) read() {
	buf := make([]byte, starterBuffer)
	for {
		n, _, _, _, err := s.conn.ReadMsgUnix(buf, nil)
		if err == nil && n == 0 {
			err = io.EOF
		}
		if err != nil {
			s.fail(fmt.Errorf("the starter of workers has exited: %w", err))
			return
		}
		var m message
		if err := json.Unmarshal(buf[:n], &m); err != nil {
			slog.Error("invalid message from the starter of workers", "error", err)
			continue
		}
		switch m.Op {
		case "ready":
			s.ready <- m
		case "log":
			logger.Relay(m.Record, slog.String("process", "starter"))
		case "dir":
			s.onDir(dirOf(m.Dir), m.err())
		case "started":
			var p *process
			s.mu.Lock()
			ch := s.pending[m.ID]
			delete(s.pending, m.ID)
			if m.Error == "" {
				pid := m.PID
				p = &process{pid: pid, dir: dirOf(m.Dir), exited: make(chan struct{}),
					kill: func() error { return s.send(message{Op: "kill", PID: pid}) }}
				s.procs[pid] = p
			}
			if ch != nil {
				ch <- reply{m, p} // under s.mu, as request forgets: it is answered, or not waited for
			}
			s.mu.Unlock()
			if ch == nil && p != nil {
				p.kill() // whoever asked for it no longer waits
			}
		case "limits":
			s.mu.Lock()
			if ch := s.pending[m.ID]; ch != nil {
				ch <- reply{m: m}
			}
			delete(s.pending, m.ID)
			s.mu.Unlock()
		case "exited":
			s.mu.Lock()
			p := s.procs[m.PID]
			delete(s.procs, m.PID)
			s.mu.Unlock()
			if p != nil {
				p.err = m.err()
				close(p.exited)
			}
		default:
			slog.Error("unknown message from the starter of workers", "op", m.Op)
		}
	}
}

// fail is called once the starter has gone: what waits for it gets err
func (s *Starter) fail(err error) {
	s.mu.Lock()
	s.gone = err
	pending, procs, closing, lost := s.pending, s.procs, s.closing, s.lost
	s.pending, s.procs = make(map[uint64]chan reply), make(map[int]*process)
	s.mu.Unlock()
	switch {
	case s.pid > 0 && closing:
		go unix.Wait4(s.pid, nil, 0, nil) // once its workers have exited
	case s.pid > 0:
		// It has exited, as its end of the socket closed
		var ws unix.WaitStatus
		if _, werr := unix.Wait4(s.pid, &ws, 0, nil); werr == nil && (ws.Exited() && ws.ExitStatus() != 0 || ws.Signaled()) {
			err = fmt.Errorf("%w (%s)", err, describeWait(ws))
		}
	}
	m := message{}
	m.setErr(err)
	select {
	case s.ready <- m:
	default:
	}
	for _, ch := range pending {
		ch <- reply{m: m}
	}
	for _, p := range procs {
		p.err = err
		close(p.exited)
	}
	if !closing && lost != nil {
		lost(err)
	}
}

func describeWait(ws unix.WaitStatus) string {
	if ws.Signaled() {
		return "killed by signal " + ws.Signal().String()
	}
	return "exit status " + strconv.Itoa(ws.ExitStatus())
}

func (s *Starter) send(m message, fds ...int) error { return send(s.conn, &s.wmu, m, fds...) }

// request sends m, and waits for the reply to it
func (s *Starter) request(m message, fds ...int) (reply, error) {
	ch := make(chan reply, 1)
	s.mu.Lock()
	if s.gone != nil {
		err := s.gone
		s.mu.Unlock()
		return reply{}, err
	}
	s.nextID++
	m.ID = s.nextID
	s.pending[m.ID] = ch
	s.mu.Unlock()
	forget := func() {
		s.mu.Lock()
		delete(s.pending, m.ID)
		s.mu.Unlock()
	}
	if err := s.send(m, fds...); err != nil {
		forget()
		return reply{}, fmt.Errorf("cannot reach the starter of workers: %w", err)
	}
	select {
	case r := <-ch:
		return r, r.m.err()
	case <-time.After(time.Minute):
		forget()
		// The answer may have come as the wait ended: once forgotten, none comes
		select {
		case r := <-ch:
			return r, r.m.err()
		default:
		}
		return reply{}, errors.New("the starter of workers did not answer")
	}
}

func (s *Starter) start(u *fsuser.User, check bool, ctl, logw *os.File, limits []string) (*process, error) {
	r, err := s.request(message{Op: "start", User: u, Check: check, Limits: limits}, int(ctl.Fd()), int(logw.Fd()))
	if err != nil {
		return nil, err
	}
	return r.p, nil
}

func (s *Starter) setLimits(u *fsuser.User, limits []string) error {
	_, err := s.request(message{Op: "limits", User: u, Limits: limits})
	return err
}

// close closes the socket: the starter stops once the workers it started have exited
func (s *Starter) close() {
	s.mu.Lock()
	s.closing = true
	s.mu.Unlock()
	s.conn.Close()
}

// StarterOptions configure the starter (see StarterConn.Serve)
type StarterOptions struct {
	// Config is what workers serve with, which holds no credentials
	Config config.Config
	// Cgroups gives the workers of each account a cgroup of their own (see
	// Options.Cgroups), next to which the starter moves itself, and Front
	Cgroups bool
	Front   int // the pid of the front process, 0 if none: the starter's parent (see StarterConn.Front)
	// SHA256 is that of weed's configuration, which the front process compares with
	// that of the configuration it read
	SHA256 string
	// Lookup finds accounts (fsuser.Lookup if nil)
	Lookup func(name string) (*fsuser.User, error)
}

// StarterConn is the starter's end of its socket to the front process
type StarterConn struct {
	conn  *net.UnixConn
	wmu   sync.Mutex
	front int
}

// Front is the pid of the front process, which made the socket (0: unknown)
func (sc *StarterConn) Front() int { return sc.front }

// AttachStarter takes over the socket that the front process passed as file
// descriptor 3, and logs over it, at level
func AttachStarter(level *slog.LevelVar) (*StarterConn, error) {
	f := os.NewFile(3, "front")
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("weed starter is started by weed, not by hand: %w", err)
	}
	conn, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, errors.New("weed starter is started by weed, not by hand")
	}
	sc := NewStarterConn(conn)
	// Who made the socket: the front process, even once it has exited
	if raw, err := conn.SyscallConn(); err == nil {
		raw.Control(func(fd uintptr) {
			if cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); err == nil {
				sc.front = int(cred.Pid)
			}
		})
	}
	slog.SetDefault(slog.New(logger.NewHandler(starterLog{sc}, logger.FormatJSON, level)))
	return sc, nil
}

// NewStarterConn is the starter at conn
func NewStarterConn(conn *net.UnixConn) *StarterConn { return &StarterConn{conn: conn} }

// starterLog sends the log records written to it to the front process
type starterLog struct{ sc *StarterConn }

func (l starterLog) Write(p []byte) (int, error) {
	rec := bytes.TrimRight(p, "\n")
	if !json.Valid(rec) {
		rec, _ = json.Marshal(string(rec))
	}
	l.sc.send(message{Op: "log", Record: rec})
	return len(p), nil
}

func (sc *StarterConn) send(m message, fds ...int) error { return send(sc.conn, &sc.wmu, m, fds...) }

// ErrReported is in the errors of Fail, and so of Serve, once the front process has
// them: weed logs them, and the starter need not say them again
var ErrReported = errors.New("weed has the starter's error")

// Fail tells the front process why the starter cannot start workers, and returns err,
// with ErrReported if the front has it
func (sc *StarterConn) Fail(err error) error {
	m := message{Op: "ready"}
	m.setErr(err)
	if sc.send(m) == nil {
		return fmt.Errorf("%w: %w", ErrReported, err)
	}
	return err
}

// starter serves the front process
type starter struct {
	sc     *StarterConn
	l      *local
	lookup func(name string) (*fsuser.User, error)

	mu    sync.Mutex
	procs map[int]*child // started, until they have exited
}

type child struct {
	p    *process
	user fsuser.User
}

// Serve starts the workers that the front process asks for until it closes the
// socket, or exits; then it waits for the workers to exit, as their control sockets
// have closed too, and kills those still running after shutdownGrace
func (sc *StarterConn) Serve(opts StarterOptions) error {
	if err := privileged(); err != nil {
		return sc.Fail(err)
	}
	s := &starter{sc: sc, lookup: opts.Lookup, procs: make(map[int]*child)}
	if s.lookup == nil {
		s.lookup = fsuser.Lookup
	}
	pids := []int{os.Getpid()}
	if opts.Front > 0 {
		// Moved to weed's cgroup: unless it has exited, and another is the parent
		if os.Getppid() != opts.Front {
			return sc.Fail(errors.New("weed, which started the starter of workers, has exited"))
		}
		pids = append(pids, opts.Front)
	}
	l, err := newLocal(opts.Config, opts.Cgroups, pids, func(dir fileID, err error) {
		m := message{Op: "dir", Dir: wireDir(dir)}
		m.setErr(err)
		sc.send(m)
	})
	if err != nil {
		return sc.Fail(err)
	}
	s.l = l
	defer l.close()
	if err := sc.send(message{Op: "ready", SHA256: opts.SHA256, Cgroups: opts.Cgroups}); err != nil {
		return err
	}

	buf := make([]byte, maxMessage)
	oob := make([]byte, unix.CmsgSpace(2*4))
	for {
		n, oobn, _, _, err := sc.conn.ReadMsgUnix(buf, oob)
		if err != nil || n == 0 && oobn == 0 {
			break
		}
		var fds []int
		if msgs, err := unix.ParseSocketControlMessage(oob[:oobn]); err == nil {
			for _, msg := range msgs {
				if f, err := unix.ParseUnixRights(&msg); err == nil {
					fds = append(fds, f...)
				}
			}
		}
		var m message
		if err := json.Unmarshal(buf[:n], &m); err != nil {
			slog.Error("invalid message from the front process", "error", err)
			closeFDs(fds)
			continue
		}
		switch m.Op {
		case "start":
			go s.start(m, fds)
			continue
		case "kill":
			s.kill(m.PID)
		case "limits":
			go s.limits(m)
		default:
			slog.Error("unknown message from the front process", "op", m.Op)
		}
		closeFDs(fds)
	}
	s.shutdown()
	return nil
}

func closeFDs(fds []int) {
	for _, fd := range fds {
		unix.Close(fd)
	}
}

func (s *starter) send(m message) { s.sc.send(m) }

// start starts the worker that m asks for, with fds its control socket and the write
// end of its log
func (s *starter) start(m message, fds []int) {
	var files []*os.File
	for _, fd := range fds {
		files = append(files, os.NewFile(uintptr(fd), "worker"))
	}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	r := message{Op: "started", ID: m.ID}
	u, err := s.account(&m)
	if err == nil && len(files) != 2 {
		err = fmt.Errorf("a worker needs 2 file descriptors, not %d", len(files))
	}
	if err == nil {
		err = checkFDs(int(files[0].Fd()), int(files[1].Fd()))
	}
	for _, l := range m.Limits {
		if err == nil {
			err = limits.CheckCgroupLimit(l)
		}
	}
	var p *process
	if err == nil {
		p, err = s.l.start(u, m.Check, files[0], files[1], m.Limits)
	}
	if err != nil {
		r.setErr(err)
		s.send(r)
		return
	}
	s.mu.Lock()
	s.procs[p.pid] = &child{p, *u}
	s.mu.Unlock()
	r.PID, r.Dir = p.pid, wireDir(p.dir)
	s.send(r) // before exited
	go func() {
		<-p.exited
		s.mu.Lock()
		delete(s.procs, p.pid)
		s.mu.Unlock()
		e := message{Op: "exited", PID: p.pid}
		e.setErr(p.err)
		s.send(e)
	}()
}

// nobody is the account of the worker of Pool.Check
var nobody = fsuser.User{Name: "nobody", UID: 65534, GID: 65534, Groups: []int{65534}}

// account is the account that m asks for a worker of, as the system has it: which
// must be what the front process has (its cache of accounts), and not root
func (s *starter) account(m *message) (*fsuser.User, error) {
	if m.Check {
		u := nobody
		return &u, nil
	}
	if m.User == nil || m.User.Name == "" {
		return nil, errors.New("no account")
	}
	u, err := s.lookup(m.User.Name)
	if err != nil {
		return nil, fmt.Errorf("cannot find account %s: %w", m.User.Name, err)
	}
	if u.UID == 0 {
		return nil, fmt.Errorf("account %s is the superuser", u.Name)
	}
	if !sameAccount(u, m.User) {
		return nil, fmt.Errorf("account %s is %v on this system, not %v as weed has it: systemctl reload weed looks it up again", u.Name, u, m.User)
	}
	return u, nil
}

// checkFDs checks that ctl is a socket, and logw a pipe
func checkFDs(ctl, logw int) error {
	var st unix.Stat_t
	if err := unix.Fstat(ctl, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return errors.New("the control socket of a worker is not a socket")
	}
	if err := unix.Fstat(logw, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO {
		return errors.New("the log of a worker is not a pipe")
	}
	return nil
}

// kill kills the worker pid, if it is one that it started
func (s *starter) kill(pid int) {
	s.mu.Lock()
	c := s.procs[pid]
	s.mu.Unlock()
	if c == nil {
		return
	}
	if err := c.p.kill(); err != nil {
		slog.Error("cannot kill a worker", "worker", slog.GroupValue(slog.String("user", c.user.Name), slog.Int("pid", pid)), "error", err)
	}
}

// limits writes the cgroup limits of an account that has workers
func (s *starter) limits(m message) {
	r := message{Op: "limits", ID: m.ID}
	var err error
	for _, l := range m.Limits {
		if err == nil {
			err = limits.CheckCgroupLimit(l)
		}
	}
	var u *fsuser.User
	s.mu.Lock()
	for _, c := range s.procs {
		if m.User != nil && c.user.Name == m.User.Name {
			u = &c.user
		}
	}
	s.mu.Unlock()
	if err == nil && u != nil {
		err = s.l.setLimits(u, m.Limits)
	}
	r.setErr(err)
	s.send(r)
}

// shutdown waits for the workers to exit, and kills those still running after
// shutdownGrace
func (s *starter) shutdown() {
	deadline := time.After(shutdownGrace + 5*time.Second)
	for {
		s.mu.Lock()
		var left []*child
		for _, c := range s.procs {
			left = append(left, c)
		}
		s.mu.Unlock()
		if len(left) == 0 {
			return
		}
		select {
		case <-left[0].p.exited:
		case <-deadline:
			for _, c := range left {
				slog.Warn("killing a worker that did not stop in time", "worker", slog.GroupValue(slog.String("user", c.user.Name), slog.Int("pid", c.p.pid)))
				c.p.kill()
			}
			wait := time.After(killWait)
			for _, c := range left {
				select {
				case <-c.p.exited:
				case <-wait:
					return
				}
			}
			return
		}
	}
}

// CheckStarter checks that this process, the starter, has what LaunchStarter gave
// it: the capabilities to start and kill workers and no others, no_new_privs, and
// only the sockets s
func CheckStarter(s seccomp.Sockets) error {
	if err := privileged(); err != nil {
		return err
	}
	if more, err := HasCapabilities(starterCaps); err != nil || more != 0 {
		return fmt.Errorf("the starter of workers has capabilities beyond CAP_SETUID, CAP_SETGID and CAP_KILL (%#x)", more)
	}
	if v, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0); err != nil || v != 1 {
		return errors.New("the starter of workers was started to have no_new_privs, and has not")
	}
	if !seccomp.Filtered(s) {
		return fmt.Errorf("the starter of workers was started to open %s sockets alone (seccomp), and opens others", s)
	}
	return nil
}
