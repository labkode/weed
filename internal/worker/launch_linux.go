package worker

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/fsuser"
	"github.com/labkode/weed/internal/landlock"
	"github.com/labkode/weed/internal/seccomp"
	"golang.org/x/sys/unix"
)

// launcher starts the processes of workers, confined, and kills and reaps them: in
// this process (local), or in the starter, a process of its own that alone has the
// privileges to (see Starter)
type launcher interface {
	// start starts a worker process as u, or as nobody for Pool.Check if check,
	// confined to the exported directory as it now is, with ctl as its control socket
	// and logw as its standard output and error; with cgroups, in the cgroup of u's
	// workers, which gets limits
	start(u *fsuser.User, check bool, ctl, logw *os.File, limits []string) (*process, error)
	// setLimits writes the limits of the cgroup of u's workers again, if u has any
	setLimits(u *fsuser.User, limits []string) error
	// close stops watching the exported directory, and the starter once the workers
	// it started have exited
	close()
}

// process is the process of a worker, as its launcher sees it
type process struct {
	pid  int
	dir  fileID       // the exported directory that it is confined to
	kill func() error // SIGKILL
	// exited is closed once the process has exited, err then says how
	exited chan struct{}
	err    error
}

// errPrivileges is why workers cannot start without the capabilities they need
var errPrivileges = errors.New("weed must run as root, or with the capabilities CAP_SETUID, CAP_SETGID and CAP_KILL (systemd: AmbientCapabilities=)")

// starterCaps are the capabilities that starting workers needs: to switch to their
// accounts, and to kill them
const starterCaps = 1<<unix.CAP_SETUID | 1<<unix.CAP_SETGID | 1<<unix.CAP_KILL

// capabilities are the permitted capabilities of the calling thread
func capabilities() (uint64, error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return 0, fmt.Errorf("cannot read capabilities: %w", err)
	}
	return uint64(data[0].Permitted) | uint64(data[1].Permitted)<<32, nil
}

// privileged says whether this process may start and kill workers (errPrivileges)
func privileged() error {
	have, err := capabilities()
	if err != nil {
		return err
	}
	if have&starterCaps != starterCaps {
		return errPrivileges
	}
	return nil
}

// KeepCapabilities leaves the calling thread, a locked one never given back to Go,
// only those of the capabilities keep (a mask of CAP_*) that it has: in what it
// executes too, as ambient capabilities, whatever its user. It drops the others from
// its bounding set, if it may (root).
func KeepCapabilities(keep uint64) error {
	have, err := capabilities()
	if err != nil {
		return err
	}
	keep &= have
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil && err != unix.EINVAL {
		return fmt.Errorf("cannot clear ambient capabilities: %w", err)
	}
	if have&(1<<unix.CAP_SETPCAP) != 0 {
		for c := uintptr(0); c < 64; c++ {
			if keep&(1<<c) == 0 && unix.Prctl(unix.PR_CAPBSET_DROP, c, 0, 0, 0) == unix.EINVAL {
				break // beyond the last capability of this kernel
			}
		}
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	lo, hi := uint32(keep), uint32(keep>>32)
	data := [2]unix.CapUserData{{Effective: lo, Permitted: lo, Inheritable: lo}, {Effective: hi, Permitted: hi, Inheritable: hi}}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("cannot drop capabilities: %w", err)
	}
	for c := uintptr(0); c < 64; c++ {
		if keep&(1<<c) != 0 {
			if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, c, 0, 0); err != nil {
				return fmt.Errorf("cannot keep capability %d: %w", c, err)
			}
		}
	}
	return nil
}

// HasCapabilities says whether the calling thread has capabilities beyond keep
func HasCapabilities(keep uint64) (uint64, error) {
	have, err := capabilities()
	return have &^ keep, err
}

// local starts workers from this process
type local struct {
	cfg     config.Config // the workers'
	sockets seccomp.Sockets
	cgroups *cgroups // nil: workers stay in this process's cgroup
	conf    *confiner
}

// newLocal prepares to start workers that serve with cfg, in cgroups of their own if
// cgroups, below that of this process, to which it moves the processes pids; onDir
// learns of the exported directory, as watch finds it
func newLocal(cfg config.Config, cgroups bool, pids []int, onDir func(fileID, error)) (*local, error) {
	l := &local{cfg: cfg, sockets: Sockets(&cfg)}
	if cgroups {
		cg, err := newCgroups(pids...)
		if err != nil {
			return nil, err
		}
		l.cgroups = cg
	}
	// Workers are confined with Landlock to the exported directory, and to reading
	// the system's files (see Rules)
	if cfg.Directory == "/" {
		return nil, errors.New("weed does not export /: its workers, confined with Landlock to the exported directory, would reach everything")
	}
	abi := landlock.ABI()
	if abi < landlock.MinABI {
		return nil, fmt.Errorf("weed confines its workers with Landlock, which this kernel does not have (Landlock ABI %d, and %d is needed: Linux 5.19 or later, with landlock in lsm=)",
			abi, landlock.MinABI)
	}
	rules := Rules(&cfg)
	var desc []string
	for _, r := range rules {
		desc = append(desc, r.String())
	}
	nw := landlock.Net{Connect: cfg.TPC}
	tcp := "not confined (Linux 6.7 or later)"
	if abi >= landlock.TCPABI {
		tcp = "no bind, no connect"
		if nw.Connect {
			tcp = "no bind, connect (tpc.enabled)"
		}
	}
	slog.Info("workers are confined with Landlock", "landlock_abi", abi, "rules", desc, "tcp", tcp,
		"sockets", l.sockets.String())
	l.conf = newConfiner(cfg.Directory, rules, nw, onDir)
	return l, nil
}

func (l *local) start(u *fsuser.User, check bool, ctl, logw *os.File, limits []string) (*process, error) {
	rules, dir, err := l.conf.ruleset()
	if err != nil {
		return nil, err
	}
	defer rules.Close()
	// The settings are the worker's file descriptor 4, a pipe written before it starts:
	// what does not fit in the pipe's buffer (64 KiB, 8 KiB once the account of weed
	// has more pipes than fs.pipe-user-pages-soft) is refused rather than waited for
	settings, err := json.Marshal(Settings{User: *u, Config: l.cfg, Cgroup: l.cgroups != nil})
	if err != nil {
		return nil, err
	}
	var pfd [2]int
	if err := unix.Pipe2(pfd[:], unix.O_CLOEXEC); err != nil {
		return nil, err
	}
	sr := os.NewFile(uintptr(pfd[0]), "settings")
	defer sr.Close()
	n, err := 0, unix.SetNonblock(pfd[1], true)
	if err == nil {
		n, err = unix.Write(pfd[1], settings)
	}
	unix.Close(pfd[1])
	if err == nil && n < len(settings) {
		err = unix.EAGAIN
	}
	if err != nil {
		return nil, fmt.Errorf("cannot pass its settings (%d bytes) to the worker of %s: %w", len(settings), u.Name, err)
	}
	groups := make([]uint32, len(u.Groups))
	for i, g := range u.Groups {
		groups[i] = uint32(g)
	}
	cmd := &exec.Cmd{
		// The binary that is running, even if it has since been replaced on disk
		Path:       "/proc/self/exe",
		Args:       []string{"weed", "worker", u.Name},
		Env:        environment(),
		Dir:        "/",
		Stdout:     logw,
		Stderr:     logw,
		ExtraFiles: []*os.File{ctl, sr}, // 3 and 4
		SysProcAttr: &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uint32(u.UID), Gid: uint32(u.GID), Groups: groups},
		},
	}
	if l.cgroups != nil {
		fd, err := l.cgroups.prepare(u, limits)
		if err != nil {
			return nil, err
		}
		defer unix.Close(fd)
		cmd.SysProcAttr.UseCgroupFD = true
		cmd.SysProcAttr.CgroupFD = fd
	}
	if err := startConfined(cmd, rules, l.sockets); err != nil {
		if errors.Is(err, unix.EPERM) {
			err = fmt.Errorf("%w (%w)", err, errPrivileges)
		}
		return nil, err
	}
	p := &process{pid: cmd.Process.Pid, dir: dir, exited: make(chan struct{})}
	p.kill = func() error {
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		return nil
	}
	go func() {
		p.err = cmd.Wait()
		if l.cgroups != nil {
			l.cgroups.remove(u)
		}
		close(p.exited)
	}()
	return p, nil
}

func (l *local) setLimits(u *fsuser.User, limits []string) error {
	if l.cgroups == nil {
		return nil
	}
	return l.cgroups.apply(u, limits)
}

func (l *local) close() { l.conf.close() }

// startConfined starts cmd from a thread that first gives up what workers must not
// inherit: capabilities other than those needed to switch to the account (which the
// kernel drops at execve), ambient and inheritable capabilities, and the ability to
// gain privileges by executing files (no_new_privs, which also covers file
// capabilities on the weed binary); and confines itself with Landlock to rules, and
// with seccomp to the sockets s. These are attributes of threads, so the thread is
// discarded afterwards rather than returned to the Go scheduler.
func startConfined(cmd *exec.Cmd, rules *landlock.Ruleset, s seccomp.Sockets) error {
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
			if err := rules.Restrict(); err != nil {
				return fmt.Errorf("cannot confine the worker with Landlock: %w", err)
			}
			if err := seccomp.Restrict(s); err != nil {
				return fmt.Errorf("cannot confine the worker: %w", err)
			}
			return cmd.Start()
		}()
	}()
	return <-errc
}

// confiner watches the exported directory, and makes the ruleset of Landlock that
// workers start with: again whenever the directory is another than it was, as the
// rules name the directories themselves, and a storage mounted again over the
// exported directory is one that they cannot reach. It alone touches the exported
// directory, so that only it waits if the storage does not answer, not the starts of
// workers.
type confiner struct {
	dir   string
	rules []landlock.Rule // the exported directory first (see Rules)
	nw    landlock.Net
	onDir func(fileID, error)
	done  chan struct{}

	mu      sync.Mutex
	current *confinement // once the exported directory has answered
	err     error        // why workers cannot be confined, if they cannot
	storage fileID       // the exported directory when it was last on a storage of its own
}

// confinement is the ruleset of Landlock that workers start with, of the exported
// directory as it was when it was made
type confinement struct {
	dir   fileID
	rules *landlock.Ruleset
}

// newConfiner looks at the exported directory, waiting for the first look for some
// time, and every dirCheckInterval after that, until close. onDir learns, after each
// look, of the exported directory that workers start confined to, or why they
// cannot start.
func newConfiner(dir string, rules []landlock.Rule, nw landlock.Net, onDir func(fileID, error)) *confiner {
	c := &confiner{dir: dir, rules: rules, nw: nw, onDir: onDir, done: make(chan struct{})}
	first := make(chan struct{})
	go c.watch(first)
	select {
	case <-first:
	case <-time.After(10 * time.Second):
		slog.Warn("the exported directory does not answer: workers, confined to it with Landlock, start once it does", "dir", dir)
	}
	return c
}

// dirCheckInterval is how often the exported directory is looked at (a variable for
// tests)
var dirCheckInterval = 5 * time.Second

// watch looks at the exported directory until close; first is closed after the
// first look
func (c *confiner) watch(first chan<- struct{}) {
	t := time.NewTicker(dirCheckInterval)
	defer t.Stop()
	for {
		c.check()
		if first != nil {
			close(first)
			first = nil
		}
		select {
		case <-t.C:
		case <-c.done:
			c.mu.Lock()
			if c.current != nil {
				c.current.rules.Close()
				c.current = nil
			}
			c.mu.Unlock()
			return
		}
	}
}

func (c *confiner) close() { close(c.done) }

func (c *confiner) check() {
	id, err := identify(unix.AT_FDCWD, c.dir)
	c.mu.Lock()
	cur := c.current
	c.mu.Unlock()
	// Gone, as when the storage mounted above it is no longer
	gone := errors.Is(err, unix.ENOENT) && cur != nil && cur.dir != (fileID{})
	if cur == nil || err == nil && id != cur.dir || gone {
		next, err := c.confine()
		c.mu.Lock()
		c.err = err
		if c.current != nil {
			c.current.rules.Close() // workers that started with it have a copy
		}
		c.current = next
		c.mu.Unlock()
	}
	c.mu.Lock()
	dir, err := fileID{}, c.err
	if c.current != nil {
		dir = c.current.dir
	}
	c.mu.Unlock()
	c.onDir(dir, err)
}

// confine makes the ruleset of workers, with the exported directory as it now is (or
// without it, if it cannot be opened)
func (c *confiner) confine() (*confinement, error) {
	next := &confinement{}
	rules := slices.Clone(c.rules)
	fd, err := unix.Open(rules[0].Path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		rules = rules[1:]
	} else {
		f := os.NewFile(uintptr(fd), rules[0].Path)
		defer f.Close()
		next.dir, _ = identify(fd, "")
		rules[0].File = f
	}
	// Once the directory has been on a storage of its own, at startup or mounted
	// since, it is not served from the file system of / again
	root, rootErr := identify(unix.AT_FDCWD, "/")
	c.mu.Lock()
	storage := c.storage
	if rootErr == nil && next.dir != (fileID{}) && next.dir.dev != root.dev {
		c.storage = next.dir
	}
	c.mu.Unlock()
	if rootErr == nil && unmounted(storage, next.dir, root) {
		return nil, &UnmountedError{Dir: c.dir}
	}
	if next.rules, err = landlock.New(rules, c.nw); err != nil {
		return nil, err
	}
	path, err := next.rules.Unreachable(c.dir, "/proc/self/exe")
	if err == nil && path != "" {
		if exe, err := os.Readlink(path); err == nil && path == "/proc/self/exe" {
			path = "weed's executable, " + exe + ","
		}
		err = fmt.Errorf("confined with Landlock, workers could not open %s which weed opens without: it is on a file system that Landlock cannot follow (such as Docker Desktop's mounts of the host): move it", path)
	}
	if err != nil {
		next.rules.Close()
		return nil, err
	}
	return next, nil
}

// ruleset is a copy of the ruleset that workers start with now, and the exported
// directory that it names, or why workers cannot start
func (c *confiner) ruleset() (*landlock.Ruleset, fileID, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current == nil && c.err != nil {
		var unmounted *UnmountedError
		if errors.As(c.err, &unmounted) {
			return nil, fileID{}, c.err
		}
		return nil, fileID{}, fmt.Errorf("cannot confine the worker with Landlock: %w", c.err)
	}
	if c.current == nil {
		return nil, fileID{}, errors.New("the exported directory has not answered yet, and workers are confined to it with Landlock")
	}
	rules, err := c.current.rules.Dup()
	if err != nil {
		return nil, fileID{}, fmt.Errorf("cannot confine the worker with Landlock: %w", err)
	}
	return rules, c.current.dir, nil
}
