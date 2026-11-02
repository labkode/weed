package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/labkode/weed/internal/fsuser"
	"github.com/labkode/weed/internal/logger"
	"github.com/labkode/weed/internal/metrics"
	"github.com/labkode/weed/internal/seccomp"
	"github.com/labkode/weed/internal/version"
	"golang.org/x/sys/unix"
)

// shutdownGrace is how long requests in progress get when a worker is terminated
const shutdownGrace = 30 * time.Second

// Workers are started as /proc/self/exe, which would make their name "exe". It is
// that of the main thread, on which init functions run (and Landlock may keep them
// from writing /proc/self/comm).
func init() {
	if len(os.Args) > 1 && os.Args[1] == "worker" {
		if name, err := unix.BytePtrFromString("weed"); err == nil {
			unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(name)), 0, 0, 0)
		}
	}
}

// Child is a worker process, as seen from itself
type Child struct {
	Settings Settings
	ctl      *net.UnixConn
	build    string // of its executable (see version.Build)
}

// Attach takes over the control socket that the front process passed as file
// descriptor 3, reads the settings and checks that every thread of the process runs
// as the account and with no privileges
func Attach() (*Child, error) {
	f := os.NewFile(3, "control")
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("weed worker is started by weed, not by hand: %w", err)
	}
	ctl, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, errors.New("weed worker is started by weed, not by hand")
	}
	buf := make([]byte, maxMessage)
	n, err := ctl.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("cannot read the settings: %w", err)
	}
	child := &Child{ctl: ctl}
	if err := json.Unmarshal(buf[:n], &child.Settings); err != nil {
		return nil, child.Fail(fmt.Errorf("invalid settings: %w", err))
	}
	if err := checkConfinement(&child.Settings.User); err != nil {
		return nil, child.Fail(fmt.Errorf("refusing to serve: %w", err))
	}
	// Confined with Landlock, it cannot list /
	if f, err := os.Open("/"); err == nil {
		f.Close()
		return nil, child.Fail(errors.New("refusing to serve: started to be confined with Landlock, and is not"))
	}
	// Nor may it open other sockets than its own (see sockets)
	if s := sockets(&child.Settings.Config); !seccomp.Filtered(s) {
		return nil, child.Fail(fmt.Errorf("refusing to serve: started to open %s sockets alone (seccomp), and opens others", s))
	}
	// Workers are started from /proc/self/exe: the front process's binary, unless it
	// was overwritten in place, which the front process detects from the build
	if child.build, err = version.ExecutableBuild(); err != nil {
		return nil, child.Fail(fmt.Errorf("cannot identify the build of its executable: %w", err))
	}
	if child.Settings.Cgroup {
		limitMemory()
	}
	return child, nil
}

// limitMemory sets the Go runtime's memory limit to 90% of the lower of the cgroup's
// memory.max and memory.high, so that the garbage collector works harder before the
// kernel reclaims the worker's memory or kills it. GOMEMLIMIT, if set, prevails.
func limitMemory() {
	if _, ok := os.LookupEnv("GOMEMLIMIT"); ok {
		return
	}
	limit, err := cgroupMemoryLimit()
	if err != nil {
		slog.Warn("cannot read the memory limits of the worker's cgroup", "error", err)
		return
	}
	goLimit := int64(math.MaxInt64) // none, as without GOMEMLIMIT
	if limit > 0 {
		goLimit = limit / 10 * 9
	}
	if prev := debug.SetMemoryLimit(goLimit); prev != goLimit {
		if limit > 0 {
			slog.Info("set the Go memory limit from the cgroup's", "cgroup_memory_limit", limit, "go_memory_limit", goLimit)
		} else {
			slog.Info("the cgroup has no memory limit, nor has Go")
		}
	}
}

// cgroupMemoryLimit is the lower of memory.max and memory.high of the process's
// cgroup, 0 if neither is set
func cgroupMemoryLimit() (int64, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return 0, err
	}
	var dir string
	for _, line := range strings.Split(string(data), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			dir = filepath.Join(cgroupRoot, p)
		}
	}
	if dir == "" {
		return 0, errors.New("not in the cgroup v2 hierarchy")
	}
	var limit int64
	for _, file := range []string{"memory.max", "memory.high"} {
		b, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			return 0, err
		}
		v := strings.TrimSpace(string(b))
		if v == "max" {
			continue
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%s: %q", file, v)
		}
		if limit == 0 || n < limit {
			limit = n
		}
	}
	return limit, nil
}

// Fail tells the front process why the worker cannot serve, and returns err
func (c *Child) Fail(err error) error {
	c.ctl.Write([]byte(err.Error()))
	return err
}

// checkConfinement checks every thread of the process (see checkStatus)
func checkConfinement(u *fsuser.User) error {
	if u.UID == 0 {
		return errors.New("the account is the superuser")
	}
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return err
	}
	for _, t := range tasks {
		status, err := os.ReadFile("/proc/self/task/" + t.Name() + "/status")
		if errors.Is(err, os.ErrNotExist) {
			continue // the thread has exited
		}
		if err != nil {
			return err
		}
		if err := checkStatus(string(status), u); err != nil {
			return fmt.Errorf("thread %s %w", t.Name(), err)
		}
	}
	return nil
}

// Serve tells the front process that the worker is ready, then serves the requests
// it forwards with h until it closes the control socket (or exits), and waits for the
// requests in progress. SIGTERM and SIGINT give those requests shutdownGrace. reload
// is called when the front process reloads.
func (c *Child) Serve(h http.Handler, reload func()) error {
	signal.Ignore(syscall.SIGHUP) // meant for the front process, which reloads
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	srv := &http.Server{
		Handler:     Handler(limitRequests(h, c.Settings.Config.WorkerMaxRequests), &c.Settings.User),
		IdleTimeout: 5 * time.Minute,
		ErrorLog:    logger.ErrorLog(),
	}
	// The front process checks that the worker runs its own build
	if _, err := c.ctl.Write([]byte("ready " + c.build)); err != nil {
		return err
	}
	metrics.ForwardTo(c.ctl)

	onReload := func() {
		if c.Settings.Cgroup {
			limitMemory() // the front process has written the cgroup's limits again
		}
		if reload != nil {
			reload()
		}
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(&listener{ctl: c.ctl, reload: onReload}) }()
	select {
	case err := <-errc:
		if !errors.Is(err, io.EOF) {
			return err
		}
		// The front process takes no more requests here: finish those in progress
		return srv.Shutdown(context.Background())
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			srv.Close()
		}
		return nil
	}
}

// listener accepts the connections that the front process passes over the control
// socket, and calls reload when it asks for it
type listener struct {
	ctl    *net.UnixConn
	reload func()
}

func (l *listener) Accept() (net.Conn, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	for {
		n, oobn, _, _, err := l.ctl.ReadMsgUnix(buf, oob)
		if err != nil {
			return nil, err
		}
		if n == 0 && oobn == 0 {
			return nil, io.EOF
		}
		if oobn == 0 {
			if buf[0] == msgReload && l.reload != nil {
				go l.reload()
			}
			continue
		}
		var fds []int
		if msgs, err := unix.ParseSocketControlMessage(oob[:oobn]); err == nil && len(msgs) == 1 {
			fds, _ = unix.ParseUnixRights(&msgs[0])
		}
		if len(fds) != 1 {
			for _, fd := range fds {
				unix.Close(fd)
			}
			continue
		}
		f := os.NewFile(uintptr(fds[0]), "connection")
		c, err := net.FileConn(f)
		f.Close()
		if err == nil {
			return c, nil
		}
	}
}

// Close makes Accept return io.EOF; the control socket stays open for metrics
func (l *listener) Close() error { return l.ctl.CloseRead() }

func (l *listener) Addr() net.Addr { return l.ctl.LocalAddr() }
