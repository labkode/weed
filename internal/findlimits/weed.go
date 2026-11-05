package findlimits

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/labkode/weed/internal/config"
)

// The weed that weed limits runs: weed's own build and configuration, as far as they
// set what it costs to serve, on ports of 127.0.0.1, with the credentials of creds,
// exporting a directory of the storage that weed limits makes and removes

// methods are the authentication methods of the identities. With basic, the load
// authenticates by an app token, which weed checks without bcrypt, and auth-basic by
// a password.
type methods struct {
	cert, bearer, basic bool
	none                bool // the configuration enables none: weed limits chose them
}

// methodsOf is the methods of weed's configuration; without a configuration, or one
// that enables none, a WLCG token and Basic, and a certificate with TLS
func methodsOf(cfg *config.Config, noFile bool) methods {
	if noFile {
		return methods{cert: true, bearer: true, basic: true}
	}
	m := methods{cert: cfg.TLS && cfg.X509Auth, bearer: cfg.TokenIssuers != "", basic: cfg.BasicAuth}
	if !m.cert && !m.bearer && !m.basic {
		m = methods{cert: cfg.TLS, bearer: true, basic: true, none: true}
	}
	return m
}

// kinds are stress's kinds of identities, in the order of the identities file: the
// first is that of the scenarios, each other that of an auth-KIND
func (m methods) kinds() []string {
	var k []string
	if m.cert {
		k = append(k, "cert")
	}
	if m.bearer {
		k = append(k, "bearer")
	}
	if m.basic {
		k = append(k, "app-token", "basic")
	}
	return k
}

// testWeed is the weed that weed limits runs
type testWeed struct {
	work, dir      string // its files; the directory it exports
	config         string
	port, metrics  int
	tls            bool
	scope          string // its systemd scope, "" without
	cgroup         string // its cgroup, "" when it shares weed limits's
	cmd            *exec.Cmd
	exited         chan struct{}
	log, stderr    string
	logs           *logWatch
	withCgroups    bool // its workers in cgroups of their own
	scopeAvailable bool
}

// freePort is a port of 127.0.0.1 that nothing listens on
func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// systemdScope says whether weed can run in a systemd scope of its own
func systemdScope() bool {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return false
	}
	_, err := exec.LookPath("systemd-run")
	return err == nil
}

// writeConfig writes the configuration of w, from weed's own cfg
func (w *testWeed) writeConfig(cfg *config.Config, c *creds, m methods) error {
	var b strings.Builder
	p := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	p("# weed limits: the weed it measures, as weed's own configuration sets what serving costs")
	p("[server]")
	p("address = %s", tomlString("127.0.0.1"))
	p("port = %d", w.port)
	p("dir = %s", tomlString(w.dir))
	p("log_file = %s", tomlString(w.log))
	p("log_level = %s", tomlString(cfg.LogLevel))
	p("log_format = %s", tomlString(cfg.LogFormat))
	p("metrics_address = %s", tomlString(fmt.Sprintf("127.0.0.1:%d", w.metrics)))
	p(`reload_interval = "0s"`)
	p("[tls]")
	p("enabled = %t", w.tls)
	p("cert = %s", tomlString(c.hostCert))
	p("key = %s", tomlString(c.hostKey))
	if m.cert {
		p("[x509]")
		p("enabled = true")
		p("ca = %s", tomlString(c.caFile))
		p("crl_path = %s", tomlString(c.crlFile))
		p("crl_mode = %s", tomlString(cfg.CRLMode))
		p("gridmap = %s", tomlString(c.gridmap))
	}
	if m.basic {
		p("[basic]")
		p("enabled = true")
		p("htpasswd = %s", tomlString(c.htpasswd))
		p("app_tokens = %s", tomlString(c.appTokens))
	}
	if m.bearer {
		p("[tokens]")
		p("issuers = %s", tomlString(c.issuers))
		p("ca_path = %s", tomlString(c.caFile))
	}
	p("[unix_users]")
	p("idle_timeout = %s", tomlString(cfg.WorkerIdleTimeout.String()))
	p("max_workers = %d", cfg.MaxWorkers)
	p("max_requests = %d", cfg.WorkerMaxRequests)
	p("max_storage_calls = %d", cfg.WorkerMaxStorageCalls)
	p("cgroups = %t", w.withCgroups)
	if w.withCgroups {
		p("cgroup_limits = %s", tomlStrings(cfg.WorkerCgroupLimits))
	}
	p("[admin]")
	p(`socket = ""`)
	p(`bans = ""`)
	w.config = filepath.Join(w.work, "weed.toml")
	if err := os.WriteFile(w.config, []byte(b.String()), 0o644); err != nil {
		return err
	}
	tc, err := config.Load(w.config)
	if err != nil {
		return fmt.Errorf("the configuration of weed limits's weed: %w", err)
	}
	return tc.Validate()
}

// url is the URL of the exported directory
func (w *testWeed) url() string {
	scheme := "http"
	if w.tls {
		scheme = "https"
	}
	return fmt.Sprintf("%s://127.0.0.1:%d/webdav/", scheme, w.port)
}

func (w *testWeed) status() string { return fmt.Sprintf("http://127.0.0.1:%d/status", w.metrics) }

// start starts weed, the executable exe, in a systemd scope of its own when there is
// systemd, and waits until it serves
func (w *testWeed) start(ctx context.Context, exe string) error {
	args := []string{exe, "-config", w.config}
	if w.scopeAvailable {
		w.scope = fmt.Sprintf("weed-limits-%d.scope", os.Getpid())
		args = append([]string{"systemd-run", "--scope", "--quiet", "--collect", "--unit=" + w.scope,
			"-p", "Delegate=yes", "-p", "TasksMax=infinity", "--"}, args...)
	}
	stderr, err := os.Create(w.stderr)
	if err != nil {
		return err
	}
	defer stderr.Close()
	w.cmd = exec.Command(args[0], args[1:]...)
	w.cmd.Stdout, w.cmd.Stderr = stderr, stderr
	// Its own process group: a Ctrl-C stops the load, and then weed limits stops weed
	w.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := w.cmd.Start(); err != nil {
		return err
	}
	w.exited = make(chan struct{})
	go func() { w.cmd.Wait(); close(w.exited) }()

	healthz := fmt.Sprintf("http://127.0.0.1:%d/healthz", w.metrics)
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(time.Minute)
	for {
		if resp, err := client.Get(healthz); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		select {
		case <-w.exited:
			return fmt.Errorf("weed did not start: %s", w.lastWords())
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("weed did not serve within a minute: %s", w.lastWords())
		}
	}
	if w.scope != "" {
		w.cgroup = cgroupOf(w.cmd.Process.Pid)
	}
	w.logs = watchLog(w.log)
	return nil
}

// cgroupOf is the cgroup of pid, that of its scope: weed moves itself into main below it
func cgroupOf(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	for line := range strings.Lines(string(b)) {
		if p, ok := strings.CutPrefix(strings.TrimSpace(line), "0::"); ok {
			return filepath.Join("/sys/fs/cgroup", strings.TrimSuffix(p, "/main"))
		}
	}
	return ""
}

// lastWords is the end of what weed wrote before it exited
func (w *testWeed) lastWords() string {
	var lines []string
	for _, f := range []string{w.stderr, w.log} {
		b, _ := os.ReadFile(f)
		for l := range strings.Lines(string(b)) {
			if l = strings.TrimSpace(l); l != "" {
				lines = append(lines, l)
			}
		}
	}
	if len(lines) == 0 {
		return "it wrote nothing"
	}
	return strings.Join(lines[max(0, len(lines)-5):], "\n  ")
}

// stop stops weed, and what is left of its scope
func (w *testWeed) stop() {
	if w.cmd == nil || w.cmd.Process == nil {
		return
	}
	w.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-w.exited:
	case <-time.After(45 * time.Second):
		w.cmd.Process.Kill()
		<-w.exited
	}
	if w.scope != "" {
		exec.Command("systemctl", "stop", w.scope).Run()
	}
	if w.logs != nil {
		w.logs.stop()
	}
}

// --- weed's log

// logWatch reads weed's log as it grows, counts its warnings and errors by message,
// and keeps the file small: the log of a load of tens of thousands of requests a
// second grows by gigabytes
type logWatch struct {
	file   string
	quit   chan struct{}
	done   chan struct{}
	mu     sync.Mutex
	counts map[string]int // level and message
	sample map[string]string
}

const maxLog = 256 << 20

var (
	levelRe = regexp.MustCompile(`level=(WARN|ERROR)\b|"level":"(WARN|ERROR)"`)
	msgRe   = regexp.MustCompile(`msg="((?:[^"\\]|\\.)*)"|msg=(\S+)|"msg":"((?:[^"\\]|\\.)*)"`)
)

func watchLog(file string) *logWatch {
	l := &logWatch{file: file, quit: make(chan struct{}), done: make(chan struct{}),
		counts: make(map[string]int), sample: make(map[string]string)}
	go l.run()
	return l
}

func (l *logWatch) run() {
	defer close(l.done)
	var off int64
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		off = l.read(off)
		select {
		case <-l.quit:
			l.read(off)
			return
		case <-t.C:
		}
	}
}

// read reads the log from off, and returns where it stopped; once it has read more
// than maxLog, it empties the file, which weed appends to (O_APPEND)
func (l *logWatch) read(off int64) int64 {
	f, err := os.Open(l.file)
	if err != nil {
		return off
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() < off {
		off = 0 // emptied
	}
	f.Seek(off, io.SeekStart)
	r := bufio.NewReaderSize(f, 1<<20)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break // a line not yet complete is read again next time
		}
		off += int64(len(line))
		l.note(line)
	}
	if off > maxLog {
		os.Truncate(l.file, 0)
		off = 0
	}
	return off
}

func (l *logWatch) note(line string) {
	lv := levelRe.FindStringSubmatch(line)
	if lv == nil {
		return
	}
	level := lv[1] + lv[2]
	msg := ""
	if m := msgRe.FindStringSubmatch(line); m != nil {
		msg = m[1] + m[2] + m[3]
	}
	key := level + " " + msg
	l.mu.Lock()
	defer l.mu.Unlock()
	l.counts[key]++
	if _, ok := l.sample[key]; !ok {
		l.sample[key] = strings.TrimSpace(line)
	}
}

func (l *logWatch) stop() {
	select {
	case <-l.quit:
	default:
		close(l.quit)
	}
	<-l.done
}

// LogNote is a warning or an error that weed logged under the load, how many times,
// and its first record
type LogNote struct {
	Message string `json:"message"`
	Count   int    `json:"count"`
	First   string `json:"first"`
}

// notes are the warnings and errors, the most frequent first
func (l *logWatch) notes() []LogNote {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var list []LogNote
	for k, n := range l.counts {
		list = append(list, LogNote{Message: k, Count: n, First: l.sample[k]})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Count != list[j].Count {
			return list[i].Count > list[j].Count
		}
		return list[i].Message < list[j].Message
	})
	return list
}
