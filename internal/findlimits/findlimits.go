// Package findlimits is weed limits: what weed can serve on this machine, as its
// configuration sets it, and the settings of weed, systemd and the kernel that would
// let it serve more. It runs a weed of its own on 127.0.0.1, with credentials it
// makes, exporting a directory of weed's storage; it measures the storage by itself,
// then puts weed under a load that grows until weed or the machine gives
// (internal/stress); and it reads what the kernel dropped meanwhile. It changes
// nothing of the machine: it writes what it found, and the files of settings it
// suggests, for you to review and install.
package findlimits

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/fsuser"
	"github.com/labkode/weed/internal/stress"
)

const usage = `weed limits finds what weed can serve on this machine, as its configuration
sets it, and suggests the settings of weed, systemd and the kernel that would let it
serve more. It changes nothing of the machine.

  weed limits [-config FILE] [-dir DIR] [OPTIONS] [-- STRESS OPTIONS]

It runs a weed of its own: this executable, with the settings of FILE that set what
serving costs (its authentication methods, TLS and its host key's kind, the limits
of unix_users, logging), on ports of 127.0.0.1, with credentials it makes. That weed
exports a directory that weed limits makes in weed's storage (DIR, or dir of FILE)
and removes. weed limits measures the storage by itself, then puts its weed under a
load that grows until weed or the machine gives, as -account; and reads what the
kernel dropped meanwhile. A load takes 10 to 20 minutes, -quick one or two.

It needs root, as weed does. Run it before weed serves, or when it serves little:
the load takes CPUs, memory and the storage from the weed that serves, and weed
limits refuses to start while that one has many requests in progress (-force).

What it found and suggests is in -out:
  summary.txt     what this machine can and cannot do, and why; also printed
  limits.json     all of it, as JSON
  stress.txt      the load, step by step (stress.json: as JSON)
  weed.toml       FILE with the settings it suggests, each under a comment that
                  says why and what it was (diff -u FILE weed.toml)
  sysctl.d/90-weed.conf, modules-load.d/weed.conf
                  settings of the kernel (for /etc/sysctl.d, /etc/modules-load.d)
  weed.service.d/limits.conf
                  a drop-in of weed's unit (for /etc/systemd/system)
Only the files of what it suggests are written.

Options:
`

// Main runs weed limits with args, the arguments after "limits", until ctx is done;
// it returns the exit status
func Main(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("weed limits", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgFile := fs.String("config", "", `weed's configuration file (default: /etc/weed/weed.toml if there is one; "" for none, as weed without one, but with every authentication method and TLS)`)
	dir := fs.String("dir", "", "the storage to measure: a directory that weed serves (default: dir of -config)")
	account := fs.String("account", "nobody", "the account that the load is made as, which must be able to enter DIR; not root")
	out := fs.String("out", "weed-limits", "the directory to write what it found and suggests to")
	unit := fs.String("unit", "weed.service", "weed's systemd unit")
	rtt := fs.Duration("rtt", 0, `the round trip to weed's farthest clients, e.g. "150ms", to size the kernel's TCP buffers for them`)
	var bandwidth float64
	fs.Func("bandwidth", `the bandwidth of weed's machine to its clients, in bits a second, e.g. "10G" (default: its fastest network interface's)`, func(s string) error {
		v, err := parseBits(s)
		bandwidth = v
		return err
	})
	quick := fs.Bool("quick", false, "a short load, of up to 8 clients and small files, and a short measure of the storage: to check that weed limits works, not to find limits")
	force := fs.Bool("force", false, "run while weed serves many requests")
	noProbe := fs.Bool("no-probe", false, "do not measure the storage by itself")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), usage)
		fs.PrintDefaults()
		fmt.Fprint(fs.Output(), "\nThe arguments after -- go to the load (stress), e.g. -- -scenarios download,upload -max 64; those of\nstress -h but -url, -ca, -identities, -cgroup and -status.\n")
	}
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		return 0
	} else if err != nil {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "weed limits: %v\n", err)
		return 1
	}
	if os.Geteuid() != 0 {
		return fail(errors.New("weed limits runs a weed whose workers act as -account: run it as root (sudo)"))
	}

	// weed's configuration: -config "" for none
	configSet := false
	fs.Visit(func(f *flag.Flag) { configSet = configSet || f.Name == "config" })
	if !configSet {
		if _, err := os.Stat("/etc/weed/weed.toml"); err == nil {
			*cfgFile = "/etc/weed/weed.toml"
		}
	}
	cfg := config.Default()
	if *cfgFile != "" {
		c, err := config.Load(*cfgFile)
		if err != nil {
			return fail(err)
		}
		cfg = c
	}
	if *dir == "" {
		if *cfgFile == "" {
			return fail(errors.New("no configuration (-config) and no storage to measure (-dir)"))
		}
		*dir = cfg.Directory
	}
	// As weed resolves it; and the mounts and the test weed's configuration name it
	if abs, err := filepath.Abs(*dir); err == nil {
		*dir = abs
	}
	if fi, err := os.Stat(*dir); err != nil {
		return fail(err)
	} else if !fi.IsDir() {
		return fail(fmt.Errorf("%s is not a directory", *dir))
	}
	user, err := fsuser.Lookup(*account)
	if err != nil {
		return fail(fmt.Errorf("-account: %w", err))
	}
	if blocked := unreachable(*dir, user); blocked != "" {
		return fail(fmt.Errorf("%s cannot enter %s, and so neither %s: -account names one that can", user.Name, blocked, *dir))
	}
	if n := busy(cfg.MetricsAddress); n > 10 && !*force {
		return fail(fmt.Errorf("weed has %d requests in progress (%s): the load would take from them; -force runs it all the same", n, cfg.MetricsAddress))
	}
	exe, err := os.Executable()
	if err != nil {
		return fail(err)
	}
	_, statErr := os.Stat(*out)
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return fail(err)
	}

	r := &run{ctx: ctx, stdout: stdout, stderr: stderr, cfg: cfg, cfgFile: *cfgFile, dir: *dir, user: user,
		out: *out, unit: *unit, rtt: *rtt, bandwidth: bandwidth, quick: *quick, noProbe: *noProbe,
		stressArgs: fs.Args(), exe: exe, madeOut: statErr != nil}
	code, err := r.run()
	if err != nil {
		fmt.Fprintf(stderr, "weed limits: %v\n", err)
	}
	return code
}

// run is a run of weed limits
type run struct {
	ctx            context.Context
	stdout, stderr io.Writer
	cfg            *config.Config
	cfgFile, dir   string
	user           *fsuser.User
	out, unit      string
	rtt            time.Duration
	bandwidth      float64
	quick, noProbe bool
	stressArgs     []string
	exe            string
	madeOut        bool // weed limits made the directory out

	facts  *Facts
	probe  *Probe
	report *stress.Report
	m      methods
	w      *testWeed
	result *Result
}

func (r *run) say(format string, args ...any) {
	fmt.Fprintf(r.stdout, "weed limits: "+format+"\n", args...)
}

func (r *run) run() (int, error) {
	cfg := r.cfg
	r.facts = readFacts(r.dir, r.unit)
	hostKey := defaultHostKey
	if cfg.TLS {
		if k, err := hostKeyOf(cfg.TLSCert); err == nil {
			hostKey = k
		} else {
			r.say("cannot read weed's host certificate (%v): its weed gets an %s key", err, hostKey)
		}
	}
	r.facts.HostKey = hostKey.String()
	r.m = methodsOf(cfg, r.cfgFile == "")
	if r.m.basic {
		r.facts.BcryptCost = bcryptCostOf(cfg.HtpasswdFile)
	}
	r.say("%s, %s, storage %s (%s)", r.facts.Host, machineText(r.facts), r.dir, storageText(r.facts.Storage))

	// Its files, and the directory of the storage that its weed exports
	work, err := os.MkdirTemp("/var/tmp", "weed-limits-")
	if err != nil {
		return 1, err
	}
	defer os.RemoveAll(work)
	scratch, err := os.MkdirTemp(r.dir, ".weed-limits-")
	if err != nil {
		return 1, fmt.Errorf("cannot make a directory in the storage: %w", err)
	}
	defer os.RemoveAll(scratch)

	// The storage, by itself
	if !r.noProbe {
		size := probeFull
		if r.quick {
			size = probeQuick
		}
		r.say("measuring the storage by itself")
		p, err := probeStorage(r.ctx, scratch, size, cfg.WorkerMaxStorageCalls)
		if err != nil {
			if r.ctx.Err() != nil {
				return 130, nil
			}
			return 1, fmt.Errorf("measuring the storage: %w", err)
		}
		r.probe = p
		r.say("%s", probeText(p))
	}

	if err := os.Chown(scratch, r.user.UID, r.user.GID); err != nil {
		return 1, err
	}
	r.say("making the credentials of %s (a host key of %s)", r.user.Name, hostKey)
	c, err := newCreds(work, r.user.Name, hostKey, max(r.facts.BcryptCost, 4), r.m.bearer)
	if err != nil {
		return 1, fmt.Errorf("the credentials: %w", err)
	}
	defer c.close()

	w := &testWeed{work: work, dir: scratch, tls: cfg.TLS || r.cfgFile == "",
		log: filepath.Join(work, "weed.log"), stderr: filepath.Join(work, "weed.stderr"),
		scopeAvailable: systemdScope()}
	w.withCgroups = w.scopeAvailable && (cfg.WorkerCgroups || len(cfg.WorkerCgroupLimits) > 0 || cfg.LimitsFile != "")
	if w.port, err = freePort(); err != nil {
		return 1, err
	}
	if w.metrics, err = freePort(); err != nil {
		return 1, err
	}
	if err := w.writeConfig(cfg, c, r.m); err != nil {
		return 1, err
	}
	r.w = w
	how := "in a systemd scope of its own"
	if !w.scopeAvailable {
		how = "without systemd: weed's CPU and memory are not measured, nor its workers' cgroups"
	}
	r.say("starting weed on 127.0.0.1:%d, %s", w.port, how)
	if err := w.start(r.ctx, r.exe); err != nil {
		w.stop()
		if r.ctx.Err() != nil {
			return 130, nil
		}
		return 1, err
	}
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			w.stop()
		}
	}
	defer stop()

	// The load
	ids := filepath.Join(work, "identities")
	var lines []string
	for _, kind := range r.m.kinds() {
		args := map[string]string{"cert": c.userCert + " " + c.userKey, "bearer": "@" + c.tokenFile,
			"app-token": c.appToken, "basic": c.password}[kind]
		lines = append(lines, r.user.Name+" "+kind+" "+args)
	}
	if err := os.WriteFile(ids, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		return 1, err
	}
	sargs := []string{"-url", w.url(), "-ca", c.caFile, "-identities", ids, "-status", w.status(),
		"-report", filepath.Join(r.out, "stress.txt"), "-json", filepath.Join(r.out, "stress.json"),
		// upload last: the storage writes back what it wrote for a while after, which
		// takes CPUs from the scenarios that follow
		"-scenarios", "get-small,put-small,list,connect,auth,download,upload"}
	if w.cgroup != "" {
		sargs = append(sargs, "-cgroup", w.cgroup)
	}
	if r.quick {
		sargs = append(sargs, "-max", "8", "-step", "2s", "-warmup", "500ms", "-download-size", "16MiB", "-upload-size", "4MiB")
	}
	sargs = append(sargs, r.stressArgs...)
	before := readCounters()
	r.say("the load: steps of more and more clients, until weed or this machine gives")
	rep, code := stress.Run(r.ctx, sargs, r.stdout, r.stderr)
	r.report = rep
	counters := readCounters().minus(before)
	events := cgroupEvents(w.cgroup)
	var exited bool
	select {
	case <-w.exited:
		exited = true
	default:
	}
	interrupted := r.ctx.Err() != nil
	lastWords := ""
	if exited {
		lastWords = w.lastWords()
	}
	stop()
	if interrupted {
		r.say("interrupted: what it found so far is in %s", r.out)
	}
	if code != 0 && rep == nil && !interrupted {
		return code, errors.New("the load found nothing (above)")
	}

	in := &inputs{cfg: cfg, cfgFile: r.cfgFile, facts: r.facts, probe: r.probe, report: rep,
		counters: counters, events: events, rtt: r.rtt, bandwidth: r.bandwidth}
	advice, cannot := advise(in)
	if exited {
		cannot = append([]string{fmt.Sprintf("serve the load: weed exited during it: %s", lastWords)}, cannot...)
	}
	r.result = &Result{
		Time: time.Now().UTC().Format(time.RFC3339), Config: r.cfgFile, Account: r.user.Name,
		Quick: r.quick, Interrupted: interrupted, Methods: r.m.kinds(), ChoseMethods: r.m.none, Facts: r.facts, Probe: r.probe, Stress: rep,
		Counters: counters, Cgroup: events, Log: w.logs.notes(), Cannot: cannot, Advice: advice,
	}
	if err := r.write(); err != nil {
		return 1, err
	}
	if interrupted {
		return 130, nil
	}
	return code, nil
}

// unreachable is the first directory of the path to dir that u cannot enter ("" if
// none)
func unreachable(dir string, u *fsuser.User) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	for p := abs; ; p = filepath.Dir(p) {
		var st os.FileInfo
		if st, err = os.Stat(p); err == nil && !canEnter(st, u) {
			return p
		}
		if p == "/" {
			return ""
		}
	}
}

func canEnter(fi os.FileInfo, u *fsuser.User) bool {
	uid, gid, ok := ownerOf(fi)
	mode := fi.Mode().Perm()
	if !ok {
		return true
	}
	switch {
	case uid == u.UID:
		return mode&0o100 != 0
	case slices.Contains(u.Groups, gid):
		return mode&0o010 != 0
	}
	return mode&0o001 != 0
}

// busy is the requests in progress in weed's workers, from /status at its
// metrics_address (0 if it does not answer)
func busy(metricsAddress string) int {
	if metricsAddress == "" {
		return 0
	}
	host := metricsAddress
	if strings.HasPrefix(host, ":") {
		host = "127.0.0.1" + host
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + host + "/status")
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	var st struct {
		Workers []struct {
			Requests int `json:"requests"`
		} `json:"workers"`
	}
	if json.NewDecoder(resp.Body).Decode(&st) != nil {
		return 0
	}
	n := 0
	for _, w := range st.Workers {
		n += w.Requests
	}
	return n
}

// parseBits reads a rate in bits a second: a number, with k, M, G or T after it
func parseBits(s string) (float64, error) {
	t := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(s), "bit"), "b")
	mult := 1.0
	if t != "" {
		switch t[len(t)-1] {
		case 'k', 'K':
			mult = 1e3
		case 'M':
			mult = 1e6
		case 'G':
			mult = 1e9
		case 'T':
			mult = 1e12
		}
		if mult != 1 {
			t = t[:len(t)-1]
		}
	}
	v, err := strconv.ParseFloat(t, 64)
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("invalid rate %q: e.g. 10G, 2.5G, 100M (bits a second)", s)
	}
	return v * mult, nil
}
