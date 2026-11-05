package findlimits

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/stress"
)

// What weed limits writes: its findings, and the files of the settings it suggests

// Result is all that weed limits found, limits.json
type Result struct {
	Time        string `json:"time"`
	Config      string `json:"config,omitempty"`
	Account     string `json:"account"`
	Quick       bool   `json:"quick,omitempty"`
	Interrupted bool   `json:"interrupted,omitempty"`
	// Methods are how the load authenticates: the first in the scenarios, each other
	// in an auth-METHOD; cert, bearer, app-token or basic (a password)
	Methods      []string       `json:"methods"`
	ChoseMethods bool           `json:"chose_methods,omitempty"` // the configuration enables none
	Facts        *Facts         `json:"machine"`
	Probe        *Probe         `json:"storage,omitempty"`
	Stress       *stress.Report `json:"load,omitempty"`
	Counters     Counters       `json:"kernel_drops"`
	Cgroup       CgroupEvents   `json:"cgroup"`
	Log          []LogNote      `json:"log,omitempty"`
	Cannot       []string       `json:"cannot"`
	Advice       []Advice       `json:"advice"`
}

// The files of suggested settings, in -out
const (
	sysctlFile  = "sysctl.d/90-weed.conf"
	modulesFile = "modules-load.d/weed.conf"
	dropInName  = "limits.conf"
)

func (r *run) dropIn() string { return filepath.Join(r.unit+".d", dropInName) }

// write writes the files of the result to r.out, and prints its summary
func (r *run) write() error {
	res := r.result
	// Those of an earlier run go: only what this one suggests is there
	for _, f := range []string{"weed.toml", sysctlFile, modulesFile, r.dropIn()} {
		os.Remove(filepath.Join(r.out, f))
	}
	var written []string
	put := func(name string, perm os.FileMode, content string) error {
		p := filepath.Join(r.out, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(content), perm); err != nil {
			return err
		}
		os.Chmod(p, perm) // also of a file that was there
		written = append(written, name)
		return nil
	}

	// weed.toml
	var changes []tomlChange
	for _, a := range res.Advice {
		if a.toml != nil {
			ch := *a.toml
			ch.Reason = a.Reason
			changes = append(changes, ch)
		}
	}
	var tomlProblem error
	if len(changes) > 0 {
		src, perm := "", os.FileMode(0o644)
		if r.cfgFile != "" {
			b, err := os.ReadFile(r.cfgFile)
			if err != nil {
				return err
			}
			src = string(b)
			if fi, err := os.Stat(r.cfgFile); err == nil {
				perm = fi.Mode().Perm()
			}
		}
		if r.cfgFile == "" {
			src = "# The settings that weed limits suggests, " + res.Time + ", to add to weed's configuration file\n"
		}
		if err := put("weed.toml", perm, editTOML(src, changes)); err != nil {
			return err
		}
		if _, err := config.Load(filepath.Join(r.out, "weed.toml")); err != nil {
			tomlProblem = err
		}
	}

	// sysctl.d, modules-load.d and the unit's drop-in
	var sysctl, unit, modules strings.Builder
	for _, a := range res.Advice {
		switch a.File {
		case "sysctl":
			writeComment(&sysctl, a.Reason, a.Current, a.Key+" = ")
			fmt.Fprintf(&sysctl, "%s = %s\n\n", a.Key, a.Value)
		case "unit":
			writeComment(&unit, a.Reason, a.Current, a.Key+"=")
			fmt.Fprintf(&unit, "%s=%s\n\n", a.Key, a.Value)
		case "modules-load":
			writeComment(&modules, a.Reason, "", "")
			fmt.Fprintf(&modules, "%s\n", a.Key)
		}
	}
	header := "# Suggested by weed limits, " + res.Time + ": review it, and install it if you agree\n"
	if sysctl.Len() > 0 {
		if err := put(sysctlFile, 0o644, header+"# (/etc/sysctl.d, then sysctl --system)\n\n"+sysctl.String()); err != nil {
			return err
		}
	}
	if unit.Len() > 0 {
		if err := put(r.dropIn(), 0o644, header+"# (/etc/systemd/system/"+r.unit+".d, then systemctl daemon-reload and a restart)\n[Service]\n"+unit.String()); err != nil {
			return err
		}
	}
	if modules.Len() > 0 {
		if err := put(modulesFile, 0o644, header+"# (/etc/modules-load.d)\n"+modules.String()); err != nil {
			return err
		}
	}

	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	if err := put("limits.json", 0o644, string(b)+"\n"); err != nil {
		return err
	}
	summary := r.summary(written, tomlProblem)
	if err := put("summary.txt", 0o644, summary); err != nil {
		return err
	}
	fmt.Fprint(r.stdout, "\n"+summary)

	// The files that it wrote are of who ran sudo, and their directories that it made
	if uid, gid, ok := sudoer(); ok {
		var paths []string
		if r.madeOut {
			paths = append(paths, r.out)
		}
		for _, w := range append(written, "stress.txt", "stress.json") {
			paths = append(paths, filepath.Join(r.out, w))
			if d := filepath.Dir(w); d != "." {
				paths = append(paths, filepath.Join(r.out, d)) // the drop-in's
			}
		}
		for _, p := range paths {
			os.Lchown(p, uid, gid)
		}
	}
	return nil
}

func writeComment(b *strings.Builder, reason, current, was string) {
	for _, l := range wrap("weed limits: "+reason, 76) {
		fmt.Fprintf(b, "# %s\n", l)
	}
	if current != "" {
		fmt.Fprintf(b, "# was: %s%s\n", was, current)
	}
}

func sudoer() (uid, gid int, ok bool) {
	u, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	g, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	return u, g, err1 == nil && err2 == nil && u != 0
}

// summary is what this machine can and cannot do, and what weed limits suggests
func (r *run) summary(written []string, tomlProblem error) string {
	res := r.result
	var b strings.Builder
	p := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	f := res.Facts
	p("weed limits, %s: %s, %s", res.Time, f.Host, machineText(f))
	how := "as " + res.Config + " sets it"
	switch {
	case res.Config == "":
		how = "without a configuration file: every authentication method, and TLS"
	case res.ChoseMethods:
		how += ", but authentication, which it does not enable: weed limits enabled the methods below"
	}
	tls := "without TLS"
	if r.w != nil && r.w.tls {
		tls = "TLS with a host key of " + f.HostKey
	}
	p("weed: %s; %s", how, tls)
	p("The load: as %s, %s", res.Account, loadText(res.Methods))
	p("Storage: %s, %s", f.Storage.Dir, storageText(f.Storage))
	if res.Quick {
		p("A quick run (-quick): its numbers check that weed limits works, they are not this machine's limits")
	}
	if res.Interrupted {
		p("Interrupted: what follows is what it found until then")
	}

	if rep := res.Stress; rep != nil && len(rep.Results) > 0 {
		p("\nWhat weed served")
		for _, s := range rep.Results {
			p("  %-14s %s", s.Name, s.Summary())
			if s.Limit != "" {
				p("  %-14s %s", "", s.Limit)
			}
		}
	}
	if pr := res.Probe; pr != nil {
		p("\nThe storage by itself")
		p("  an upload's end (a write, fsync, rename, fsync of its directory): %s, p99 %s; 16 at once, %.0f a second",
			secondsText(pr.CommitP50), secondsText(pr.CommitP99), pr.CommitsPerSec)
		var pts []string
		for _, pt := range pr.Parallel {
			pts = append(pts, fmt.Sprintf("%d: %s", pt.Calls, countText(pt.PerSecond)))
		}
		p("  calls a second (open, fstat, read of 4 KiB), by calls at once: %s", strings.Join(pts, ", "))
		p("  a large file written and synced: %s/s", siBytes(pr.WriteBytesPerSec))
	}

	c := res.Counters
	p("\nWhat the kernel dropped under the load")
	if c == (Counters{}) {
		p("  nothing")
	} else {
		p("  connections whose listen queue was full: %d; dropped by connection tracking: %d; packets the CPUs could not take: %d",
			c.ListenOverflows+c.ListenDrops, c.ConntrackDrops, c.SoftnetDrops)
	}
	if e := res.Cgroup; e.PidsPeak > 0 || e.MemoryPeak > 0 {
		// memory.peak counts the page cache of the files weed read and wrote, which
		// the kernel takes back when it needs to; stress measures without it
		var own int64
		if rep := res.Stress; rep != nil {
			for _, sr := range rep.Results {
				for _, st := range sr.Steps {
					own = max(own, st.WeedMemory)
				}
			}
		}
		mem := bytesText(e.MemoryPeak) + " of memory"
		if own > 0 {
			mem = fmt.Sprintf("%s of memory, the page cache aside (%s with it)", bytesText(own), bytesText(e.MemoryPeak))
		}
		s := fmt.Sprintf("  weed and its workers used at most %d threads and %s", e.PidsPeak, mem)
		if e.WorkersPeak > 0 {
			s += fmt.Sprintf("; a worker at most %d threads", e.WorkersPeak)
		}
		p("%s", s)
	}

	if len(res.Log) > 0 {
		p("\nweed's warnings and errors under the load")
		for i, n := range res.Log {
			if i == 8 {
				p("  and %d more kinds (limits.json)", len(res.Log)-i)
				break
			}
			note := ""
			if n.Message == "WARN upload aborted" {
				note = " (also the load's own: it cuts the uploads still in progress a minute after a step, or when interrupted)"
			}
			p("  %6d × %s%s", n.Count, n.Message, note)
		}
	}

	p("\nWhat it cannot do, as set")
	if len(res.Cannot) == 0 {
		p("  nothing that weed limits could tell")
	}
	for _, s := range res.Cannot {
		writeItem(&b, s)
	}

	p("\nWhat weed limits suggests (it changed nothing)")
	if len(res.Advice) == 0 {
		p("  nothing")
	}
	for _, a := range res.Advice {
		where := map[string]string{"weed.toml": "weed.toml", "sysctl": sysctlFile, "unit": r.dropIn(), "modules-load": modulesFile}[a.File]
		switch {
		case a.File == "modules-load":
			writeItem(&b, fmt.Sprintf("%s: load %s at boot: %s", where, a.Key, a.Reason))
		case a.File == "unit" || a.File == "weed.toml" || a.File == "sysctl":
			setting := a.Key + " = " + a.Value
			if a.File == "unit" {
				setting = a.Key + "=" + a.Value
			}
			if a.Current != "" {
				setting += " (was " + a.Current + ")"
			}
			writeItem(&b, fmt.Sprintf("%s: %s: %s", where, setting, a.Reason))
		default:
			writeItem(&b, a.Reason)
		}
	}
	if tomlProblem != nil {
		p("  weed.toml does not load (a bug of weed limits): %v", tomlProblem)
	}

	files := []string{"summary.txt", "limits.json"}
	for _, f := range []string{"stress.txt", "stress.json"} {
		if _, err := os.Stat(filepath.Join(r.out, f)); err == nil {
			files = append(files, f)
		}
	}
	var proposed []string
	for _, w := range written {
		if w != "limits.json" {
			proposed = append(proposed, w)
		}
	}
	p("\nIn %s: %s", r.out, strings.Join(append(files, proposed...), ", "))
	if len(proposed) > 0 {
		p("To install what you agree with:")
	}
	for _, w := range proposed {
		switch w {
		case "weed.toml":
			if r.cfgFile == "" {
				p("  add the settings of %s to weed's configuration file; weed check -config it, and restart weed", filepath.Join(r.out, w))
			} else {
				p("  diff -u %s %s; install it, weed check -config it, and restart weed", r.cfgFile, filepath.Join(r.out, w))
			}
		case sysctlFile:
			p("  install -m 644 %s /etc/sysctl.d/ && sysctl --system", filepath.Join(r.out, w))
		case r.dropIn():
			p("  install -D -m 644 %s /etc/systemd/system/%s && systemctl daemon-reload && systemctl restart %s",
				filepath.Join(r.out, w), w, r.unit)
		case modulesFile:
			p("  install -m 644 %s /etc/modules-load.d/ && modprobe nf_conntrack", filepath.Join(r.out, w))
		}
	}
	return b.String()
}

// writeItem writes a paragraph of a list
func writeItem(b *strings.Builder, text string) {
	for i, l := range wrap(text, 76) {
		if i == 0 {
			fmt.Fprintf(b, "  - %s\n", l)
		} else {
			fmt.Fprintf(b, "    %s\n", l)
		}
	}
}

func machineText(f *Facts) string {
	s := fmt.Sprintf("%d CPUs", f.CPUs)
	if f.Cores > 0 && f.Cores < f.CPUs {
		s += fmt.Sprintf(" (%d cores)", f.Cores)
	}
	if f.MemoryBytes > 0 {
		s += ", " + bytesText(f.MemoryBytes) + " of memory"
	}
	if f.Kernel != "" {
		s += ", Linux " + f.Kernel
	}
	return s
}

func storageText(s Storage) string {
	t := s.FSType
	if t == "" {
		t = "a file system"
	}
	if s.Source != "" {
		t += " on " + s.Source
	}
	if s.Network {
		t += ", over the network"
	}
	if s.FreeBytes > 0 {
		t += ", " + bytesText(s.FreeBytes) + " free"
	}
	return t
}

func probeText(p *Probe) string {
	best := ParallelPoint{}
	for _, pt := range p.Parallel {
		if pt.PerSecond > best.PerSecond {
			best = pt
		}
	}
	return fmt.Sprintf("an upload's end takes %s (p99 %s), %.0f a second 16 at once; %s calls a second at most, %d at once; writes of %s/s",
		secondsText(p.CommitP50), secondsText(p.CommitP99), p.CommitsPerSec, countText(best.PerSecond), best.Calls, siBytes(p.WriteBytesPerSec))
}

var methodNames = map[string]string{"cert": "an X.509 certificate", "bearer": "a WLCG token",
	"app-token": "an app token", "basic": "a password"}

// loadText is how the load authenticates: by the first method, but in auth-METHOD
func loadText(m []string) string {
	if len(m) == 0 {
		return "authenticated by nothing"
	}
	s := "authenticated by " + methodNames[m[0]]
	for _, k := range m[1:] {
		s += ", in auth-" + k + " by " + methodNames[k]
	}
	return s
}

func secondsText(s float64) string {
	switch {
	case s >= 1:
		return trimFloat(s) + " s"
	case s >= 1e-3:
		return trimFloat(s*1e3) + " ms"
	}
	return trimFloat(s*1e6) + " µs"
}

func countText(v float64) string {
	switch {
	case v >= 1e6:
		return trimFloat(v/1e6) + "M"
	case v >= 1e4:
		return trimFloat(v/1e3) + "k"
	}
	return strconv.FormatFloat(v, 'f', 0, 64)
}

// ownerOf is the owner and group of a file
func ownerOf(fi os.FileInfo) (uid, gid int, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}
