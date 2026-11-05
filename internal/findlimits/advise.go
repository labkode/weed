package findlimits

import (
	"fmt"
	"math"
	"math/bits"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/stress"
)

// What weed limits suggests: a setting of weed, systemd or the kernel, only where
// what it measured or read shows a limit that the setting moves

// Advice is a setting to change, in File: weed.toml, sysctl (a file of
// /etc/sysctl.d), unit (a drop-in of weed's unit), modules-load (a file of
// /etc/modules-load.d), or "" for advice that is not a setting
type Advice struct {
	File    string `json:"file"`
	Key     string `json:"key,omitempty"`
	Current string `json:"current,omitempty"`
	Value   string `json:"value,omitempty"`
	Reason  string `json:"reason"`
	toml    *tomlChange
}

// inputs are what the advice comes from
type inputs struct {
	cfg       *config.Config
	cfgFile   string // "" without
	facts     *Facts
	probe     *Probe         // nil if not run
	report    *stress.Report // nil if nothing ran
	counters  Counters       // during the load
	events    CgroupEvents
	rtt       time.Duration
	bandwidth float64 // bits/s (0: the fastest interface's)
}

// advise returns the settings to change, and what this machine cannot do as set
func advise(in *inputs) (advice []Advice, cannot []string) {
	add := func(a Advice) { advice = append(advice, a) }
	cfg, f := in.cfg, in.facts

	// Threads: those weed's workers may hold, against systemd's limit of the unit
	if sd := f.Systemd; sd != nil {
		need := threadsNeeded(cfg, f.CPUs)
		if tm := sd.tasksMax(); tm >= 0 && tm < int64(need) {
			lets := "lets " + sd.Unit
			if !sd.Installed {
				lets = "lets a service (" + sd.Unit + " is not installed)"
			}
			add(Advice{File: "unit", Key: "TasksMax", Current: sd.TasksMax, Value: "infinity",
				Reason: fmt.Sprintf("systemd %s have %d threads, and weed's %d workers hold up to %d when the storage stops answering (unix_users.max_storage_calls %d each, plus the CPUs and a few): a process that cannot make a thread dies, weed's own too. weed bounds its threads itself, and pids.max in unix_users.cgroup_limits those of each account",
					lets, tm, cfg.MaxWorkers, need, cfg.WorkerMaxStorageCalls)})
			cannot = append(cannot, fmt.Sprintf("keep serving with all its %d workers busy while the storage hangs: systemd allows %s %d threads, weed's workers would hold %d",
				cfg.MaxWorkers, sd.Unit, tm, need))
		}
	}

	// The journal, against the rate of requests (one record each)
	peak, peakName := peakRate(in.report)
	if rate := journalRate(f); cfg.LogFile == "" && rate > 0 && peak > rate {
		add(Advice{File: "weed.toml", Key: "server.log_file", Current: `""`, Value: `"/var/log/weed/weed.log"`,
			Reason: fmt.Sprintf("the journal keeps some %.0f lines a second of a service (RateLimitBurst=%d every %s), and drops the others, errors too; weed logs a line for each request, and answered %.0f a second (%s)",
				rate, f.Journald.Burst, f.Journald.Interval, peak, peakName),
			toml: &tomlChange{Section: "server", Key: "log_file", Value: `"/var/log/weed/weed.log"`}})
		add(Advice{File: "unit", Key: "LogsDirectory", Value: "weed",
			Reason: "systemd makes /var/log/weed for weed, for server.log_file, writable also when sandboxed"})
		cannot = append(cannot, fmt.Sprintf("log every request to the journal: it keeps some %.0f lines a second, weed answered %.0f", rate, peak))
	}

	// Calls to the storage at once, on a network storage, where each call of the probe
	// waits for the server: on a local one, its files are in the page cache, and it
	// measures the CPUs
	calls := cfg.WorkerMaxStorageCalls
	if p := in.probe; p != nil && f.Storage.Network {
		cur, more := p.at(calls), p.at(calls*4)
		if cur > 0 && more > 1.25*cur && calls*4 <= 4096 {
			calls *= 4
			add(Advice{File: "weed.toml", Key: "unix_users.max_storage_calls", Current: tomlInt(cfg.WorkerMaxStorageCalls), Value: tomlInt(calls),
				Reason: fmt.Sprintf("the storage answered %.0f calls a second %d at once, and %.0f %d at once: it serves more calls at once than a worker makes",
					cur, cfg.WorkerMaxStorageCalls, more, calls),
				toml: &tomlChange{Section: "unix_users", Key: "max_storage_calls", Value: tomlInt(calls)}})
		}
	}
	// pids.max of the accounts, against the threads of a worker
	if limits, cur, ok := pidsMax(cfg.WorkerCgroupLimits); ok {
		need := calls + f.CPUs + 100
		hit := in.events.PidsMax > 0
		if cur < need || hit {
			want := roundUp(max(need, cur*2*boolInt(hit)), 100)
			value := tomlStrings(setPidsMax(limits, want))
			why := fmt.Sprintf("a worker holds up to unix_users.max_storage_calls threads (%d), plus the CPUs (%d) and some more: one that cannot make a thread dies", calls, f.CPUs)
			if hit {
				why = fmt.Sprintf("a worker could not make a thread or a process %d times under the load: ", in.events.PidsMax) + why
			}
			add(Advice{File: "weed.toml", Key: "unix_users.cgroup_limits", Current: tomlStrings(limits), Value: value, Reason: why,
				toml: &tomlChange{Section: "unix_users", Key: "cgroup_limits", Value: value}})
		}
	} else if in.events.PidsMax > 0 {
		cannot = append(cannot, fmt.Sprintf("serve the load with the threads it may make: a thread or process was refused %d times (pids.max)", in.events.PidsMax))
	}
	if in.events.OOMKills > 0 {
		cannot = append(cannot, fmt.Sprintf("serve the load in the memory of its accounts: the kernel killed a worker %d times (memory.max in unix_users.cgroup_limits)", in.events.OOMKills))
		add(Advice{File: "", Key: "unix_users.cgroup_limits", Reason: "raise memory.max: the kernel killed workers for their memory under the load"})
	}

	// TCP buffers, against the bandwidth and the round trip of the clients
	bw := in.bandwidth
	if bw == 0 {
		bw = f.fastestNIC()
	}
	for _, b := range []struct{ name, what string }{{"net.ipv4.tcp_wmem", "send to"}, {"net.ipv4.tcp_rmem", "receive from"}} {
		v := sysctlInts(f.Sysctl[b.name])
		if len(v) != 3 {
			continue
		}
		rtt := in.rtt
		if rtt == 0 {
			rtt = 100 * time.Millisecond
		}
		perConn := float64(v[2]) * 8 / rtt.Seconds() // bits/s
		if bw == 0 || perConn >= bw {
			continue
		}
		if in.rtt == 0 {
			cannot = append(cannot, fmt.Sprintf("%s a client 100 ms away faster than %s on one connection, a fraction of %s (%s: %s at most in flight); -rtt sizes the buffers for your clients",
				b.what, bitsText(perConn), bitsText(bw), b.name, bytesText(v[2])))
			continue
		}
		want := nextPow2(int64(2 * bw / 8 * in.rtt.Seconds()))
		want = max(want, 4<<20)
		value := fmt.Sprintf("%d %d %d", v[0], v[1], want)
		add(Advice{File: "sysctl", Key: b.name, Current: f.Sysctl[b.name], Value: value,
			Reason: fmt.Sprintf("a connection carries one buffer each round trip: %s at most in flight is %s over %s, and %s of %s takes %s, twice for the kernel's bookkeeping",
				bytesText(v[2]), bitsText(perConn), in.rtt, bitsText(bw), in.rtt, bytesText(want))})
		cannot = append(cannot, fmt.Sprintf("%s a client %s away faster than %s on one connection (%s)", b.what, in.rtt, bitsText(perConn), b.name))
	}

	// The buffers of the sockets to the workers, of 1 MiB if the kernel allows it: weed
	// has no CAP_NET_ADMIN to exceed what it allows
	for _, name := range []string{"net.core.wmem_max", "net.core.rmem_max"} {
		if n := f.sysctlInt(name); n >= 0 && n < 1<<20 {
			add(Advice{File: "sysctl", Key: name, Current: f.Sysctl[name], Value: "1048576",
				Reason: fmt.Sprintf("the sockets between weed and its workers get buffers of %s at most, and downloads lose a third of their speed", bytesText(n))})
		}
	}

	// Connection tracking, against new connections
	if ctMax := f.sysctlInt("net.netfilter.nf_conntrack_max"); ctMax > 0 {
		timeout := f.sysctlInt("net.netfilter.nf_conntrack_tcp_timeout_time_wait")
		if timeout <= 0 {
			timeout = 120
		}
		conns := bestRate(in.report, "connect")
		holds := float64(ctMax) / float64(timeout)
		if conns > holds/2 || in.counters.ConntrackDrops > 0 {
			want := nextPow2(max(int64(conns*float64(timeout)*2), ctMax*2))
			dropped := ""
			if d := in.counters.ConntrackDrops; d > 0 {
				dropped = fmt.Sprintf(", and the kernel dropped %d under the load", d)
			}
			add(Advice{File: "sysctl", Key: "net.netfilter.nf_conntrack_max", Current: strconv.FormatInt(ctMax, 10), Value: strconv.FormatInt(want, 10),
				Reason: fmt.Sprintf("the firewall tracks each connection until %d s after it closes: %d entries hold %.0f new connections a second, and weed took %.0f%s. "+
					"An entry takes some 300 bytes of the kernel's memory: %s when all are in use. "+
					"Rather than tracking them, a rule of the firewall can leave weed's port untracked (nftables: notrack)",
					timeout, ctMax, holds, conns, dropped, bytesText(want*300))})
			// The kernel's default: as many buckets of its hash table as entries
			if buckets := f.sysctlInt("net.netfilter.nf_conntrack_buckets"); buckets > 0 && buckets < want {
				add(Advice{File: "sysctl", Key: "net.netfilter.nf_conntrack_buckets", Current: strconv.FormatInt(buckets, 10), Value: strconv.FormatInt(want, 10),
					Reason: fmt.Sprintf("the hash table that finds the entries has %d buckets: %d entries would be %d to a bucket, on a list walked to find one. As many buckets as entries, the kernel's default, take %s",
						buckets, want, want/buckets, bytesText(want*8))})
			}
			add(Advice{File: "modules-load", Key: "nf_conntrack",
				Reason: "the settings net.netfilter.nf_conntrack_* exist once the module is loaded: loaded at boot, before the settings of /etc/sysctl.d"})
			if conns > holds {
				cannot = append(cannot, fmt.Sprintf("take %.0f new connections a second for long: connection tracking holds %.0f", conns, holds))
			}
		}
	}

	// The listen queue, if it overflowed under the load
	if n := in.counters.ListenOverflows + in.counters.ListenDrops; n > 0 {
		for _, name := range []string{"net.core.somaxconn", "net.ipv4.tcp_max_syn_backlog"} {
			cur := f.sysctlInt(name)
			want := max(cur*4, 16384)
			add(Advice{File: "sysctl", Key: name, Current: f.Sysctl[name], Value: strconv.FormatInt(want, 10),
				Reason: fmt.Sprintf("the kernel dropped %d connections under the load, its queue of connections not yet accepted full (and Backlog= of weed.socket, if you use it)", n)})
		}
		cannot = append(cannot, fmt.Sprintf("accept connections as fast as they came: the kernel dropped %d", n))
	}
	if in.counters.SoftnetDrops > 0 {
		cannot = append(cannot, fmt.Sprintf("take packets as fast as they came: the CPUs dropped %d (net.core.netdev_max_backlog)", in.counters.SoftnetDrops))
	}

	// Authentication: what is not a setting
	if r := passwordResult(in.report); r != nil && (in.cfgFile == "" || in.cfg.BasicAuth) {
		tok := ""
		for _, t := range in.report.Results {
			if t.Name == "get-small" && strings.HasSuffix(t.As, "(app-token)") {
				tok = fmt.Sprintf(", and %.0f by an app token", t.BestStep().ReqRate)
			}
		}
		add(Advice{Key: "basic", Reason: fmt.Sprintf("a password costs a bcrypt check (cost %d) on every request: weed answered %.0f a second authenticated by one%s. Give scripts and services app tokens (weed utils token), bearer tokens or certificates",
			f.BcryptCost, r.BestStep().ReqRate, tok)})
	}
	if strings.HasPrefix(f.HostKey, "RSA ") {
		if bits, _ := strconv.Atoi(strings.TrimPrefix(f.HostKey, "RSA ")); bits >= 3072 {
			add(Advice{Key: "tls.cert", Reason: fmt.Sprintf("the host key is %s, whose signature is most of the cost of a new connection (RSA 4096 signs in some 4.5 ms, ECDSA P-256 in 0.02 ms): an ECDSA host certificate, if your CA issues them, makes new connections cheaper", f.HostKey)})
		}
	}
	return advice, cannot
}

// threadsNeeded is what weed's workers may hold at most: each its calls to the
// storage, a thread per CPU and some more, and weed's own process
func threadsNeeded(cfg *config.Config, cpus int) int {
	return cfg.MaxWorkers*(cfg.WorkerMaxStorageCalls+cpus+50) + 200
}

// journalRate is how many lines a second the journal keeps of weed's unit (0: all)
func journalRate(f *Facts) float64 {
	if sd := f.Systemd; sd != nil && sd.LogBurst > 0 && sd.LogInterval > 0 {
		return float64(sd.LogBurst) / sd.LogInterval.Seconds()
	}
	return f.Journald.LinesPerSecond()
}

// peakRate is the most requests a second of a scenario of requests, and its name
func peakRate(rep *stress.Report) (float64, string) {
	best, name := 0.0, ""
	if rep == nil {
		return 0, ""
	}
	for _, r := range rep.Results {
		if r.Unit != "req/s" {
			continue
		}
		if v := r.BestStep().ReqRate; v > best {
			best, name = v, r.Name
		}
	}
	return best, name
}

// bestRate is the requests a second of the best step of the scenario name (0 if not run)
func bestRate(rep *stress.Report, name string) float64 {
	if rep == nil {
		return 0
	}
	for _, r := range rep.Results {
		if r.Name == name {
			return r.BestStep().ReqRate
		}
	}
	return 0
}

// passwordResult is the result of the requests authenticated by a password
func passwordResult(rep *stress.Report) *stress.Result {
	if rep == nil {
		return nil
	}
	for _, r := range rep.Results {
		if r.Name == "auth-basic" || r.Unit == "req/s" && strings.HasSuffix(r.As, "(basic)") && r.Name == "get-small" {
			return r
		}
	}
	return nil
}

// pidsMax finds pids.max in cgroup limits
func pidsMax(limits []string) (list []string, n int, ok bool) {
	for _, l := range limits {
		if v, found := strings.CutPrefix(l, "pids.max="); found {
			if n, err := strconv.Atoi(v); err == nil {
				return limits, n, true
			}
		}
	}
	return limits, 0, false
}

func setPidsMax(limits []string, n int) []string {
	out := slices.Clone(limits)
	for i, l := range out {
		if strings.HasPrefix(l, "pids.max=") {
			out[i] = "pids.max=" + strconv.Itoa(n)
		}
	}
	return out
}

func roundUp(n, to int) int { return (n + to - 1) / to * to }

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nextPow2(n int64) int64 {
	if n <= 1 {
		return 1
	}
	return 1 << (64 - bits.LeadingZeros64(uint64(n-1)))
}

// bitsText writes a rate in bits a second, and in bytes
func bitsText(bits float64) string {
	units := []string{"b/s", "kb/s", "Mb/s", "Gb/s", "Tb/s"}
	v, i := bits, 0
	for v >= 1000 && i < len(units)-1 {
		v /= 1000
		i++
	}
	return fmt.Sprintf("%s %s (%s/s)", trimFloat(v), units[i], strings.TrimSuffix(siBytes(bits/8), " "))
}

// bytesText writes a size in IEC units
func bytesText(n int64) string {
	for _, u := range []struct {
		n    int64
		name string
	}{{1 << 30, "GiB"}, {1 << 20, "MiB"}, {1 << 10, "KiB"}} {
		if n >= u.n {
			v := float64(n) / float64(u.n)
			return trimFloat(v) + " " + u.name
		}
	}
	return fmt.Sprintf("%d bytes", n)
}

func siBytes(v float64) string {
	units := []string{"B", "kB", "MB", "GB", "TB"}
	i := 0
	for v >= 1000 && i < len(units)-1 {
		v /= 1000
		i++
	}
	return trimFloat(v) + " " + units[i]
}

func trimFloat(v float64) string {
	if v >= 100 || v == math.Trunc(v) {
		return strconv.FormatFloat(math.Round(v), 'f', 0, 64)
	}
	return strconv.FormatFloat(v, 'f', 1, 64)
}
