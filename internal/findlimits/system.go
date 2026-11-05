package findlimits

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/labkode/weed/internal/stress"
)

// What this machine is, and how its kernel and systemd are set: what weed limits
// reads, without changing any of it

// Facts are what weed limits found of this machine
type Facts struct {
	Host        string            `json:"host"`
	Kernel      string            `json:"kernel"`
	CPUs        int               `json:"cpus"`
	Cores       int               `json:"cores,omitempty"`
	MemoryBytes int64             `json:"memory_bytes"`
	Storage     Storage           `json:"storage"`
	NICs        []NIC             `json:"nics,omitempty"`
	Sysctl      map[string]string `json:"sysctl"`
	Systemd     *Systemd          `json:"systemd,omitempty"`
	Journald    Journald          `json:"journald"`
	HostKey     string            `json:"host_key"`
	BcryptCost  int               `json:"bcrypt_cost,omitempty"`
}

// Storage is the file system of the exported directory
type Storage struct {
	Dir       string `json:"dir"`
	FSType    string `json:"fs_type"`
	Source    string `json:"source"`
	Network   bool   `json:"network"`
	FreeBytes int64  `json:"free_bytes"`
}

// NIC is a network interface of hardware, up
type NIC struct {
	Name      string `json:"name"`
	SpeedMbps int    `json:"speed_mbps"`
	MTU       int    `json:"mtu"`
}

// Systemd is what systemd sets of weed's unit
type Systemd struct {
	Unit      string `json:"unit"`
	Installed bool   `json:"installed"`
	// TasksMax is the most threads of the unit: "infinity", or a number
	TasksMax string `json:"tasks_max"`
	User     string `json:"user,omitempty"`
	// The unit's own limit of its lines in the journal (LogRateLimit*=, 0: journald's)
	LogBurst    int           `json:"log_rate_limit_burst,omitempty"`
	LogInterval time.Duration `json:"log_rate_limit_interval_ns,omitempty"`
}

// Journald is journald's limit of the lines of a service: Burst every Interval (0:
// none)
type Journald struct {
	Burst    int           `json:"rate_limit_burst"`
	Interval time.Duration `json:"rate_limit_interval_ns"`
}

// LinesPerSecond is what the journal keeps of a service, at most, sustained (0: no
// limit); journald raises the burst on disks with much free space, a few times at most
func (j Journald) LinesPerSecond() float64 {
	if j.Burst == 0 || j.Interval == 0 {
		return 0
	}
	return float64(j.Burst) / j.Interval.Seconds()
}

// The kernel's settings that weed limits reads
var sysctls = []string{
	"net.core.somaxconn", "net.ipv4.tcp_max_syn_backlog",
	"net.ipv4.tcp_rmem", "net.ipv4.tcp_wmem", "net.ipv4.tcp_mem", "net.core.rmem_max", "net.core.wmem_max",
	"net.ipv4.tcp_congestion_control", "net.core.default_qdisc",
	"net.netfilter.nf_conntrack_max", "net.netfilter.nf_conntrack_buckets", "net.netfilter.nf_conntrack_count", "net.netfilter.nf_conntrack_tcp_timeout_time_wait",
	"kernel.threads-max", "kernel.pid_max",
}

func readSysctl(name string) (string, bool) {
	b, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(name, ".", "/"))
	if err != nil {
		return "", false
	}
	return strings.Join(strings.Fields(string(b)), " "), true
}

// sysctlInts is the numbers of a setting, such as net.ipv4.tcp_wmem's three
func sysctlInts(v string) []int64 {
	var ns []int64
	for _, f := range strings.Fields(v) {
		n, err := strconv.ParseInt(f, 10, 64)
		if err != nil {
			return nil
		}
		ns = append(ns, n)
	}
	return ns
}

// sysctlInt is the last number of a setting, -1 without
func (f *Facts) sysctlInt(name string) int64 {
	ns := sysctlInts(f.Sysctl[name])
	if len(ns) == 0 {
		return -1
	}
	return ns[len(ns)-1]
}

// readFacts reads what this machine is, its storage being dir
func readFacts(dir, unit string) *Facts {
	f := &Facts{CPUs: runtime.NumCPU(), Cores: stress.Cores(), Sysctl: make(map[string]string)}
	f.Host, _ = os.Hostname()
	var uts unix.Utsname
	if unix.Uname(&uts) == nil {
		f.Kernel = unix.ByteSliceToString(uts.Release[:])
	}
	if m := meminfo()["MemTotal:"]; m > 0 {
		f.MemoryBytes = m << 10
	}
	f.Storage = storageOf(dir)
	f.NICs = nics()
	for _, name := range sysctls {
		if v, ok := readSysctl(name); ok {
			f.Sysctl[name] = v
		}
	}
	f.Systemd = systemdOf(unit)
	f.Journald = journaldLimits()
	return f
}

func meminfo() map[string]int64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return nil
	}
	m := make(map[string]int64)
	for line := range strings.Lines(string(b)) {
		if f := strings.Fields(line); len(f) >= 2 {
			n, _ := strconv.ParseInt(f[1], 10, 64)
			m[f[0]] = n
		}
	}
	return m
}

// networkFS are the file systems whose calls wait for the network
var networkFS = []string{"nfs", "nfs4", "cifs", "smb3", "smbfs", "ceph", "lustre", "gpfs", "beegfs", "glusterfs", "9p", "afs", "virtiofs"}

// storageOf is the file system that dir is on, from /proc/self/mountinfo
func storageOf(dir string) Storage {
	s := Storage{Dir: dir}
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real
	}
	var st unix.Statfs_t
	if unix.Statfs(dir, &st) == nil {
		s.FreeBytes = int64(st.Bavail) * st.Bsize
	}
	s.FSType, s.Source = mountOf(dir, "/proc/self/mountinfo")
	s.Network = slices.Contains(networkFS, s.FSType) || strings.HasPrefix(s.FSType, "fuse")
	return s
}

// mountOf is the type and source of the mount of path, in mountinfo: the one of the
// longest mount point that holds it
func mountOf(path, mountinfo string) (fstype, source string) {
	f, err := os.Open(mountinfo)
	if err != nil {
		return "", ""
	}
	defer f.Close()
	best := -1
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
		fields := strings.Fields(sc.Text())
		sep := slices.Index(fields, "-")
		if len(fields) < 5 || sep < 0 || sep+2 >= len(fields) {
			continue
		}
		mp := unescapeMount(fields[4])
		if !strings.HasPrefix(path, mp) || (mp != "/" && len(path) > len(mp) && path[len(mp)] != '/') {
			continue
		}
		if len(mp) >= best {
			best = len(mp)
			fstype, source = fields[sep+1], unescapeMount(fields[sep+2])
		}
	}
	return fstype, source
}

// unescapeMount undoes the octal escapes of mountinfo (\040 is a space)
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// nics are the network interfaces of hardware that are up, with their speed
func nics() []NIC {
	paths, _ := filepath.Glob("/sys/class/net/*")
	var list []NIC
	for _, p := range paths {
		if _, err := os.Stat(filepath.Join(p, "device")); err != nil {
			continue // virtual: lo, bridges, veths, tunnels
		}
		if state, _ := os.ReadFile(filepath.Join(p, "operstate")); strings.TrimSpace(string(state)) != "up" {
			continue
		}
		n := NIC{Name: filepath.Base(p)}
		n.SpeedMbps, _ = readInt(filepath.Join(p, "speed"))
		n.MTU, _ = readInt(filepath.Join(p, "mtu"))
		list = append(list, n)
	}
	return list
}

func readInt(file string) (int, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

// fastestNIC is the speed of the fastest network interface, in bits per second (0:
// unknown)
func (f *Facts) fastestNIC() float64 {
	best := 0
	for _, n := range f.NICs {
		best = max(best, n.SpeedMbps)
	}
	return float64(best) * 1e6
}

// systemdOf is what systemd sets of unit; nil without systemd
func systemdOf(unit string) *Systemd {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return nil
	}
	out, err := exec.Command("systemctl", "show", unit, "-p", "LoadState", "-p", "TasksMax", "-p", "User",
		"-p", "LogRateLimitBurst", "-p", "LogRateLimitIntervalUSec").Output()
	if err != nil {
		return nil
	}
	s := &Systemd{Unit: unit}
	for line := range strings.Lines(string(out)) {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch k {
		case "LoadState":
			s.Installed = v == "loaded"
		case "TasksMax":
			s.TasksMax = v
		case "User":
			s.User = v
		case "LogRateLimitBurst":
			s.LogBurst, _ = strconv.Atoi(v)
		case "LogRateLimitIntervalUSec":
			s.LogInterval, _ = parseTimespan(v)
		}
	}
	return s
}

// tasksMax is TasksMax as a number (-1 for infinity or unknown)
func (s *Systemd) tasksMax() int64 {
	if s == nil {
		return -1
	}
	n, err := strconv.ParseInt(s.TasksMax, 10, 64)
	if err != nil { // infinity, or 2^64-1
		return -1
	}
	return n
}

// journaldLimits reads journald's rate limit, from journald.conf and its drop-ins in
// the order journald reads them
func journaldLimits() Journald {
	j := Journald{Burst: 10000, Interval: 30 * time.Second}
	files := []string{"/etc/systemd/journald.conf"}
	drop := map[string]string{}
	for _, dir := range []string{"/usr/lib/systemd/journald.conf.d", "/usr/local/lib/systemd/journald.conf.d",
		"/run/systemd/journald.conf.d", "/etc/systemd/journald.conf.d"} {
		paths, _ := filepath.Glob(filepath.Join(dir, "*.conf"))
		for _, p := range paths {
			drop[filepath.Base(p)] = p // a later directory overrides a file of the same name
		}
	}
	names := make([]string, 0, len(drop))
	for n := range drop {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		files = append(files, drop[n])
	}
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		parseJournald(string(b), &j)
	}
	return j
}

func parseJournald(conf string, j *Journald) {
	for line := range strings.Lines(conf) {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.HasPrefix(k, "#") || strings.HasPrefix(k, ";") {
			continue
		}
		switch strings.TrimSpace(k) {
		case "RateLimitBurst":
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				j.Burst = n
			}
		case "RateLimitIntervalSec", "RateLimitInterval":
			if d, err := parseTimespan(strings.TrimSpace(v)); err == nil {
				j.Interval = d
			}
		}
	}
}

// parseTimespan reads a time span of systemd: "30s", "1min 30s", "500ms", "30" (s)
func parseTimespan(s string) (time.Duration, error) {
	units := []struct {
		suffix string
		d      time.Duration
	}{ // the longest first
		{"minutes", time.Minute}, {"seconds", time.Second}, {"minute", time.Minute}, {"second", time.Second},
		{"hours", time.Hour}, {"usec", time.Microsecond}, {"msec", time.Millisecond}, {"hour", time.Hour},
		{"sec", time.Second}, {"min", time.Minute}, {"us", time.Microsecond}, {"ms", time.Millisecond},
		{"hr", time.Hour}, {"s", time.Second}, {"m", time.Minute}, {"h", time.Hour}}
	var total time.Duration
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0, strconv.ErrSyntax
	}
	for _, f := range fields {
		unit := time.Second
		for _, u := range units {
			if num, ok := strings.CutSuffix(f, u.suffix); ok && num != "" {
				f, unit = num, u.d
				break
			}
		}
		n, err := strconv.ParseFloat(f, 64)
		if err != nil {
			return 0, err
		}
		total += time.Duration(n * float64(unit))
	}
	return total, nil
}

// --- Counters, before and after the load

// Counters are the kernel's counts of what it dropped, which weed limits reads before
// and after the load
type Counters struct {
	ListenOverflows int64 `json:"listen_overflows"`
	ListenDrops     int64 `json:"listen_drops"`
	ConntrackDrops  int64 `json:"conntrack_drops"`
	SoftnetDrops    int64 `json:"softnet_drops"`
}

func readCounters() Counters {
	var c Counters
	tcp := netstat("/proc/net/netstat")["TcpExt"]
	c.ListenOverflows, c.ListenDrops = tcp["ListenOverflows"], tcp["ListenDrops"]
	c.ConntrackDrops = conntrackDrops("/proc/net/stat/nf_conntrack")
	c.SoftnetDrops = softnetDrops("/proc/net/softnet_stat")
	return c
}

func (c Counters) minus(o Counters) Counters {
	return Counters{c.ListenOverflows - o.ListenOverflows, c.ListenDrops - o.ListenDrops,
		c.ConntrackDrops - o.ConntrackDrops, c.SoftnetDrops - o.SoftnetDrops}
}

// netstat reads a file of pairs of lines "Prefix: names..." and "Prefix: values..."
func netstat(file string) map[string]map[string]int64 {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	all := make(map[string]map[string]int64)
	var names []string
	for line := range strings.Lines(string(b)) {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		prefix := strings.TrimSuffix(f[0], ":")
		if names == nil || names[0] != f[0] {
			names = f
			continue
		}
		m := make(map[string]int64)
		for i := 1; i < len(f) && i < len(names); i++ {
			m[names[i]], _ = strconv.ParseInt(f[i], 10, 64)
		}
		all[prefix] = m
		names = nil
	}
	return all
}

// conntrackDrops sums, over the CPUs, the connections that connection tracking
// dropped (drop, early_drop, insert_failed), from a table of hexadecimal numbers
func conntrackDrops(file string) int64 {
	b, err := os.ReadFile(file)
	if err != nil {
		return 0
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) < 2 {
		return 0
	}
	header := strings.Fields(lines[0])
	var sum int64
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		for i, name := range header {
			if i < len(f) && (name == "drop" || name == "early_drop" || name == "insert_failed") {
				n, _ := strconv.ParseInt(f[i], 16, 64)
				sum += n
			}
		}
	}
	return sum
}

// softnetDrops sums the packets that the CPUs dropped as their backlog was full
// (net.core.netdev_max_backlog): the second column, hexadecimal
func softnetDrops(file string) int64 {
	b, err := os.ReadFile(file)
	if err != nil {
		return 0
	}
	var sum int64
	for line := range strings.Lines(string(b)) {
		if f := strings.Fields(line); len(f) >= 2 {
			n, _ := strconv.ParseInt(f[1], 16, 64)
			sum += n
		}
	}
	return sum
}

// CgroupEvents are what weed's cgroup and those below it counted while it ran: a
// thread or process refused for pids.max, a process killed for memory.max, and the
// most threads and memory
type CgroupEvents struct {
	PidsMax     int64 `json:"pids_max_events"`
	OOMKills    int64 `json:"oom_kills"`
	PidsPeak    int64 `json:"pids_peak,omitempty"`
	MemoryPeak  int64 `json:"memory_peak_bytes,omitempty"`
	WorkersPeak int64 `json:"worker_threads_peak,omitempty"`
}

func cgroupEvents(dir string) CgroupEvents {
	var e CgroupEvents
	if dir == "" {
		return e
	}
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		ev := readKV(filepath.Join(p, "pids.events"))
		e.PidsMax = max(e.PidsMax, ev["max"])
		mem := readKV(filepath.Join(p, "memory.events"))
		e.OOMKills = max(e.OOMKills, mem["oom_kill"])
		if strings.HasPrefix(filepath.Base(p), "worker-") {
			n, _ := readInt(filepath.Join(p, "pids.peak"))
			e.WorkersPeak = max(e.WorkersPeak, int64(n))
		}
		return nil
	})
	n, _ := readInt(filepath.Join(dir, "pids.peak"))
	e.PidsPeak = int64(n)
	if b, err := os.ReadFile(filepath.Join(dir, "memory.peak")); err == nil {
		e.MemoryPeak, _ = strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	}
	return e
}

// readKV reads a file of lines "name number"
func readKV(file string) map[string]int64 {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	m := make(map[string]int64)
	for line := range strings.Lines(string(b)) {
		if f := strings.Fields(line); len(f) == 2 {
			m[f[0]], _ = strconv.ParseInt(f[1], 10, 64)
		}
	}
	return m
}
