package findlimits

import (
	"context"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/stress"
)

const weedTOML = `# weed, as installed
[server]
port = 8443   # the port
dir = "/data"

[unix_users]
max_storage_calls = 256
cgroup_limits = [
  "memory.max=8G",
  "pids.max=300",  # threads, [sic]
]

[admin]
socket = ""
`

func TestEditTOML(t *testing.T) {
	got := editTOML(weedTOML, []tomlChange{
		{Section: "unix_users", Key: "max_storage_calls", Value: "1024", Reason: "the storage serves more calls at once"},
		{Section: "unix_users", Key: "cgroup_limits", Value: `["memory.max=8G", "pids.max=1200"]`, Reason: "threads"},
		{Section: "server", Key: "log_file", Value: `"/var/log/weed/weed.log"`, Reason: "the journal drops lines"},
		{Section: "basic", Key: "enabled", Value: "true", Reason: "a section of its own"},
	})
	want := `# weed, as installed
[server]
port = 8443   # the port
dir = "/data"
# weed limits: the journal drops lines
log_file = "/var/log/weed/weed.log"

[unix_users]
# weed limits: the storage serves more calls at once
# was: max_storage_calls = 256
max_storage_calls = 1024
# weed limits: threads
# was: cgroup_limits = [
#        "memory.max=8G",
#        "pids.max=300",  # threads, [sic]
#      ]
cgroup_limits = ["memory.max=8G", "pids.max=1200"]

[admin]
socket = ""

[basic]
# weed limits: a section of its own
enabled = true
`
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	// What it writes is a configuration of weed, with the values it set
	f := filepath.Join(t.TempDir(), "weed.toml")
	if err := os.WriteFile(f, []byte(got), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(f)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WorkerMaxStorageCalls != 1024 || !slices.Equal(cfg.WorkerCgroupLimits, []string{"memory.max=8G", "pids.max=1200"}) ||
		cfg.LogFile != "/var/log/weed/weed.log" || cfg.Port != 8443 || !cfg.BasicAuth {
		t.Errorf("loaded %+v", cfg)
	}
}

func TestValueLines(t *testing.T) {
	for _, tc := range []struct {
		value string
		next  []string
		want  int
	}{
		{`"x"`, []string{"a = 1"}, 0},
		{`["a", "b"]`, []string{"]"}, 0},
		{`[`, []string{`"a]",`, `"#b",`, `]`, `x = 1`}, 3},
		{`[ # a comment [`, []string{`"a"`, `] # done`}, 2},
		{`"""`, []string{"text", `"""`}, 2},
		{`"""one line"""`, []string{`"""`}, 0},
	} {
		if got := valueLines(tc.value, tc.next); got != tc.want {
			t.Errorf("valueLines(%q) = %d, want %d", tc.value, got, tc.want)
		}
	}
}

func TestParseTimespan(t *testing.T) {
	for s, want := range map[string]time.Duration{
		"30s": 30 * time.Second, "30": 30 * time.Second, "1min 30s": 90 * time.Second, "500ms": 500 * time.Millisecond,
		"2h": 2 * time.Hour, "1.5min": 90 * time.Second, "250us": 250 * time.Microsecond, "10sec": 10 * time.Second,
	} {
		if got, err := parseTimespan(s); err != nil || got != want {
			t.Errorf("parseTimespan(%q) = %v, %v; want %v", s, got, err, want)
		}
	}
	if _, err := parseTimespan("soon"); err == nil {
		t.Error("parseTimespan(soon): no error")
	}
}

func TestParseJournald(t *testing.T) {
	j := Journald{Burst: 10000, Interval: 30 * time.Second}
	parseJournald("[Journal]\n#RateLimitBurst=1\nRateLimitBurst = 50000\nRateLimitIntervalSec=10s\n", &j)
	if j.Burst != 50000 || j.Interval != 10*time.Second || j.LinesPerSecond() != 5000 {
		t.Errorf("got %+v", j)
	}
	parseJournald("RateLimitIntervalSec=0\n", &j)
	if j.LinesPerSecond() != 0 {
		t.Errorf("RateLimitIntervalSec=0: %v lines a second, want no limit", j.LinesPerSecond())
	}
}

func TestMountOf(t *testing.T) {
	f := filepath.Join(t.TempDir(), "mountinfo")
	os.WriteFile(f, []byte(`22 1 0:21 / / rw,relatime shared:1 - btrfs /dev/nvme0n1p3 rw
40 22 0:35 / /data rw,relatime shared:2 - xfs /dev/sdb1 rw
41 40 0:36 / /data/my\040disk rw shared:3 - nfs4 server:/export rw
42 22 0:37 / /dat rw shared:4 - tmpfs tmpfs rw
`), 0o644)
	for path, want := range map[string]string{
		"/home/x": "btrfs /dev/nvme0n1p3", "/data": "xfs /dev/sdb1", "/data/a/b": "xfs /dev/sdb1",
		"/data/my disk/f": "nfs4 server:/export", "/database": "btrfs /dev/nvme0n1p3", "/dat": "tmpfs tmpfs",
	} {
		if typ, src := mountOf(path, f); typ+" "+src != want {
			t.Errorf("mountOf(%s) = %s %s, want %s", path, typ, src, want)
		}
	}
}

func TestCounters(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(s), 0o644)
		return p
	}
	ns := netstat(write("netstat", "TcpExt: SyncookiesSent ListenOverflows ListenDrops\nTcpExt: 1 7 9\nIpExt: InNoRoutes\nIpExt: 3\n"))
	if ns["TcpExt"]["ListenOverflows"] != 7 || ns["TcpExt"]["ListenDrops"] != 9 || ns["IpExt"]["InNoRoutes"] != 3 {
		t.Errorf("netstat: %v", ns)
	}
	ct := write("nf_conntrack", "entries clashres found new invalid ignore delete delete_list insert insert_failed drop early_drop\n"+
		"0000000a 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001 00000010 00000002\n"+
		"0000000a 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001 00000000\n")
	if got := conntrackDrops(ct); got != 1+16+2+1 {
		t.Errorf("conntrackDrops = %d, want 20", got)
	}
	if got := softnetDrops(write("softnet", "0000abcd 00000002 00000000\n0000abcd 0000000f 00000000\n")); got != 17 {
		t.Errorf("softnetDrops = %d, want 17", got)
	}
}

func TestParseBits(t *testing.T) {
	for s, want := range map[string]float64{"10G": 10e9, "2.5Gbit": 2.5e9, "100M": 100e6, "1000": 1000, "40Gb": 40e9} {
		if got, err := parseBits(s); err != nil || got != want {
			t.Errorf("parseBits(%q) = %v, %v; want %v", s, got, err, want)
		}
	}
	if _, err := parseBits("fast"); err == nil {
		t.Error("parseBits(fast): no error")
	}
}

// facts of a machine of 16 CPUs, its unit and kernel set as installed
func testFacts() *Facts {
	return &Facts{CPUs: 16, Cores: 8, NICs: []NIC{{Name: "eth0", SpeedMbps: 10000}},
		Systemd:  &Systemd{Unit: "weed.service", Installed: true, TasksMax: "infinity", User: "root"},
		Journald: Journald{Burst: 10000, Interval: 30 * time.Second},
		Sysctl: map[string]string{
			"net.ipv4.tcp_wmem": "4096 16384 4194304", "net.ipv4.tcp_rmem": "4096 131072 6291456",
			"net.core.wmem_max": "1048576", "net.core.rmem_max": "1048576",
			"net.core.somaxconn": "4096", "net.ipv4.tcp_max_syn_backlog": "4096",
			"net.netfilter.nf_conntrack_max": "262144", "net.netfilter.nf_conntrack_tcp_timeout_time_wait": "120",
			"net.netfilter.nf_conntrack_buckets": "262144",
		}}
}

func testReport(rates map[string]float64) *stress.Report {
	rep := &stress.Report{}
	for _, name := range []string{"get-small", "connect", "auth-basic"} {
		if r, ok := rates[name]; ok {
			rep.Results = append(rep.Results, stress.NewResult(name, "alice (cert)", "req/s", stress.Step{Clients: 64, ReqRate: r}))
		}
	}
	return rep
}

func keys(advice []Advice) []string {
	var k []string
	for _, a := range advice {
		k = append(k, a.File+":"+a.Key)
	}
	return k
}

func TestAdvise(t *testing.T) {
	quiet := func() *inputs {
		cfg := config.Default()
		cfg.LogFile = "/var/log/weed/weed.log"
		return &inputs{cfg: cfg, facts: testFacts(), report: testReport(map[string]float64{"get-small": 20000, "connect": 300})}
	}
	if a, cannot := advise(quiet()); len(a) != 0 || len(cannot) != 2 { // the TCP buffers, without -rtt: send and receive
		t.Errorf("a machine set well: %v, %q", keys(a), cannot)
	}

	in := quiet()
	in.facts.Systemd.TasksMax = "9830"
	if a, _ := advise(in); !slices.Contains(keys(a), "unit:TasksMax") {
		t.Errorf("TasksMax=9830: %v", keys(a))
	}

	in = quiet()
	in.cfg.LogFile = ""
	if a, _ := advise(in); !slices.Contains(keys(a), "weed.toml:server.log_file") || !slices.Contains(keys(a), "unit:LogsDirectory") {
		t.Errorf("20000 requests a second to the journal: %v", keys(a))
	}
	in.facts.Journald.Interval = 0 // no limit
	if a, _ := advise(in); slices.Contains(keys(a), "weed.toml:server.log_file") {
		t.Errorf("a journal without a limit: %v", keys(a))
	}

	in = quiet()
	in.probe = &Probe{Parallel: []ParallelPoint{{Calls: 256, PerSecond: 100000}, {Calls: 1024, PerSecond: 200000}}}
	in.cfg.WorkerCgroupLimits = []string{"memory.max=8G", "pids.max=500"}
	if a, _ := advise(in); slices.Contains(keys(a), "weed.toml:unix_users.max_storage_calls") {
		t.Errorf("a local storage, whose probe measures the page cache: %v", keys(a))
	}
	in.facts.Storage.Network = true
	a, _ := advise(in)
	if !slices.Contains(keys(a), "weed.toml:unix_users.max_storage_calls") || a[0].Value != "1024" {
		t.Fatalf("a storage that serves more calls at once: %v", keys(a))
	}
	// pids.max follows the calls that it suggests
	if i := slices.Index(keys(a), "weed.toml:unix_users.cgroup_limits"); i < 0 || a[i].Value != `["memory.max=8G", "pids.max=1200"]` {
		t.Errorf("pids.max: %v", a)
	}
	in.probe.Parallel[1].PerSecond = 110000
	if a, _ := advise(in); slices.Contains(keys(a), "weed.toml:unix_users.max_storage_calls") {
		t.Errorf("a storage that serves 10%% more: %v", keys(a))
	}

	in = quiet()
	in.rtt = 100 * time.Millisecond
	a, _ = advise(in)
	// 10 Gb/s over 100 ms: 125 MB in flight, twice that, 256 MiB
	if i := slices.Index(keys(a), "sysctl:net.ipv4.tcp_wmem"); i < 0 || a[i].Value != "4096 16384 268435456" {
		t.Errorf("-rtt 100ms: %v", a)
	}

	in = quiet()
	in.facts.Sysctl["net.core.wmem_max"], in.facts.Sysctl["net.core.rmem_max"] = "212992", "212992"
	if a, _ := advise(in); !slices.Contains(keys(a), "sysctl:net.core.wmem_max") || !slices.Contains(keys(a), "sysctl:net.core.rmem_max") {
		t.Errorf("the kernel's default socket buffers: %v", keys(a))
	}

	in = quiet()
	in.report = testReport(map[string]float64{"get-small": 20000, "connect": 2000})
	a, _ = advise(in)
	if !slices.Contains(keys(a), "sysctl:net.netfilter.nf_conntrack_max") || !slices.Contains(keys(a), "modules-load:nf_conntrack") {
		t.Errorf("2000 connections a second: %v", keys(a))
	}
	// 2000 a second for 120 s, twice: 524288 entries, in as many buckets, of 150 MiB
	// and 4 MiB; drops are told only when there were some
	if i := slices.Index(keys(a), "sysctl:net.netfilter.nf_conntrack_buckets"); i < 0 || a[i].Value != "524288" {
		t.Errorf("buckets: %v", a)
	}
	for _, x := range a {
		if x.Key == "net.netfilter.nf_conntrack_max" && (!strings.Contains(x.Reason, "150 MiB") || strings.Contains(x.Reason, "dropped")) {
			t.Errorf("the reason: %s", x.Reason)
		}
	}

	in = quiet()
	in.counters.ListenOverflows = 12
	if a, _ := advise(in); !slices.Contains(keys(a), "sysctl:net.core.somaxconn") {
		t.Errorf("listen overflows: %v", keys(a))
	}

	in = quiet()
	in.report = testReport(map[string]float64{"get-small": 20000, "connect": 300, "auth-basic": 150})
	in.facts.BcryptCost = 10
	if a, _ := advise(in); !slices.Contains(keys(a), ":basic") {
		t.Errorf("passwords: %v", keys(a))
	}
	// Of a configuration that enables no passwords, weed limits measured its own
	in.cfgFile = "/etc/weed/weed.toml"
	if a, _ := advise(in); slices.Contains(keys(a), ":basic") {
		t.Errorf("passwords, of a configuration without: %v", keys(a))
	}
	in.cfg.BasicAuth = true
	if a, _ := advise(in); !slices.Contains(keys(a), ":basic") {
		t.Errorf("passwords, of a configuration with: %v", keys(a))
	}
}

// The load authenticates by the cheapest method of the configuration first, by an app
// token rather than a password; by a WLCG token and Basic if it enables none
func TestMethodsOf(t *testing.T) {
	cfg := func(f func(*config.Config)) *config.Config {
		c := config.Default()
		f(c)
		return c
	}
	for _, c := range []struct {
		name   string
		cfg    *config.Config
		noFile bool
		want   string
		none   bool
	}{
		{"no file", config.Default(), true, "cert bearer app-token basic", false},
		{"none enabled", config.Default(), false, "bearer app-token basic", true},
		{"none enabled, TLS", cfg(func(c *config.Config) { c.TLS = true }), false, "cert bearer app-token basic", true},
		{"basic", cfg(func(c *config.Config) { c.BasicAuth = true }), false, "app-token basic", false},
		{"x509 and tokens", cfg(func(c *config.Config) { c.TLS, c.X509Auth, c.TokenIssuers = true, true, "i.json" }), false, "cert bearer", false},
	} {
		m := methodsOf(c.cfg, c.noFile)
		if got := strings.Join(m.kinds(), " "); got != c.want || m.none != c.none {
			t.Errorf("%s: %s (none %v), want %s (none %v)", c.name, got, m.none, c.want, c.none)
		}
	}
	if got := loadText([]string{"app-token", "basic"}); got != "authenticated by an app token, in auth-basic by a password" {
		t.Errorf("loadText: %s", got)
	}
}

func TestThreadsNeeded(t *testing.T) {
	cfg := config.Default()
	// 256 workers × (256 calls + 24 CPUs + 50) + 200
	if got := threadsNeeded(cfg, 24); got != 84680 {
		t.Errorf("threadsNeeded = %d", got)
	}
}

func TestCredsAndIssuer(t *testing.T) {
	dir := t.TempDir()
	c, err := newCreds(dir, "alice", keySpec{Kind: "ECDSA", Curve: elliptic.P256()}, 4, true)
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	if k, err := hostKeyOf(c.hostCert); err != nil || k.String() != "ECDSA P-256" {
		t.Errorf("hostKeyOf = %v, %v", k, err)
	}
	if got := bcryptCostOf(c.htpasswd); got != 4 {
		t.Errorf("bcryptCostOf = %d", got)
	}
	gm, _ := os.ReadFile(c.gridmap)
	if want := `"` + c.userDN + `" alice`; strings.TrimSpace(string(gm)) != want || !strings.Contains(c.userDN, "/CN=alice") {
		t.Errorf("grid-mapfile %q, want %q", gm, want)
	}

	// The token verifies with the key of the issuer's JWKS, found by discovery
	pool := x509.NewCertPool()
	pool.AddCert(c.caCert)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	var disco struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	getJSON(t, client, c.issuer.url+"/.well-known/openid-configuration", &disco)
	var set jose.JSONWebKeySet
	getJSON(t, client, disco.JWKSURI, &set)
	b, _ := os.ReadFile(c.tokenFile)
	tok, err := jwt.ParseSigned(strings.TrimSpace(string(b)), []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	var claims jwt.Claims
	var wlcg struct {
		Ver   string `json:"wlcg.ver"`
		Scope string `json:"scope"`
	}
	if len(tok.Headers) != 1 || len(set.Key(tok.Headers[0].KeyID)) != 1 {
		t.Fatalf("the token's key %q is not in the JWKS", tok.Headers[0].KeyID)
	}
	if err := tok.Claims(set.Key(tok.Headers[0].KeyID)[0].Key, &claims, &wlcg); err != nil {
		t.Fatal(err)
	}
	if err := claims.Validate(jwt.Expected{Issuer: disco.Issuer, Subject: "alice", AnyAudience: jwt.Audience{c.audience}}); err != nil {
		t.Error(err)
	}
	if wlcg.Ver != "1.0" || !strings.Contains(wlcg.Scope, "storage.modify:/") {
		t.Errorf("claims %+v", wlcg)
	}
	var rules []map[string]any
	ib, _ := os.ReadFile(c.issuers)
	if err := json.Unmarshal(ib, &rules); err != nil || len(rules) != 1 || rules[0]["issuer"] != disco.Issuer {
		t.Errorf("issuers %s: %v", ib, err)
	}
}

func getJSON(t *testing.T, client *http.Client, url string, v any) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("%s: %v", url, err)
	}
}

func TestProbeStorage(t *testing.T) {
	dir := t.TempDir()
	size := probeSize{commits: 5, duration: 20 * time.Millisecond, files: 20, writeSize: 2 << 20}
	p, err := probeStorage(context.Background(), dir, size, 256)
	if err != nil {
		t.Fatal(err)
	}
	if p.CommitP50 <= 0 || p.CommitP99 < p.CommitP50 || p.CommitsPerSec <= 0 || p.WriteBytesPerSec <= 0 {
		t.Errorf("probe %+v", p)
	}
	var calls []int
	for _, pt := range p.Parallel {
		calls = append(calls, pt.Calls)
		if pt.PerSecond <= 0 {
			t.Errorf("%d at once: %v a second", pt.Calls, pt.PerSecond)
		}
	}
	if !slices.Equal(calls, []int{1, 4, 16, 64, 256, 1024}) {
		t.Errorf("calls at once %v", calls)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Errorf("the probe left %v", left)
	}
	if got := parallelCalls(100); !slices.Equal(got, []int{1, 4, 16, 25, 64, 100, 256, 400, 1024}) {
		t.Errorf("parallelCalls(100) = %v", got)
	}
}

func TestEditTOMLEmpty(t *testing.T) {
	got := editTOML("", []tomlChange{{Section: "server", Key: "log_file", Value: `"/var/log/weed/weed.log"`, Reason: "the journal"}})
	if want := "[server]\n# weed limits: the journal\nlog_file = \"/var/log/weed/weed.log\"\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
