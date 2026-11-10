// Package stress finds the limits of a weed server, and of the machine it runs on:
// test/stress is its command, and weed limits runs it against a weed of its own. For
// each scenario it doubles the number of concurrent clients (1, 2, 4, ...) until
// throughput stops growing, requests fail or latency explodes, and reports what each
// step reached, with what weed used of the CPUs when it runs on the same machine.
// Two scenarios instead grow a crowd of thousands of clients that each hold a
// connection, and make requests now and then, or read slowly.
//
//	stress -url https://weed.example.org/webdav/alice -cert usercert.pem -key userkey.pem
//	stress -identities ids.txt -as alice -url 'https://localhost:9443/webdav/{user}' -ca ca.pem
//
// It works in a directory of its own below the URL (weed-stress-...), which it
// removes at the end, also when interrupted.
package stress

import (
	"bufio"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/labkode/weed/internal/x509utils"
)

const usage = `stress finds the limits of a weed server: for each scenario, it doubles the
number of concurrent clients until throughput stops growing, requests fail or
latency explodes. The scenarios clients and slow-download grow a crowd instead: up
to thousands of clients that stay connected from one step to the next, until weed
fails them, they fall behind, or this machine runs out of memory.

  stress -url URL CREDENTIALS [OPTIONS]

URL is a directory that the credentials can write: stress works in a directory of
its own below it (weed-stress-...), and removes it at the end, also when
interrupted.

CREDENTIALS, of one identity:
  -cert FILE -key FILE            an X.509 certificate (a proxy: -cert alone)
  -token TOKEN, -token-file FILE  a bearer token (a WLCG token, a macaroon)
  -user NAME -password PASSWORD   a password (Basic authentication)
or of several, which the scenarios auth and accounts need:
  -identities FILE                lines of NAME basic PASSWORD, NAME app-token TOKEN
                                  (Basic too, without bcrypt), NAME bearer TOKEN,
                                  NAME bearer @TOKENFILE (read again before each
                                  step) or NAME cert CERT KEY; -as
                                  NAME picks the one of the other scenarios (the
                                  first by default), and {user} in URL becomes
                                  each one's name

Scenarios (-scenarios, comma-separated; all by default):
  get-small  GET of a small file (-small-size)
  put-small  PUT of a small file, each client to a file of its own
  list       PROPFIND, Depth 1, of a directory of -list-entries files
  connect    GET of the small file, on a new connection (with https, a full TLS
             handshake) each time
  download   GET of a large file (-download-size): throughput. The same file every
             time, which weed's machine reads from memory rather than from its disk
  upload     PUT of large files (-upload-size), each deleted after: throughput
  auth       get-small as the first identity of each other authentication method
  accounts   get-small, client i as identity i of the method with the most
             identities: as many accounts, each with a worker of its own
  clients    clients that each hold a connection of their own, and make a GET of
             the small file every -interval: six steps of up to -clients clients
  slow-download
             clients that each download the large file at -client-rate, on a
             connection of their own, as jobs that read across a WAN: six steps
             of up to -clients clients
The clients of clients and slow-download are all the first identity, or with
-crowd-accounts, client i identity i of the identities of accounts.

Run it from another machine than weed's to measure weed's alone: on weed's machine,
it takes CPUs from weed, and says how many. There, -cgroup adds what weed used.

Options:
`

// Main runs stress with the arguments of its command line (see usage), until ctx is
// done; it returns the exit status
func Main(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	_, code := Run(ctx, args, stdout, stderr)
	return code
}

// Report is what stress found: the results of its scenarios, from a machine of CPUs
// and MemoryBytes (as -json writes it)
type Report struct {
	URL         string    `json:"url"`
	CPUs        int       `json:"cpus"`
	MemoryBytes int64     `json:"memory_bytes"`
	Results     []*Result `json:"results"`
}

type config struct {
	scenarios                           []string
	start, max                          int
	step, warmup, maxP99                time.Duration
	smallSize, downloadSize, uploadSize int64
	clients                             int           // of the last step of a crowd
	crowdAccounts                       bool          // crowds as the identities of accounts
	interval                            time.Duration // between the requests of each client of clients
	clientRate                          int64         // what each client of slow-download reads per second
	listEntries                         int
	cgroup, status                      string
	http2                               bool
	out                                 io.Writer // stdout, and -report
}

// Run is Main, and also returns what stress found: the scenarios it ran, also when
// it fails or ctx is done (nil if none)
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) (*Report, int) {
	cfg := &config{scenarios: allScenarios, smallSize: 4 << 10, downloadSize: 1 << 30, uploadSize: 64 << 20, clientRate: 1 << 20}
	fs := flag.NewFlagSet("stress", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, usage)
		fs.PrintDefaults()
	}
	rawURL := fs.String("url", "", "the directory to work below (required)")
	ca := fs.String("ca", "", "the CA certificates of weed's host certificate: a PEM file or a directory such as /etc/grid-security/certificates (default: the system's)")
	certFile := fs.String("cert", "", "an X.509 certificate or proxy")
	keyFile := fs.String("key", "", "its key (default: -cert)")
	token := fs.String("token", "", "a bearer token")
	tokenFile := fs.String("token-file", "", "a file with a bearer token, read again before each step")
	user := fs.String("user", "", "the account of -password")
	password := fs.String("password", "", "a password")
	identities := fs.String("identities", "", "a file of identities (see above)")
	as := fs.String("as", "", "the identity of -identities of the scenarios but auth and accounts (default: the first)")
	fs.Func("scenarios", "the scenarios, comma-separated (default: all)", func(s string) error {
		cfg.scenarios = strings.Split(s, ",")
		return nil
	})
	fs.IntVar(&cfg.start, "start", 1, "the clients of the first step")
	fs.IntVar(&cfg.max, "max", 256, "the clients of the last step, at most; upload needs up to max × -upload-size on weed's storage")
	fs.DurationVar(&cfg.step, "step", 8*time.Second, "how long each step is measured")
	fs.DurationVar(&cfg.warmup, "warmup", 2*time.Second, "how long each step runs before it is measured")
	fs.DurationVar(&cfg.maxP99, "max-p99", 2*time.Second, "the p99 latency at which a ramp stops (but those of download and upload)")
	fs.Var(sizeFlag{&cfg.smallSize}, "small-size", "the size of the small files")
	fs.Var(sizeFlag{&cfg.downloadSize}, "download-size", "the size of the file downloaded")
	fs.Var(sizeFlag{&cfg.uploadSize}, "upload-size", "the size of the files uploaded")
	fs.IntVar(&cfg.listEntries, "list-entries", 100, "the files of the directory listed")
	fs.IntVar(&cfg.clients, "clients", 8192, "the clients of the last step of clients and slow-download; the steps before halve it")
	fs.BoolVar(&cfg.crowdAccounts, "crowd-accounts", false, "the clients of clients and slow-download as the identities of accounts, each a worker of its own, rather than all the first; slow-download uploads -download-size to each")
	fs.DurationVar(&cfg.interval, "interval", time.Second, "how often each client of clients makes a request")
	fs.Var(sizeFlag{&cfg.clientRate}, "client-rate", "what each client of slow-download reads per second")
	fs.StringVar(&cfg.cgroup, "cgroup", "", "weed's cgroup, e.g. /sys/fs/cgroup/system.slice/weed.service, to report the CPU and memory weed uses (on weed's machine)")
	fs.StringVar(&cfg.status, "status", "", "weed's /status, e.g. http://localhost:9180/status, to report its workers")
	fs.BoolVar(&cfg.http2, "http2", false, "use HTTP/2 when weed offers it; HTTP/1.1 otherwise, as most WLCG clients")
	report := fs.String("report", "", "also write what it prints to this file")
	jsonFile := fs.String("json", "", "write the results to this file, as JSON")
	if err := fs.Parse(args); err != nil {
		return nil, 2
	}
	if *rawURL == "" || fs.NArg() > 0 {
		fs.Usage()
		return nil, 2
	}
	var rep *Report
	fail := func(err error) (*Report, int) {
		fmt.Fprintln(stderr, "stress:", err)
		return rep, 1
	}
	if cfg.start < 1 || cfg.max < cfg.start {
		return fail(errors.New("-start must be at least 1, and -max at least -start"))
	}
	if cfg.clients < 1 || cfg.interval <= 0 {
		return fail(errors.New("-clients must be at least 1, and -interval more than 0"))
	}
	if cfg.cgroup != "" && cgroupCPU(cfg.cgroup) < 0 {
		return fail(fmt.Errorf("-cgroup: cannot read %s", filepath.Join(cfg.cgroup, "cpu.stat")))
	}

	var specs [][]string
	var err error
	switch {
	case *identities != "":
		specs, err = readIdentities(*identities)
	case *certFile != "":
		specs = [][]string{{"you", "cert", *certFile, cmp.Or(*keyFile, *certFile)}}
	case *token != "":
		specs = [][]string{{"you", "bearer", *token}}
	case *tokenFile != "":
		specs = [][]string{{"you", "bearer", "@" + *tokenFile}}
	case *user != "":
		specs = [][]string{{*user, "basic", *password}}
	default:
		err = errors.New("no credentials: -cert, -token, -token-file, -user or -identities")
	}
	switch {
	case err != nil:
	case len(specs) == 0:
		err = fmt.Errorf("%s has no identity", *identities)
	case *identities == "" && strings.Contains(*rawURL, "{user}"):
		err = errors.New("{user} in -url needs -identities")
	}
	if err != nil {
		return fail(err)
	}
	tlsBase := &tls.Config{MinVersion: tls.VersionTLS12}
	if *ca != "" {
		certs, err := x509utils.LoadCertificates(*ca)
		if err != nil {
			return fail(err)
		}
		tlsBase.RootCAs = x509.NewCertPool()
		for _, c := range certs {
			tlsBase.RootCAs.AddCert(c)
		}
	}
	runDir := fmt.Sprintf("weed-stress-%d-%04x", time.Now().Unix(), rand.IntN(1<<16))
	var all []*identity
	for i, spec := range specs {
		id, err := newIdentity(cfg, spec, tlsBase, *rawURL, runDir)
		if err != nil {
			return fail(err)
		}
		// Identities of one account, by several methods, have a directory each
		if slices.ContainsFunc(all, func(o *identity) bool { return o.base == id.base }) {
			id.base = strings.TrimSuffix(id.base, "/") + fmt.Sprintf("-%d/", i)
		}
		all = append(all, id)
	}
	first := all[0]
	if *as != "" {
		i := slices.IndexFunc(all, func(id *identity) bool { return id.Name == *as })
		if i < 0 {
			return fail(fmt.Errorf("-as %s: not in %s", *as, *identities))
		}
		first = all[i]
	}
	list, skipped, err := scenarios(cfg, first, all)
	if err != nil {
		return fail(err)
	}

	cfg.out = stdout
	if *report != "" {
		f, err := os.Create(*report)
		if err != nil {
			return fail(err)
		}
		defer f.Close()
		cfg.out = io.MultiWriter(stdout, f)
	}
	out := cfg.out
	fmt.Fprintf(out, "stress: %s, as %s, from a machine of %s\n", *rawURL, first, machine())
	fmt.Fprintf(out, "Steps of %d to %d clients (of crowds: up to %d), each measured for %s after %s of warm-up\n",
		cfg.start, cfg.max, cfg.clients, cfg.step, cfg.warmup)
	if cfg.cgroup != "" {
		fmt.Fprintf(out, "weed: what %s uses\n", cfg.cgroup)
	}
	for _, s := range skipped {
		fmt.Fprintln(out, "Skipped", s)
	}

	var results []*Result
	failed := false
	for _, sc := range list {
		res, err := ramp(ctx, cfg, sc)
		if len(res.Steps) > 0 {
			results = append(results, res)
		}
		if ctx.Err() != nil {
			break
		}
		if err != nil {
			fmt.Fprintf(out, "  %v\n", err)
			failed = true
		}
	}
	for _, id := range all {
		id.cleanup(stderr)
	}

	fmt.Fprintf(out, "\nLimits found at %s, from a machine of %s:\n", *rawURL, machine())
	for _, r := range results {
		fmt.Fprintf(out, "  %-14s %s\n  %-14s %s\n", r.Name, summary(r), "", r.Limit)
	}
	if ctx.Err() != nil {
		fmt.Fprintln(out, "  (interrupted)")
	}
	if len(results) > 0 {
		rep = &Report{URL: *rawURL, CPUs: runtime.NumCPU(), MemoryBytes: memTotal(), Results: results}
	}
	if *jsonFile != "" {
		b, _ := json.MarshalIndent(cmp.Or(rep, &Report{URL: *rawURL, CPUs: runtime.NumCPU(), MemoryBytes: memTotal()}), "", "  ")
		if err := os.WriteFile(*jsonFile, append(b, '\n'), 0o644); err != nil {
			return fail(err)
		}
	}
	switch {
	case ctx.Err() != nil:
		return rep, 130
	case failed:
		return rep, 1
	}
	return rep, 0
}

// --- Identities

type identity struct {
	Name, Kind string                 // kind: basic, app-token, bearer or cert
	header     atomic.Pointer[string] // the Authorization header ("" with a certificate)
	tokenFile  string                 // where header's token comes from, when it is renewed
	base       string                 // its directory of this run, with a trailing slash
	tls        *tls.Config
	keep       *http.Client
	once       *http.Client    // a new connection per request
	made       bool            // its directory exists
	ready      map[string]bool // what setup made in it
}

func (id *identity) String() string { return id.Name + " (" + id.Kind + ")" }

// readIdentities reads lines of: name kind arguments
func readIdentities(path string) ([][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var specs [][]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if len(fields) < 3 {
			return nil, fmt.Errorf("%s: %q: want a name, a kind and its arguments", path, sc.Text())
		}
		specs = append(specs, fields)
	}
	return specs, sc.Err()
}

func newIdentity(cfg *config, spec []string, tlsBase *tls.Config, rawURL, runDir string) (*identity, error) {
	name, kind, args := spec[0], spec[1], spec[2:]
	id := &identity{Name: name, Kind: kind, ready: make(map[string]bool)}
	id.setHeader("")
	conf := tlsBase.Clone()
	switch kind {
	case "basic", "app-token":
		if len(args) != 1 {
			return nil, fmt.Errorf("%s: %s takes a password or a token", name, kind)
		}
		id.setHeader("Basic " + base64.StdEncoding.EncodeToString([]byte(name+":"+args[0])))
	case "bearer":
		if len(args) != 1 {
			return nil, fmt.Errorf("%s: bearer takes a token, or @ and the file of one", name)
		}
		id.setHeader("Bearer " + args[0])
		if file, ok := strings.CutPrefix(args[0], "@"); ok {
			id.tokenFile = file
			if err := id.refresh(); err != nil {
				return nil, err
			}
		}
	case "cert":
		if len(args) != 2 {
			return nil, fmt.Errorf("%s: cert takes a certificate and its key", name)
		}
		cert, err := tls.LoadX509KeyPair(args[0], args[1])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		conf.Certificates = []tls.Certificate{cert}
	default:
		return nil, fmt.Errorf("%s: unknown kind %q: basic, app-token, bearer or cert", name, kind)
	}
	id.base = strings.TrimSuffix(strings.ReplaceAll(rawURL, "{user}", name), "/") + "/" + runDir + "/"
	id.tls = conf
	id.keep = &http.Client{Transport: transport(conf, false, cfg.http2)}
	id.once = &http.Client{Transport: transport(conf, true, cfg.http2)}
	return id, nil
}

func (id *identity) setHeader(h string) { id.header.Store(&h) }

// refresh reads id's token from its file again: tokens expire, and are renewed in
// their files (e.g. BEARER_TOKEN_FILE)
func (id *identity) refresh() error {
	if id.tokenFile == "" {
		return nil
	}
	b, err := os.ReadFile(id.tokenFile)
	if err != nil {
		return fmt.Errorf("%s: %w", id.Name, err)
	}
	id.setHeader("Bearer " + strings.TrimSpace(string(b)))
	return nil
}

func transport(conf *tls.Config, newConnections, http2 bool) *http.Transport {
	return &http.Transport{
		TLSClientConfig:     conf,
		ForceAttemptHTTP2:   http2,
		DisableKeepAlives:   newConnections,
		MaxIdleConnsPerHost: 1024,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		ReadBufferSize:      256 << 10,
		WriteBufferSize:     256 << 10,
	}
}

// --- Requests

// pattern is what uploads send: random, so that nothing on the way compresses it
var pattern = func() []byte {
	b := make([]byte, 1<<20)
	rand.NewChaCha8([32]byte{'w', 'e', 'e', 'd'}).Read(b)
	return b
}()

// body is n bytes of pattern, counted into moved as they are read
type body struct {
	n, off int64
	moved  *atomic.Int64
}

func (b *body) Read(p []byte) (int, error) {
	if b.off >= b.n {
		return 0, io.EOF
	}
	p = p[:min(int64(len(p)), b.n-b.off)]
	k := 0
	for k < len(p) {
		k += copy(p[k:], pattern[(b.off+int64(k))%int64(len(pattern)):])
	}
	b.off += int64(k)
	if b.moved != nil {
		b.moved.Add(int64(k))
	}
	return k, nil
}

// counter counts what is written to it into moved
type counter struct{ moved *atomic.Int64 }

func (c counter) Write(p []byte) (int, error) {
	if c.moved != nil {
		c.moved.Add(int64(len(p)))
	}
	return len(p), nil
}

type statusError struct{ status string }

func (e statusError) Error() string { return e.status }

var bufPool = sync.Pool{New: func() any { b := make([]byte, 256<<10); return &b }}

// send makes a request as id, and returns its answer; header holds names and values
func (id *identity) send(ctx context.Context, client *http.Client, method, target string, payload io.Reader, size int64, header ...string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, payload)
	if err != nil {
		return nil, err
	}
	if payload != nil {
		req.ContentLength = size
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	if h := *id.header.Load(); h != "" {
		req.Header.Set("Authorization", h)
	}
	return client.Do(req)
}

// do makes a request, reads the answer, and fails unless it is a success
func (id *identity) do(ctx context.Context, client *http.Client, method, target string, payload io.Reader, size int64, moved *atomic.Int64, header ...string) error {
	resp, err := id.send(ctx, client, method, target, payload, size, header...)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	buf := bufPool.Get().(*[]byte)
	defer bufPool.Put(buf)
	_, err = io.CopyBuffer(counter{moved}, resp.Body, *buf)
	if resp.StatusCode >= 300 {
		return statusError{resp.Status}
	}
	return err
}

// setup makes id's directory, and what a scenario needs in it, once
func (id *identity) setup(ctx context.Context, cfg *config, what string) error {
	if !id.made {
		if err := id.do(ctx, id.keep, "MKCOL", id.base, nil, 0, nil); err != nil {
			return fmt.Errorf("cannot make %s as %s: %w", id.base, id, err)
		}
		id.made = true
	}
	if what == "" || id.ready[what] {
		return nil
	}
	put := func(name string, size int64) error {
		if err := id.do(ctx, id.keep, "PUT", id.base+name, &body{n: size}, size, nil); err != nil {
			return fmt.Errorf("cannot upload %s%s as %s: %w", id.base, name, id, err)
		}
		return nil
	}
	var err error
	switch what {
	case "small":
		err = put("small", cfg.smallSize)
	case "big":
		err = put("big", cfg.downloadSize)
	case "list":
		if err = id.do(ctx, id.keep, "MKCOL", id.base+"list/", nil, 0, nil); err != nil {
			err = fmt.Errorf("cannot make %slist/ as %s: %w", id.base, id, err)
		}
		for i := 0; i < cfg.listEntries && err == nil; i++ {
			err = put(fmt.Sprintf("list/f%04d", i), cfg.smallSize)
		}
	}
	if err == nil {
		id.ready[what] = true
	}
	return err
}

// cleanup removes id's directory
func (id *identity) cleanup(stderr io.Writer) {
	if !id.made {
		return
	}
	id.refresh()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := id.do(ctx, id.keep, "DELETE", id.base, nil, 0, nil); err != nil {
		fmt.Fprintf(stderr, "stress: cannot remove %s: %v\n", id.base, err)
	}
}

// --- Scenarios

type scenario struct {
	Name   string `json:"name"`
	What   string `json:"what"`
	As     string `json:"as"`
	Unit   string `json:"unit"` // req/s, or B/s for transfers
	idents []*identity
	needs  string // what setup makes
	// op makes one request as client i, counting the bytes it moves into moved
	op func(ctx context.Context, id *identity, i int, moved *atomic.Int64) error
	// crowdOp, of a crowd instead, makes one request as m (see crowd)
	crowdOp func(ctx context.Context, m *member) error
	every   time.Duration // how often each client of a crowd starts crowdOp (0: once the last has ended)
	pace    int64         // what each client of a crowd reads per second (0: as fast as it can)
	// drain: at the end of a step, its requests in progress end (for up to
	// drainFor) rather than being cut. weed finishes storing an upload whose body
	// it has, also once its client has gone: cut, it would still be writing into the
	// directory that the end of the run removes.
	drain bool
}

// drainFor is how long the requests of a step of a scenario that drains have to end
const drainFor = time.Minute

func (s *scenario) transfer() bool { return s.Unit == "B/s" }

func (s *scenario) crowd() bool { return s.crowdOp != nil }

var allScenarios = []string{"get-small", "put-small", "list", "connect", "download", "upload", "auth", "accounts", "clients", "slow-download"}

var kindNames = map[string]string{"cert": "an X.509 certificate", "bearer": "a bearer token",
	"app-token": "an app token (Basic)", "basic": "a password (Basic)"}

func scenarios(cfg *config, first *identity, all []*identity) (list []*scenario, skipped []string, err error) {
	small := bytesIEC(cfg.smallSize)
	crowd := []*identity{first}
	if ids := accountsOf(all); cfg.crowdAccounts && len(ids) >= 2 {
		crowd = ids
	}
	getSmall := func(name, what string, ids ...*identity) *scenario {
		return &scenario{Name: name, What: what, Unit: "req/s", idents: ids, needs: "small",
			op: func(ctx context.Context, id *identity, i int, moved *atomic.Int64) error {
				return id.do(ctx, id.keep, "GET", id.base+"small", nil, 0, moved)
			}}
	}
	for _, name := range cfg.scenarios {
		switch name {
		case "get-small":
			list = append(list, getSmall(name, "GET of a "+small+" file", first))
		case "put-small":
			list = append(list, &scenario{Name: name, What: "PUT of a " + small + " file, each client to its own",
				Unit: "req/s", idents: []*identity{first}, drain: true,
				op: func(ctx context.Context, id *identity, i int, moved *atomic.Int64) error {
					return id.do(ctx, id.keep, "PUT", fmt.Sprintf("%sput-%d", id.base, i), &body{n: cfg.smallSize, moved: moved}, cfg.smallSize, nil)
				}})
		case "list":
			list = append(list, &scenario{Name: name, What: fmt.Sprintf("PROPFIND, Depth 1, of a directory of %d files", cfg.listEntries),
				Unit: "req/s", idents: []*identity{first}, needs: "list",
				op: func(ctx context.Context, id *identity, i int, moved *atomic.Int64) error {
					return id.do(ctx, id.keep, "PROPFIND", id.base+"list/", nil, 0, moved, "Depth", "1")
				}})
		case "connect":
			conn := "a new connection"
			if strings.HasPrefix(first.base, "https:") {
				conn = "a new connection (a full TLS handshake)"
			}
			s := getSmall(name, "GET of a "+small+" file, on "+conn+" each time", first)
			s.op = func(ctx context.Context, id *identity, i int, moved *atomic.Int64) error {
				return id.do(ctx, id.once, "GET", id.base+"small", nil, 0, moved)
			}
			list = append(list, s)
		case "download":
			list = append(list, &scenario{Name: name, What: "GET of a file of " + bytesIEC(cfg.downloadSize),
				Unit: "B/s", idents: []*identity{first}, needs: "big",
				op: func(ctx context.Context, id *identity, i int, moved *atomic.Int64) error {
					return id.do(ctx, id.keep, "GET", id.base+"big", nil, 0, moved)
				}})
		case "upload":
			// A name per upload: weed may still be reading one that the end of a
			// step cut, which locks its file
			var seq atomic.Int64
			list = append(list, &scenario{Name: name, What: "PUT of files of " + bytesIEC(cfg.uploadSize) + ", each deleted after",
				Unit: "B/s", idents: []*identity{first}, drain: true,
				op: func(ctx context.Context, id *identity, i int, moved *atomic.Int64) error {
					target := fmt.Sprintf("%sup-%d", id.base, seq.Add(1))
					if err := id.do(ctx, id.keep, "PUT", target, &body{n: cfg.uploadSize, moved: moved}, cfg.uploadSize, nil); err != nil {
						return err
					}
					return id.do(ctx, id.keep, "DELETE", target, nil, 0, nil)
				}})
		case "auth":
			n := len(list)
			for _, kind := range []string{"cert", "bearer", "app-token", "basic"} {
				i := slices.IndexFunc(all, func(id *identity) bool { return id.Kind == kind })
				if kind != first.Kind && i >= 0 {
					list = append(list, getSmall("auth-"+kind, "get-small, authenticated by "+kindNames[kind], all[i]))
				}
			}
			if len(list) == n {
				skipped = append(skipped, "auth: every identity authenticates as "+first.String()+" does")
			}
		case "accounts":
			ids := accountsOf(all)
			if len(ids) < 2 {
				skipped = append(skipped, "accounts: fewer than 2 identities of a method (-identities)")
				continue
			}
			list = append(list, getSmall(name, fmt.Sprintf("get-small, client i as identity i of %d", len(ids)), ids...))
		case "clients":
			list = append(list, &scenario{Name: name, What: fmt.Sprintf("clients that each hold a connection, and make a GET of a %s file every %s", small, cfg.interval),
				Unit: "req/s", idents: crowd, needs: "small", every: cfg.interval,
				crowdOp: func(ctx context.Context, m *member) error {
					return m.id.do(ctx, m.client, "GET", m.id.base+"small", nil, 0, &m.crowd.moved)
				}})
		case "slow-download":
			list = append(list, &scenario{Name: name, What: fmt.Sprintf("clients that each download a file of %s at %s/s, on a connection of their own",
				bytesIEC(cfg.downloadSize), bytesIEC(cfg.clientRate)),
				Unit: "B/s", idents: crowd, needs: "big", pace: cfg.clientRate,
				crowdOp: func(ctx context.Context, m *member) error {
					resp, err := m.id.send(ctx, m.client, "GET", m.id.base+"big", nil, 0)
					m.connected()
					if err != nil {
						return err
					}
					defer resp.Body.Close()
					if resp.StatusCode >= 300 {
						return statusError{resp.Status}
					}
					return m.readPaced(ctx, resp.Body)
				}})
		default:
			return nil, nil, fmt.Errorf("unknown scenario %q: %s", name, strings.Join(allScenarios, ", "))
		}
	}
	for _, s := range list {
		s.As = s.idents[0].String()
		if len(s.idents) > 1 {
			s.As = fmt.Sprintf("%s and %d more", s.idents[0], len(s.idents)-1)
		}
	}
	return list, skipped, nil
}

// accountsOf returns the identities of the method that has the most, those of Basic
// only when no other has two: weed checks a password with bcrypt, whose cost would
// hide that of more accounts
func accountsOf(all []*identity) []*identity {
	by := make(map[string][]*identity)
	for _, id := range all {
		by[id.Kind] = append(by[id.Kind], id)
	}
	ids := by["bearer"]
	for _, kind := range []string{"cert", "app-token"} {
		if len(by[kind]) > len(ids) {
			ids = by[kind]
		}
	}
	if len(ids) < 2 {
		ids = by["basic"]
	}
	return ids
}

// --- Steps

type Step struct {
	Clients       int              `json:"clients"`
	Seconds       float64          `json:"seconds"`
	Requests      int64            `json:"requests"` // of slow-download: the clients whose download did not fail
	Errors        int64            `json:"errors"`
	ErrorKinds    map[string]int64 `json:"error_kinds,omitempty"`
	Behind        int              `json:"behind,omitempty"` // of slow-download: the clients a second or more behind
	ReqRate       float64          `json:"requests_per_second"`
	ByteRate      float64          `json:"bytes_per_second"`
	P50           float64          `json:"p50_seconds"`
	P99           float64          `json:"p99_seconds"`
	LoadCPU       float64          `json:"load_cpu_cores"`                 // of stress itself
	WeedCPU       float64          `json:"weed_cpu_cores,omitempty"`       // with -cgroup
	WeedMemory    int64            `json:"weed_memory_bytes,omitempty"`    // with -cgroup, the most
	WeedFiles     int              `json:"weed_files,omitempty"`           // with -cgroup, the files open, as root
	Workers       int              `json:"workers,omitempty"`              // with -status
	MachineMemory int64            `json:"machine_memory_bytes,omitempty"` // the most this machine used (Linux)
}

func (s *Step) value(sc *scenario) float64 {
	if sc.transfer() {
		return s.ByteRate
	}
	return s.ReqRate
}

func (s *Step) errorRate() float64 {
	if s.Requests+s.Errors == 0 {
		return 0
	}
	return float64(s.Errors) / float64(s.Requests+s.Errors)
}

// good says whether s held: few errors, no more than 1% of the clients behind, its
// latency within maxP99 (but of transfers), and memory to spare
func (s *Step) good(sc *scenario, maxP99 time.Duration) bool {
	return s.errorRate() <= 0.01 && s.Behind*100 <= s.Clients && (sc.transfer() || s.P99 <= maxP99.Seconds()) &&
		!outOfMemory(s.MachineMemory)
}

type clientResult struct {
	latencies []time.Duration
	requests  int64
	errors    map[string]int64
}

// runStep runs clients clients for the warm-up and the step, and measures the step
func runStep(ctx context.Context, cfg *config, sc *scenario, clients int) Step {
	var moved atomic.Int64
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	from := time.Now().Add(cfg.warmup)
	to := from.Add(cfg.step)
	results := make([]clientResult, clients)
	var wg sync.WaitGroup
	var ending atomic.Bool // no new requests: those in progress end
	for i := range clients {
		wg.Go(func() {
			r := &results[i]
			r.errors = make(map[string]int64)
			id := sc.idents[i%len(sc.idents)]
			for ctx.Err() == nil && !ending.Load() {
				start := time.Now()
				err := sc.op(ctx, id, i, &moved)
				end := time.Now()
				if ctx.Err() != nil {
					return // cut by the end of the step
				}
				if err != nil {
					time.Sleep(time.Millisecond) // no spinning on a server that refuses
				}
				if end.Before(from) || end.After(to) {
					continue
				}
				if err != nil {
					r.errors[shortError(err)]++
					continue
				}
				r.requests++
				r.latencies = append(r.latencies, end.Sub(start))
			}
		})
	}

	sleep(ctx, time.Until(from))
	s := Step{Clients: clients}
	measure(ctx, cfg, &moved, to, &s)
	if sc.drain {
		ending.Store(true)
		cut := time.AfterFunc(drainFor, cancel)
		wg.Wait()
		cut.Stop()
	}
	cancel()
	wg.Wait()
	s.count(results)
	return s
}

// measure fills s with what was moved, and what weed and this machine used, from now
// until to. It stops early when ctx is done, or once this machine has used 90% of
// its memory.
func measure(ctx context.Context, cfg *config, moved *atomic.Int64, to time.Time, s *Step) {
	b0, cpu0, load0, t0 := moved.Load(), cgroupCPU(cfg.cgroup), loadCPU(), time.Now()
	for {
		s.WeedMemory = max(s.WeedMemory, cgroupMemory(cfg.cgroup))
		s.MachineMemory = max(s.MachineMemory, machineMemory())
		if !time.Now().Before(to) || ctx.Err() != nil || outOfMemory(s.MachineMemory) {
			break
		}
		sleep(ctx, min(500*time.Millisecond, time.Until(to)))
	}
	b1, cpu1, load1, t1 := moved.Load(), cgroupCPU(cfg.cgroup), loadCPU(), time.Now()
	s.Workers = statusWorkers(cfg.status)
	s.WeedFiles = weedFiles(cfg.cgroup)
	if s.Seconds = t1.Sub(t0).Seconds(); s.Seconds < 0.1 {
		return // cut before it began
	}
	s.ByteRate = float64(b1-b0) / s.Seconds
	if cpu0 >= 0 && cpu1 >= 0 {
		s.WeedCPU = (cpu1 - cpu0) / s.Seconds
	}
	s.LoadCPU = (load1 - load0) / s.Seconds
}

// count adds what the clients measured to s, whose Seconds measure has set
func (s *Step) count(results []clientResult) {
	s.ErrorKinds = make(map[string]int64)
	var lat []time.Duration
	for _, r := range results {
		s.Requests += r.requests
		lat = append(lat, r.latencies...)
		for k, n := range r.errors {
			s.Errors += n
			s.ErrorKinds[k] += n
		}
	}
	if s.Seconds >= 0.1 {
		s.ReqRate = float64(s.Requests) / s.Seconds
	}
	if len(lat) > 0 {
		slices.Sort(lat)
		s.P50 = lat[len(lat)*50/100].Seconds()
		s.P99 = lat[min(len(lat)-1, len(lat)*99/100)].Seconds()
	}
}

// --- Crowds

// A crowd is the clients of a crowd scenario, who stay from one step to the next:
// each step adds clients, each on a connection of its own, as thousands of jobs
// that read and write through weed hold thousands of connections
type crowd struct {
	cfg       *config
	sc        *scenario
	ctx       context.Context
	stop      context.CancelFunc
	wg        sync.WaitGroup
	members   []*member
	connected atomic.Int64 // the members that have had an answer
	moved     atomic.Int64
	from, to  atomic.Int64 // the window of the step measured, in Unix nanoseconds
}

// member is a client of a crowd
type member struct {
	crowd  *crowd
	id     *identity
	client *http.Client
	once   sync.Once // counts it in crowd.connected
	// The download in progress of a paced scenario: since when, in Unix nanoseconds
	// (0: none), and what it has read
	since, got atomic.Int64

	mu     sync.Mutex
	result clientResult // in the window of the step measured
}

func newCrowd(ctx context.Context, cfg *config, sc *scenario) *crowd {
	c := &crowd{cfg: cfg, sc: sc}
	c.ctx, c.stop = context.WithCancel(ctx)
	c.from.Store(math.MaxInt64)
	return c
}

// close stops the clients, and waits for them
func (c *crowd) close() {
	c.stop()
	c.wg.Wait()
	for _, m := range c.members {
		m.client.CloseIdleConnections()
	}
}

// step grows the crowd to n clients, waits until each has had an answer (thousands
// of TLS handshakes take seconds), and measures the step
func (c *crowd) step(n int) Step {
	for i := len(c.members); i < n; i++ {
		m := &member{crowd: c, id: c.sc.idents[i%len(c.sc.idents)]}
		m.client = &http.Client{Transport: crowdTransport(m.id.tls, c.cfg.http2)}
		c.members = append(c.members, m)
		c.wg.Go(func() { c.run(m) })
	}
	s := Step{Clients: n}
	deadline := time.Now().Add(2 * time.Minute)
	for c.connected.Load() < int64(n) && time.Now().Before(deadline) && c.ctx.Err() == nil && !outOfMemory(s.MachineMemory) {
		s.MachineMemory = max(s.MachineMemory, machineMemory())
		sleep(c.ctx, 100*time.Millisecond)
	}
	if !outOfMemory(s.MachineMemory) {
		sleep(c.ctx, c.cfg.warmup)
	}
	from := time.Now()
	to := from.Add(c.cfg.step)
	c.to.Store(to.UnixNano())
	c.from.Store(from.UnixNano())
	measure(c.ctx, c.cfg, &c.moved, to, &s)
	c.from.Store(math.MaxInt64)

	end := time.Now()
	results := make([]clientResult, len(c.members))
	failed := 0
	for i, m := range c.members {
		m.mu.Lock()
		results[i], m.result = m.result, clientResult{}
		m.mu.Unlock()
		if len(results[i].errors) > 0 {
			failed++
		}
		if since := m.since.Load(); since != 0 && c.sc.pace > 0 {
			due := float64(c.sc.pace) * end.Sub(time.Unix(0, since)).Seconds()
			if due-float64(m.got.Load()) >= float64(c.sc.pace) {
				s.Behind++
			}
		}
	}
	s.count(results)
	if c.sc.pace > 0 {
		// Downloads seldom end within a step: it counts those that ran
		s.Requests, s.ReqRate = int64(n-failed), 0
	}
	return s
}

// run makes m's requests until the crowd stops
func (c *crowd) run(m *member) {
	next := time.Now()
	if c.sc.every > 0 {
		next = next.Add(rand.N(c.sc.every)) // the clients spread over the interval
	}
	for c.ctx.Err() == nil {
		if c.sc.every > 0 {
			sleep(c.ctx, time.Until(next))
			if next = next.Add(c.sc.every); next.Before(time.Now()) {
				next = time.Now() // behind: the next at once, but no burst to catch up
			}
		}
		start := time.Now()
		err := c.sc.crowdOp(c.ctx, m)
		end := time.Now()
		m.connected()
		if c.ctx.Err() != nil {
			return
		}
		c.record(m, start, end, err)
		if err != nil && c.sc.every == 0 {
			sleep(c.ctx, time.Second) // no spinning on a server that refuses
		}
	}
}

// record counts a request of m that ended at end, if within the step measured
func (c *crowd) record(m *member, start, end time.Time, err error) {
	if e := end.UnixNano(); e < c.from.Load() || e > c.to.Load() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r := &m.result
	switch {
	case err != nil:
		if r.errors == nil {
			r.errors = make(map[string]int64)
		}
		r.errors[shortError(err)]++
	case c.sc.pace == 0: // the end of a download is not a request of the step
		r.requests++
		r.latencies = append(r.latencies, end.Sub(start))
	}
}

// connected counts m in its crowd's connected clients, once
func (m *member) connected() { m.once.Do(func() { m.crowd.connected.Add(1) }) }

// readPaced reads r at the crowd's pace, as m's download in progress: a sixteenth of
// a second's worth at a time, then waits until that is due
func (m *member) readPaced(ctx context.Context, r io.Reader) error {
	pace := m.crowd.sc.pace
	quantum := min(max(pace/16, 16<<10), 1<<20)
	buf := make([]byte, 16<<10) // small: thousands of clients read
	since := time.Now()
	m.got.Store(0)
	m.since.Store(since.UnixNano())
	defer m.since.Store(0)
	var got, wait int64 // wait: what read, it waits until due
	for {
		n, err := r.Read(buf)
		got += int64(n)
		m.got.Store(got)
		m.crowd.moved.Add(int64(n))
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if got >= wait {
			sleep(ctx, time.Until(since.Add(time.Duration(float64(got)/float64(pace)*float64(time.Second)))))
			wait = got + quantum
		}
	}
}

// crowdTransport is the transport of a client of a crowd: a connection of its own,
// with small buffers, as thousands of clients share this machine's memory. Its
// receive buffer is small too, as a client that reads slowly keeps it full.
func crowdTransport(conf *tls.Config, http2 bool) *http.Transport {
	t := transport(conf, false, http2)
	t.MaxIdleConnsPerHost = 1
	t.ReadBufferSize, t.WriteBufferSize = 0, 0
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, network, addr)
		if tcp, ok := conn.(*net.TCPConn); ok {
			tcp.SetReadBuffer(64 << 10)
		}
		return conn, err
	}
	return t
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func shortError(err error) string {
	var se statusError
	if errors.As(err, &se) {
		return se.status
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	msg := err.Error()
	if len(msg) > 80 {
		msg = msg[:80] + "..."
	}
	return msg
}

// --- The ramp

// verdict says why the ramp of sc stops after its last step ("" to go on): this
// machine short of memory, too many errors, clients of a crowd behind, latency beyond
// maxP99 (of requests, not transfers), or but for a crowd, saturation: two doublings
// of the clients that each added less than 10% to the best so far
func verdict(steps []Step, sc *scenario, maxP99 time.Duration) string {
	last := &steps[len(steps)-1]
	if outOfMemory(last.MachineMemory) {
		return "this machine used 90% of its memory"
	}
	if r := last.errorRate(); r > 0.01 {
		return fmt.Sprintf("%.1f%% of the requests failed", 100*r)
	}
	if last.Behind*100 > last.Clients {
		return fmt.Sprintf("%d of the %d clients fell a second or more behind %s/s", last.Behind, last.Clients, bytesIEC(sc.pace))
	}
	if !sc.transfer() && last.P99 > maxP99.Seconds() {
		return fmt.Sprintf("p99 latency above %s", maxP99)
	}
	if sc.crowd() || len(steps) < 3 {
		return ""
	}
	best := 0.0
	for i := range steps[:len(steps)-2] {
		best = max(best, steps[i].value(sc))
	}
	for i := len(steps) - 2; i < len(steps); i++ {
		if steps[i].value(sc) >= best*1.10 {
			return ""
		}
		best = max(best, steps[i].value(sc))
	}
	return "saturated, as doubling the clients twice added less than 10%"
}

type Result struct {
	*scenario
	Steps   []Step `json:"steps"`
	Best    int    `json:"best"` // index in Steps
	Stopped string `json:"stopped"`
	Limit   string `json:"limit"` // what seems to limit it
}

// NewResult is a result of the scenario name, of unit "req/s" or "B/s", whose best
// step is the last of steps: a result of stress made elsewhere, as for tests
func NewResult(name, as, unit string, steps ...Step) *Result {
	return &Result{scenario: &scenario{Name: name, As: as, Unit: unit}, Steps: steps, Best: len(steps) - 1}
}

// BestStep is the step of r that went furthest, within the limits of a ramp
func (r *Result) BestStep() *Step { return &r.Steps[r.Best] }

// Summary says in a line what r reached
func (r *Result) Summary() string { return summary(r) }

// ramp runs steps of sc until verdict stops it; res has the steps run, also with an
// error or when ctx is done
func ramp(ctx context.Context, cfg *config, sc *scenario) (*Result, error) {
	out := cfg.out
	res := &Result{scenario: sc}
	fmt.Fprintf(out, "\n%s: %s, as %s\n", sc.Name, sc.What, sc.As)
	refresh := func() error {
		for _, id := range sc.idents {
			if err := id.refresh(); err != nil {
				return fmt.Errorf("%s: %w", sc.Name, err)
			}
		}
		return nil
	}
	if err := refresh(); err != nil {
		return res, err
	}
	if sc.needs == "big" {
		n := len(slices.DeleteFunc(slices.Clone(sc.idents), func(id *identity) bool { return id.ready["big"] }))
		if of := ""; n > 0 {
			if n > 1 {
				of = fmt.Sprintf(", for each of %d identities", n)
			}
			fmt.Fprintf(cfg.out, "  (uploading the file of %s to download%s)\n", bytesIEC(cfg.downloadSize), of)
		}
	}
	for _, id := range sc.idents {
		if err := id.setup(ctx, cfg, sc.needs); err != nil {
			return res, fmt.Errorf("%s: %w", sc.Name, err)
		}
	}
	var cr *crowd
	if sc.crowd() {
		cr = newCrowd(ctx, cfg, sc)
		defer cr.close()
	}
	fmt.Fprintln(out, header(cfg, sc))
	for _, clients := range stepClients(cfg, sc) {
		if err := refresh(); err != nil {
			return res, err
		}
		var s Step
		if cr != nil {
			s = cr.step(clients)
		} else {
			s = runStep(ctx, cfg, sc, clients)
		}
		if ctx.Err() != nil {
			res.Stopped = "interrupted"
			break
		}
		res.Steps = append(res.Steps, s)
		fmt.Fprintln(out, row(cfg, sc, &s))
		if res.Stopped = verdict(res.Steps, sc, cfg.maxP99); res.Stopped != "" {
			break
		}
	}
	if len(res.Steps) == 0 {
		return res, nil
	}
	limited := res.Stopped != "" && res.Stopped != "interrupted"
	switch {
	case res.Stopped != "":
	case sc.crowd():
		res.Stopped = fmt.Sprintf("reached -clients %d", cfg.clients)
	default:
		res.Stopped = fmt.Sprintf("reached -max %d clients", cfg.max)
	}
	for i := range res.Steps {
		s := &res.Steps[i]
		if s.good(sc, cfg.maxP99) && s.value(sc) > res.Steps[res.Best].value(sc) {
			res.Best = i
		}
	}
	res.Limit = limit(cfg, res, limited)
	fmt.Fprintf(out, "  => %s. Stopped: %s.\n     %s\n", summary(res), res.Stopped, res.Limit)
	return res, nil
}

// stepClients is the clients of each step of sc: doublings from -start to -max, or of
// a crowd, six steps that double up to -clients
func stepClients(cfg *config, sc *scenario) []int {
	var counts []int
	if sc.crowd() {
		for shift := 5; shift >= 0; shift-- {
			if n := cfg.clients >> shift; n > 0 && (len(counts) == 0 || n > counts[len(counts)-1]) {
				counts = append(counts, n)
			}
		}
		return counts
	}
	for n := cfg.start; n <= cfg.max; n *= 2 {
		counts = append(counts, n)
	}
	return counts
}

// limit guesses what limits the best step; limited says whether the ramp stopped on
// memory, errors, clients behind, latency or saturation
func limit(cfg *config, res *Result, limited bool) string {
	last := &res.Steps[len(res.Steps)-1]
	if outOfMemory(last.MachineMemory) {
		s := fmt.Sprintf("Limit: the memory of this machine, %s used of %s", bytesSI(float64(last.MachineMemory)), bytesSI(float64(memTotal())))
		if last.WeedMemory > 0 {
			s += fmt.Sprintf(" (by weed: %s)", bytesSI(float64(last.WeedMemory)))
		}
		return s
	}
	if last.errorRate() > 0.01 {
		kind, n := "", int64(0)
		for k, c := range last.ErrorKinds {
			if c > n {
				kind, n = k, c
			}
		}
		if strings.HasPrefix(kind, "503") {
			return "Limit: weed refuses with 503 (unix_users.max_requests or max_workers?)"
		}
		return "Errors: " + kind
	}
	b := &res.Steps[res.Best]
	cpus := float64(runtime.NumCPU())
	used := fmt.Sprintf("weed %.1f cores, stress %.1f, of %s", b.WeedCPU, b.LoadCPU, cpusText())
	switch {
	case cfg.cgroup != "" && b.WeedCPU+b.LoadCPU > FullCPUs():
		s := "Limit: the CPUs, all busy (" + used + ")"
		if b.LoadCPU > b.WeedCPU {
			s += ": weed alone would go further"
		}
		return s
	case cfg.cgroup == "" && b.LoadCPU > 0.8*cpus:
		return fmt.Sprintf("Limit: this load generator (%.1f cores of %.0f): run it from more machines", b.LoadCPU, cpus)
	case !limited:
		return "Limit: not reached (" + res.Stopped + ")"
	case cfg.cgroup != "":
		return "Limit: not the CPUs (" + used + "): the disk, the network, or waiting in weed"
	}
	return "Limit: unknown (-cgroup, on weed's machine, would tell weed's CPU)"
}

func summary(res *Result) string {
	b := &res.Steps[res.Best]
	if b.Requests == 0 && (!res.transfer() || b.ByteRate == 0) {
		return "nothing succeeded"
	}
	var s string
	switch {
	case res.pace > 0:
		s = fmt.Sprintf("%d clients at %s/s each: %s/s", b.Clients, bytesIEC(res.pace), bytesSI(b.ByteRate))
	case res.crowd():
		s = fmt.Sprintf("%d clients: %.0f req/s, p99 %s", b.Clients, b.ReqRate, seconds(b.P99))
	case res.transfer():
		s = fmt.Sprintf("%s/s with %d clients", bytesSI(b.ByteRate), b.Clients)
	default:
		s = fmt.Sprintf("%.0f req/s with %d clients, p99 %s", b.ReqRate, b.Clients, seconds(b.P99))
	}
	// What each client of a crowd costs: the growth from the first step to the best
	if first := &res.Steps[0]; res.crowd() && b.Clients > first.Clients {
		per := func(a, b int64, n int) string { return bytesSI(max(0, float64(b-a)/float64(n))) }
		n := b.Clients - first.Clients
		switch {
		case b.WeedMemory > 0 && b.MachineMemory > 0:
			s += fmt.Sprintf("; each client adds %s to weed's memory, %s to this machine's", per(first.WeedMemory, b.WeedMemory, n),
				per(first.MachineMemory, b.MachineMemory, n))
		case b.MachineMemory > 0:
			s += fmt.Sprintf("; each client adds %s to this machine's memory", per(first.MachineMemory, b.MachineMemory, n))
		}
	}
	if b.WeedCPU > 0.05 {
		if res.transfer() {
			s += fmt.Sprintf("; %s/s per core weed used", bytesSI(b.ByteRate/b.WeedCPU))
		} else {
			s += fmt.Sprintf("; %.0f req/s per core weed used", b.ReqRate/b.WeedCPU)
		}
	}
	return s
}

func header(cfg *config, sc *scenario) string {
	h := "  clients     req/s      MB/s       p50       p99   errors"
	if sc.pace > 0 {
		h += "  behind"
	}
	h += "  stress CPU"
	if cfg.cgroup != "" {
		h += "  weed CPU  weed memory  weed files"
	}
	if cfg.status != "" {
		h += "  workers"
	}
	if memTotal() > 0 {
		h += "  machine memory"
	}
	return h
}

func row(cfg *config, sc *scenario, s *Step) string {
	r := fmt.Sprintf("  %7d  %8.0f  %8.1f  %8s  %8s  %7s", s.Clients, s.ReqRate, s.ByteRate/1e6,
		seconds(s.P50), seconds(s.P99), errorsText(s))
	if sc.pace > 0 {
		r += fmt.Sprintf("  %6d", s.Behind)
	}
	r += fmt.Sprintf("  %10.1f", s.LoadCPU)
	if cfg.cgroup != "" {
		files := "-"
		if s.WeedFiles > 0 {
			files = strconv.Itoa(s.WeedFiles)
		}
		r += fmt.Sprintf("  %8.1f  %11s  %10s", s.WeedCPU, bytesSI(float64(s.WeedMemory)), files)
	}
	if cfg.status != "" {
		r += fmt.Sprintf("  %7d", s.Workers)
	}
	if memTotal() > 0 {
		r += fmt.Sprintf("  %14s", bytesSI(float64(s.MachineMemory)))
	}
	return r
}

func errorsText(s *Step) string {
	if s.Errors == 0 {
		return "0"
	}
	return fmt.Sprintf("%.1f%%", 100*s.errorRate())
}

func seconds(s float64) string {
	switch {
	case s == 0:
		return "-"
	case s < 0.01:
		return fmt.Sprintf("%.2fms", s*1000)
	case s < 1:
		return fmt.Sprintf("%.0fms", s*1000)
	}
	return fmt.Sprintf("%.2fs", s)
}

func bytesSI(v float64) string {
	units := []string{"B", "kB", "MB", "GB", "TB"}
	i := 0
	for v >= 1000 && i < len(units)-1 {
		v /= 1000
		i++
	}
	return strconv.FormatFloat(v, 'f', min(i, 1), 64) + " " + units[i]
}

func bytesIEC(n int64) string {
	for _, u := range []struct {
		n    int64
		name string
	}{{1 << 30, "GiB"}, {1 << 20, "MiB"}, {1 << 10, "KiB"}} {
		if n >= u.n && n%u.n == 0 {
			return fmt.Sprintf("%d %s", n/u.n, u.name)
		}
	}
	return fmt.Sprintf("%d bytes", n)
}

// parseSize reads sizes such as 4KiB, 64 MiB, 1GiB, 100MB or 512
func parseSize(s string) (int64, error) {
	mult := int64(1)
	for _, u := range []struct {
		suffix string
		n      int64
	}{{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30}, {"kB", 1e3}, {"KB", 1e3}, {"MB", 1e6}, {"GB", 1e9}, {"B", 1}} {
		if num, ok := strings.CutSuffix(s, u.suffix); ok {
			s, mult = num, u.n
			break
		}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid size %q: e.g. 4KiB, 64MiB, 1GiB", s)
	}
	return n * mult, nil
}

// sizeFlag is a flag of a size in bytes (parseSize)
type sizeFlag struct{ n *int64 }

func (f sizeFlag) String() string {
	if f.n == nil {
		return ""
	}
	return bytesIEC(*f.n)
}

func (f sizeFlag) Set(s string) error {
	n, err := parseSize(s)
	if err == nil {
		*f.n = n
	}
	return err
}

// --- What weed and this machine have

// cgroupCPU is the CPU time of the cgroup dir and below, in seconds (-1 without)
func cgroupCPU(dir string) float64 {
	if dir == "" {
		return -1
	}
	if v, ok := statField(filepath.Join(dir, "cpu.stat"), "usage_usec"); ok {
		return float64(v) / 1e6
	}
	return -1
}

// cgroupMemory is the memory of the cgroup dir and below, but the page cache of the
// files weed reads and writes: heaps and stacks (anon), the kernel's (kernel; before
// Linux 5.18, slab and kernel_stack) and network buffers (sock)
func cgroupMemory(dir string) int64 {
	if dir == "" {
		return 0
	}
	st := readStat(filepath.Join(dir, "memory.stat"))
	kernel, ok := st["kernel"]
	if !ok {
		kernel = st["slab"] + st["kernel_stack"]
	}
	return st["anon"] + kernel + st["sock"]
}

// weedFiles is the number of files that the processes of the cgroup dir and below
// have open, 0 when unknown (not as root, or not on Linux)
func weedFiles(dir string) int {
	if dir == "" {
		return 0
	}
	n, known := 0, true
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.Name() != "cgroup.procs" {
			return nil
		}
		b, _ := os.ReadFile(path)
		for _, pid := range strings.Fields(string(b)) {
			fds, err := os.ReadDir("/proc/" + pid + "/fd")
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				known = false
			}
			n += len(fds)
		}
		return nil
	})
	if !known {
		return 0
	}
	return n
}

// memTotal is the memory of this machine, 0 when unknown
func memTotal() int64 {
	return readStat("/proc/meminfo")["MemTotal:"] << 10
}

// machineMemory is what this machine uses of its memory, but what it could free (the
// page cache): 0 when unknown
func machineMemory() int64 {
	st := readStat("/proc/meminfo")
	available, ok := st["MemAvailable:"]
	if !ok {
		return 0
	}
	return (st["MemTotal:"] - available) << 10
}

// outOfMemory says whether used is 90% of this machine's memory or more
func outOfMemory(used int64) bool {
	total := memTotal()
	return total > 0 && used >= total/10*9
}

// statField reads the number after name in a file of lines "name number ..."
func statField(path, name string) (int64, bool) {
	v, ok := readStat(path)[name]
	return v, ok
}

// readStat reads a file of lines "name number ...", as numbers by name
func readStat(path string) map[string]int64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	st := make(map[string]int64)
	for line := range strings.Lines(string(b)) {
		if f := strings.Fields(line); len(f) >= 2 {
			if v, err := strconv.ParseInt(f[1], 10, 64); err == nil {
				st[f[0]] = v
			}
		}
	}
	return st
}

// Cores is the number of physical cores of this machine's CPUs: fewer than the CPUs
// with SMT, which runs two threads (CPUs) on each core. 0 when unknown.
func Cores() int {
	paths, _ := filepath.Glob("/sys/devices/system/cpu/cpu[0-9]*/topology/core_cpus_list")
	if len(paths) == 0 {
		paths, _ = filepath.Glob("/sys/devices/system/cpu/cpu[0-9]*/topology/thread_siblings_list")
	}
	cores := make(map[string]bool)
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			cores[strings.TrimSpace(string(b))] = true
		}
	}
	if len(cores) > runtime.NumCPU() {
		return 0 // offline CPUs, or a cpuset: unknown
	}
	return len(cores)
}

// FullCPUs is how many CPUs busy make this machine's CPUs full: 85% of them, or with
// SMT 1.3 for each core, as a core's second thread adds a third of the first at most
// (on a laptop of 12 cores, 24 threads, weed gained nothing beyond 18 busy)
func FullCPUs() float64 {
	full := 0.85 * float64(runtime.NumCPU())
	if c := Cores(); c > 0 && c < runtime.NumCPU() {
		full = min(full, 1.3*float64(c))
	}
	return full
}

func cpusText() string {
	s := fmt.Sprintf("%d CPUs", runtime.NumCPU())
	if c := Cores(); c > 0 && c < runtime.NumCPU() {
		s += fmt.Sprintf(" (%d cores)", c)
	}
	return s
}

func machine() string {
	s := cpusText()
	if m := memTotal(); m > 0 {
		s += ", " + bytesSI(float64(m)) + " of memory"
	}
	return s
}

var statusClient = &http.Client{Timeout: 5 * time.Second}

func statusWorkers(statusURL string) int {
	if statusURL == "" {
		return 0
	}
	resp, err := statusClient.Get(statusURL)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	var st struct {
		Workers []json.RawMessage `json:"workers"`
	}
	json.NewDecoder(resp.Body).Decode(&st)
	return len(st.Workers)
}
