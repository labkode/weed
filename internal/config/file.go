package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Default is the configuration that a file which sets nothing gives
func Default() *Config {
	return &Config{
		Port:                  9000,
		Directory:             ".",
		LogLevel:              "info",
		LogFormat:             "text",
		TLSCert:               "server.crt",
		TLSKey:                "server.key",
		CRLMode:               CRLRequire,
		GridmapFile:           "/etc/grid-security/grid-mapfile",
		ReloadInterval:        time.Hour,
		HtpasswdFile:          ".htpasswd",
		AppTokensFile:         ".app-tokens",
		MacaroonLocation:      "weed-webdav",
		MacaroonMaxValidity:   24 * time.Hour,
		TPCMaxTransfers:       32,
		TPCMarkerInterval:     5 * time.Second,
		TPCStallTimeout:       2 * time.Minute,
		WorkerIdleTimeout:     10 * time.Minute,
		MaxWorkers:            256,
		WorkerMaxRequests:     4000,
		WorkerMaxStorageCalls: 256,
		AdminSocket:           "/run/weed/admin.sock",
		BansFile:              "/var/lib/weed/bans.json",
		WorkerCgroupLimits:    []string{},
		OIDCScopes:            []string{"openid", "storage.read:/"},
	}
}

// QuickStart is the configuration without a file: the current directory, to local
// clients, without authentication
func QuickStart() *Config {
	c := Default()
	c.Address = "127.0.0.1"
	c.Anonymous = true
	return c
}

// option is a key of the configuration file
type option struct {
	key, doc string
	value    any // the field of Config it sets
}

// secrets are the options whose values are never shown (see Settings)
var secrets = map[string]bool{"macaroons.secret_key": true, "oidc.client_secret": true}

type section struct {
	name, doc string
	options   []option
}

// sections lays out the configuration file over the fields of c
func (c *Config) sections() []section {
	return []section{
		{"server", "Server", []option{
			{"address", `address to listen on ("" for all interfaces)`, &c.Address},
			{"port", "TCP port", &c.Port},
			{"dir", "directory exported under /webdav/", &c.Directory},
			{"require_mount", "serve dir only from a file system other than that of /, the storage mounted at dir or above it: weed does not start while it is not mounted, and never serves the directory beneath it", &c.RequireMount},
			{"anonymous", "serve requests without credentials as the Unix account nobody; only on a loopback address (the default without a configuration file)", &c.Anonymous},
			{"log_file", `log to this file ("" for standard error, which systemd sends to the journal: it drops the lines beyond its rate limit, a file keeps them all); weed reopens it on SIGHUP, for logrotate`, &c.LogFile},
			{"log_level", `log records of this level and above: "debug", "info", "warn" or "error"`, &c.LogLevel},
			{"log_format", `"text" (key=value) or "json", one record per line`, &c.LogFormat},
			{"metrics_address", `serve Prometheus metrics (/metrics), what runs (/status), a dashboard of both (/) and /healthz, without authentication, on this address, e.g. "localhost:9100" ("" disables)`, &c.MetricsAddress},
			{"reload_interval", `re-read credential files (htpasswd, app tokens, grid-mapfile, CAs, CRLs, token issuers, TLS certificate) this often ("0s": only on SIGHUP)`, &c.ReloadInterval},
		}},
		{"tls", "HTTPS", []option{
			{"enabled", "serve HTTPS", &c.TLS},
			{"cert", "server certificate (PEM)", &c.TLSCert},
			{"key", "its private key (PEM)", &c.TLSKey},
		}},
		{"x509", "X.509 client certificates and proxies (needs tls)", []option{
			{"enabled", "accept X.509 client certificates", &c.X509Auth},
			{"ca", "CA certificates: a PEM file, or a directory such as /etc/grid-security/certificates", &c.CACert},
			{"crl_path", `certificate revocation lists: a file or a directory such as /etc/grid-security/certificates, kept current by fetch-crl ("" accepts revoked certificates)`, &c.CRLPath},
			{"crl_mode", `"require" rejects certificates whose issuer has no current CRL; "if-valid" only checks against the CRLs that are present and current`, &c.CRLMode},
			{"gridmap", "grid-mapfile: only certificates whose DN it lists are accepted, as its usernames", &c.GridmapFile},
		}},
		{"basic", "HTTP Basic authentication with passwords and app tokens (weed utils password, weed utils token)", []option{
			{"enabled", "accept Basic authentication", &c.BasicAuth},
			{"htpasswd", "htpasswd file (bcrypt)", &c.HtpasswdFile},
			{"app_tokens", "app tokens file", &c.AppTokensFile},
		}},
		{"oidc", "A login page for browsers (/auth/oidc) that gives out WLCG tokens: users log in at a token issuer listed in tokens.issuers, and get the access token it issues, to use as a bearer token", []option{
			{"enabled", "serve the login page", &c.OIDCAuth},
			{"issuer", `issuer URL, as in tokens.issuers, e.g. "https://wlcg.cloud.cnaf.infn.it/"`, &c.OIDCIssuer},
			{"client_id", "client ID", &c.OIDCClientID},
			{"client_secret", "client secret", &c.OIDCClientSecret},
			{"redirect_url", `redirect URL, e.g. "https://weed.example.org/oidc_redirect"`, &c.OIDCRedirectURL},
			{"scopes", `scopes to ask for, e.g. ["openid", "storage.read:/", "storage.modify:/"]; the issuer grants those its policies allow`, &c.OIDCScopes},
			{"audience", `audience to ask for (the "audience" parameter of INDIGO IAM), one of the issuer's audiences in tokens.issuers ("": the issuer's default)`, &c.OIDCAudience},
		}},
		{"macaroons", "Macaroons: bearer tokens that weed mints (POST with Content-Type application/macaroon-request)", []option{
			{"enabled", "accept and mint macaroons", &c.MacaroonAuth},
			{"secret_key", "signing key, at least 32 characters", &c.MacaroonSecretKey},
			{"location", "location identifier", &c.MacaroonLocation},
			{"max_validity", "maximum (and default) lifetime of minted macaroons", &c.MacaroonMaxValidity},
		}},
		{"tokens", "WLCG and SciTokens JWT bearer tokens", []option{
			{"issuers", `accept tokens from the issuers in this JSON file ("" disables): [{"issuer": "https://...", "audiences": ["https://this.server"], "base_path": "/", "users": [{"sub": "...", "group": "/vo/group", "user": "account"}]}]`, &c.TokenIssuers},
			{"ca_path", "extra CA certificates (file or directory) for fetching the issuers' signing keys, in addition to the system roots", &c.TokenCAPath},
		}},
		{"tpc", "WLCG HTTP third-party copy (COPY with Source, or with a remote Destination)", []option{
			{"enabled", "serve third-party copies", &c.TPC},
			{"ca_path", "extra CA certificates (file or directory, e.g. /etc/grid-security/certificates) for verifying remote endpoints, in addition to the system roots", &c.TPCCAPath},
			{"allow_http", "allow plain-text http:// remote endpoints", &c.TPCAllowHTTP},
			{"allow_local", "allow remote endpoints on loopback and link-local addresses (testing only)", &c.TPCAllowLocal},
			{"allow_private", "allow remote endpoints on private addresses (RFC 1918, RFC 4193, shared address space)", &c.TPCAllowPrivate},
			{"max_transfers", "maximum number of concurrent copies", &c.TPCMaxTransfers},
			{"marker_interval", "interval between performance markers", &c.TPCMarkerInterval},
			{"stall_timeout", `abort a copy that transfers no data for this long ("0s" disables)`, &c.TPCStallTimeout},
		}},
		{"unix_users", "Unix accounts: every request accesses files as the Unix account its credentials map to (anonymous ones: nobody), from a worker process running as that account; an identity without an account gets 403. weed runs on Linux, as root (or with CAP_SETUID and CAP_SETGID)", []option{
			{"idle_timeout", "stop the worker process of an account once it has served no request for this long", &c.WorkerIdleTimeout},
			{"max_workers", "at most this many worker processes take requests; once they are all busy, requests of other accounts get 503", &c.MaxWorkers},
			{"max_requests", "at most this many requests in progress in each worker process, counted until the worker has finished them, also once their clients have gone; beyond, requests of its account get 503", &c.WorkerMaxRequests},
			{"max_storage_calls", "at most this many calls to the storage (open, stat, a batch of a listing, a read, a write, ...) in progress at once in each worker process; the requests beyond wait for one to end, without a thread, until their clients go. Each call holds a thread of the worker until the storage answers: this bounds those threads, also when the storage is slow or does not answer", &c.WorkerMaxStorageCalls},
			{"cgroups", "run the worker processes of each account in a cgroup of their own, below weed's, which must be delegated to weed (systemd: Delegate=yes); cgroup v2", &c.WorkerCgroups},
			{"cgroup_limits", `write these file=value settings to the cgroup of every account, e.g. ["memory.max=8G", "pids.max=5000"] (implies cgroups), unless limits says otherwise; pids.max counts threads, and a worker that cannot make one dies: keep it above max_storage_calls, plus the CPUs, plus a hundred. The Go runtime of workers keeps below 90% of memory.max and memory.high`, &c.WorkerCgroupLimits},
			{"limits", `cgroup limits of some users and Unix groups, in this JSON file ("" for none), which weed re-reads when it reloads: [{"user": "alice", "cgroup_limits": ["io.max=8:16 wbps=100000000"]}, {"group": "cms", "cgroup_limits": ["memory.max=32G", "cpu.weight=400"]}]. A limit of a rule for the user prevails over one for a group, which prevails over cgroup_limits, file by file (implies cgroups)`, &c.LimitsFile},
		}},
		{"admin", "The control plane: a Unix socket that weed utils talks to (ban, unban, bans), which only root and weed's own user can use", []option{
			{"socket", `its path ("" disables); weed creates the directory, which only its owner may enter, if missing`, &c.AdminSocket},
			{"bans", `the users banned with weed utils ban, which weed refuses (403) whatever their credentials, are kept in this file across restarts ("": until weed stops); weed writes it, and reads it at startup`, &c.BansFile},
		}},
	}
}

// Source is where a configuration was read from
type Source struct {
	Path   string // absolute; "" for QuickStart
	SHA256 string // of the content that was read, hex encoded
}

// Load reads a configuration file. What it does not set keeps its default; unknown
// keys are errors. A file that holds secrets must not be readable by other users.
func Load(path string) (*Config, error) {
	c, _, err := Read(path)
	return c, err
}

// Read is Load, and also says where the configuration came from
func Read(path string) (*Config, Source, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, Source{}, err
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		return nil, Source{}, err
	}
	sum := sha256.Sum256(b)
	c, err := parse(path, b)
	if err != nil {
		return nil, Source{}, err
	}
	return c, Source{Path: abs, SHA256: hex.EncodeToString(sum[:])}, nil
}

func parse(path string, b []byte) (*Config, error) {
	var tables map[string]toml.Primitive
	md, err := toml.Decode(string(b), &tables)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c := Default()
	for name, table := range tables {
		var sec *section
		for _, s := range c.sections() {
			if s.name == name {
				sec = &s
			}
		}
		var keys map[string]toml.Primitive
		if sec == nil || md.PrimitiveDecode(table, &keys) != nil {
			return nil, fmt.Errorf("%s: unknown section [%s]", path, name)
		}
	next:
		for key, value := range keys {
			for _, o := range sec.options {
				if o.key == key {
					if err := md.PrimitiveDecode(value, o.value); err != nil {
						return nil, fmt.Errorf("%s: %s.%s: %w", path, name, key, err)
					}
					continue next
				}
			}
			return nil, fmt.Errorf("%s: unknown option %s.%s", path, name, key)
		}
	}
	if c.holdsSecrets() {
		if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o004 != 0 {
			return nil, fmt.Errorf("%s holds secrets but every user can read it (chmod o-r %s)", path, path)
		}
	}
	return c, nil
}

func (c *Config) holdsSecrets() bool {
	for _, s := range c.sections() {
		for _, o := range s.options {
			if v, ok := o.value.(*string); ok && secrets[s.name+"."+o.key] && *v != "" {
				return true
			}
		}
	}
	return false
}

// Setting is the value of an option, as weed reports it
type Setting struct {
	Section, Key string
	// Value is a string, bool, int or []string; durations are strings such as "1h",
	// as in the file, and secrets "<redacted>" when they are set
	Value any
}

// Settings returns the value of every option, in the order of Example
func (c *Config) Settings() []Setting {
	var settings []Setting
	for _, s := range c.sections() {
		for _, o := range s.options {
			settings = append(settings, Setting{s.name, o.key, reported(s.name, o)})
		}
	}
	return settings
}

func reported(section string, o option) any {
	switch v := o.value.(type) {
	case *string:
		if secrets[section+"."+o.key] && *v != "" {
			return "<redacted>"
		}
		return *v
	case *bool:
		return *v
	case *int:
		return *v
	case *time.Duration:
		return durationString(*v)
	case *[]string:
		return slices.Clone(*v)
	}
	panic(fmt.Sprintf("config: no reported form for %T", o.value))
}

// LogValue logs every option, grouped by section (secrets redacted)
func (c *Config) LogValue() slog.Value {
	var sections []slog.Attr
	for _, s := range c.sections() {
		attrs := make([]slog.Attr, len(s.options))
		for i, o := range s.options {
			attrs[i] = slog.Any(o.key, reported(s.name, o))
		}
		sections = append(sections, slog.Attr{Key: s.name, Value: slog.GroupValue(attrs...)})
	}
	return slog.GroupValue(sections...)
}

// Changed lists the options (section.key) whose values differ between a and b
func Changed(a, b *Config) []string {
	var keys []string
	sb := b.sections()
	for i, s := range a.sections() {
		for j, o := range s.options {
			if !sameValue(o.value, sb[i].options[j].value) {
				keys = append(keys, s.name+"."+o.key)
			}
		}
	}
	return keys
}

func sameValue(a, b any) bool {
	if l, ok := a.(*[]string); ok {
		return slices.Equal(*l, *b.(*[]string)) // nil and empty alike
	}
	return reflect.ValueOf(a).Elem().Interface() == reflect.ValueOf(b).Elem().Interface()
}

const usage = `usage: weed [-config weed.toml]
       weed check [-config weed.toml]
                      check that weed would start with a configuration, without serving
       weed version   print the version, commit and build of weed
       weed config    print a configuration file with every option and its default
       weed utils     helpers for passwords, app tokens and certificates, and
                      ban, unban and bans for the running weed

Options are set in the configuration file. Without one, weed serves the current
directory at http://127.0.0.1:9000/webdav/ to local clients, without authentication,
as the Unix account nobody, and its metrics, status and dashboard at
http://127.0.0.1:9000/metrics, /status and /dashboard/. weed runs on Linux,
as root.
`

// ErrUsage is returned for a command line that the usage has been printed for
var ErrUsage = errors.New("invalid command line")

// FromArgs returns the configuration that the command line names (-config), or
// QuickStart without one, and where it came from
func FromArgs(args []string) (*Config, Source, error) {
	fs := flag.NewFlagSet("weed", flag.ContinueOnError)
	path := fs.String("config", "", "configuration file (TOML)")
	fs.Usage = func() { fmt.Fprint(fs.Output(), usage) }
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		return nil, Source{}, err
	} else if err != nil {
		return nil, Source{}, ErrUsage
	}
	if fs.NArg() > 0 {
		return nil, Source{}, fmt.Errorf("unexpected argument %q: options are set in the configuration file (weed config prints one)", fs.Arg(0))
	}
	if *path == "" {
		return QuickStart(), Source{}, nil
	}
	return Read(*path)
}

const exampleHeader = `# weed configuration: weed -config weed.toml
#
# Every option is optional: this file sets each one to its default. Without a
# configuration file, weed serves the current directory to local clients without
# authentication (address = "127.0.0.1" and anonymous = true in [server]).
# Durations are strings such as "90s", "10m" or "24h". weed refuses to read a file
# that holds secrets (macaroons.secret_key, oidc.client_secret) if every user can.
`

// Example returns a configuration file that sets every option to its default, and
// says what each one does
func Example() string {
	var b strings.Builder
	b.WriteString(exampleHeader)
	for _, s := range Default().sections() {
		b.WriteString("\n")
		for _, line := range wrap(s.doc, 78) {
			fmt.Fprintf(&b, "# %s\n", line)
		}
		fmt.Fprintf(&b, "[%s]\n", s.name)
		for _, o := range s.options {
			for _, line := range wrap(o.doc, 78) {
				fmt.Fprintf(&b, "# %s\n", line)
			}
			fmt.Fprintf(&b, "%s = %s\n", o.key, tomlValue(o.value))
		}
	}
	return b.String()
}

// tomlValue writes the value a field points to as TOML
func tomlValue(v any) string {
	switch v := v.(type) {
	case *string:
		return fmt.Sprintf("%q", *v)
	case *bool:
		return fmt.Sprint(*v)
	case *int:
		return fmt.Sprint(*v)
	case *time.Duration:
		return fmt.Sprintf("%q", durationString(*v))
	case *[]string:
		quoted := make([]string, len(*v))
		for i, s := range *v {
			quoted[i] = fmt.Sprintf("%q", s)
		}
		return "[" + strings.Join(quoted, ", ") + "]"
	}
	panic(fmt.Sprintf("config: no TOML form for %T", v))
}

// durationString formats d as in configuration files: "1h", not "1h0m0s"
func durationString(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// wrap breaks text into lines of at most width characters
func wrap(text string, width int) []string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(text) {
		if line != "" && len(line)+1+len(word) > width {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	return append(lines, line)
}

// loopback reports whether address (server.address) only reaches the local host
func loopback(address string) bool {
	if address == "localhost" {
		return true
	}
	ip := net.ParseIP(address)
	return ip != nil && ip.IsLoopback()
}
