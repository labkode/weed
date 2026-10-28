package config

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Default is the configuration that a file which sets nothing gives
func Default() *Config {
	return &Config{
		Port:                9000,
		Directory:           ".",
		LogLevel:            "info",
		LogFormat:           "text",
		TLSCert:             "server.crt",
		TLSKey:              "server.key",
		CRLMode:             CRLRequire,
		GridmapFile:         "/etc/grid-security/grid-mapfile",
		ReloadInterval:      time.Hour,
		HtpasswdFile:        ".htpasswd",
		AppTokensFile:       ".app-tokens",
		MacaroonLocation:    "weed-webdav",
		MacaroonMaxValidity: 24 * time.Hour,
		TPCMaxTransfers:     32,
		TPCMarkerInterval:   5 * time.Second,
		TPCStallTimeout:     2 * time.Minute,
		WorkerIdleTimeout:   10 * time.Minute,
		MaxWorkers:          256,
		WorkerCgroupLimits:  []string{},
		OIDCScopes:          []string{"openid", "storage.read:/"},
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
			{"anonymous", "serve requests without credentials, read-write, as \"anonymous\"; only on a loopback address (the default without a configuration file)", &c.Anonymous},
			{"log_file", `log to this file ("" for standard error); weed reopens it on SIGHUP, for logrotate`, &c.LogFile},
			{"log_level", `log records of this level and above: "debug", "info", "warn" or "error"`, &c.LogLevel},
			{"log_format", `"text" (key=value) or "json", one record per line`, &c.LogFormat},
			{"metrics_address", `serve Prometheus metrics (/metrics) and /healthz, without authentication, on this address, e.g. "localhost:9100" ("" disables)`, &c.MetricsAddress},
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
		{"unix_users", "Unix accounts: each identity is a local account, whose files a worker process running as the account accesses (Linux; needs root, or CAP_SETUID and CAP_SETGID)", []option{
			{"enabled", "map identities to Unix accounts (an identity without one gets 403)", &c.UnixUsers},
			{"idle_timeout", "stop the worker process of an account once it has served no request for this long", &c.WorkerIdleTimeout},
			{"max_workers", "at most this many worker processes take requests; once they are all busy, requests of other accounts get 503", &c.MaxWorkers},
			{"cgroups", "run each worker process in a cgroup of its own, below weed's, which must be delegated to weed (systemd: Delegate=yes); cgroup v2", &c.WorkerCgroups},
			{"cgroup_limits", `write these file=value settings to the cgroup of every worker process, e.g. ["memory.max=8G", "pids.max=1000"] (implies cgroups)`, &c.WorkerCgroupLimits},
		}},
	}
}

// Load reads a configuration file. What it does not set keeps its default; unknown
// keys are errors. A file that holds secrets must not be readable by other users.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
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
	if c.MacaroonSecretKey != "" || c.OIDCClientSecret != "" {
		if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o004 != 0 {
			return nil, fmt.Errorf("%s holds secrets but every user can read it (chmod o-r %s)", path, path)
		}
	}
	return c, nil
}

const usage = `usage: weed [-config weed.toml]
       weed config    print a configuration file with every option and its default
       weed utils     helpers for passwords, app tokens and certificates

Options are set in the configuration file. Without one, weed serves the current
directory at http://127.0.0.1:9000/webdav/ to local clients, without authentication.
`

// ErrUsage is returned for a command line that the usage has been printed for
var ErrUsage = errors.New("invalid command line")

// FromArgs returns the configuration that the command line names (-config), or
// QuickStart without one
func FromArgs(args []string) (*Config, error) {
	fs := flag.NewFlagSet("weed", flag.ContinueOnError)
	path := fs.String("config", "", "configuration file (TOML)")
	fs.Usage = func() { fmt.Fprint(fs.Output(), usage) }
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		return nil, err
	} else if err != nil {
		return nil, ErrUsage
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q: options are set in the configuration file (weed config prints one)", fs.Arg(0))
	}
	if *path == "" {
		return QuickStart(), nil
	}
	return Load(*path)
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
		d := v.String() // e.g. 1h0m0s
		if strings.HasSuffix(d, "m0s") {
			d = strings.TrimSuffix(d, "0s")
		}
		if strings.HasSuffix(d, "h0m") {
			d = strings.TrimSuffix(d, "0m")
		}
		return fmt.Sprintf("%q", d)
	case *[]string:
		quoted := make([]string, len(*v))
		for i, s := range *v {
			quoted[i] = fmt.Sprintf("%q", s)
		}
		return "[" + strings.Join(quoted, ", ") + "]"
	}
	panic(fmt.Sprintf("config: no TOML form for %T", v))
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

var errAnonymousUnixUsers = errors.New("server.anonymous cannot be combined with unix_users: anonymous requests have no Unix account")
