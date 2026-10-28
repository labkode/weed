package config

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, content string, perm os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "weed.toml")
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		t.Fatal(err)
	}
	return path
}

// Every field of Config has exactly one key in the file
func TestEveryFieldHasAKey(t *testing.T) {
	c := &Config{}
	keys := make(map[any]string)
	for _, s := range c.sections() {
		for _, o := range s.options {
			if other, ok := keys[o.value]; ok {
				t.Errorf("%s.%s and %s set the same field", s.name, o.key, other)
			}
			keys[o.value] = s.name + "." + o.key
		}
	}
	v := reflect.ValueOf(c).Elem()
	for i := range v.NumField() {
		if _, ok := keys[v.Field(i).Addr().Interface()]; !ok {
			t.Errorf("Config.%s has no key in the configuration file", v.Type().Field(i).Name)
		}
	}
}

// weed config prints a file that gives the defaults
func TestExample(t *testing.T) {
	c, err := Load(write(t, Example(), 0600))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c, Default()) {
		t.Errorf("the example gives\n%+v\nnot the defaults\n%+v", c, Default())
	}
	if err := Default().Validate(); err != nil {
		t.Errorf("the defaults are not valid: %v", err)
	}
}

func TestLoad(t *testing.T) {
	c, err := Load(write(t, `
[server]
port = 8443
dir = "/data"

[tls]
enabled = true

[tpc]
enabled = true
stall_timeout = "90s"

[unix_users]
enabled = true
cgroup_limits = ["memory.max=8G", "pids.max=1000"]
`, 0644))
	if err != nil {
		t.Fatal(err)
	}
	want := Default()
	want.Port, want.Directory, want.TLS, want.TPC, want.TPCStallTimeout = 8443, "/data", true, true, 90*time.Second
	want.UnixUsers, want.WorkerCgroupLimits = true, []string{"memory.max=8G", "pids.max=1000"}
	if !reflect.DeepEqual(c, want) {
		t.Errorf("got\n%+v\nwant\n%+v", c, want)
	}

	for name, tc := range map[string]struct{ content, err string }{
		"unknown section":  {"[serve]\nport = 1\n", "unknown section [serve]"},
		"unknown key":      {"[server]\nprot = 1\n", "unknown option server.prot"},
		"top-level key":    {"port = 1\n", "unknown section [port]"},
		"wrong type":       {"[server]\nport = \"8443\"\n", "server.port"},
		"bad duration":     {"[tpc]\nstall_timeout = \"2 minutes\"\n", "tpc.stall_timeout"},
		"nested table":     {"[server.tls]\nenabled = true\n", "unknown option server.tls"},
		"invalid TOML":     {"[server\n", "weed.toml"},
		"duplicate key":    {"[server]\nport = 1\nport = 2\n", "weed.toml"},
		"duplicate table":  {"[server]\nport = 1\n[server]\ndir = \"/\"\n", "weed.toml"},
		"secret, readable": {"[macaroons]\nsecret_key = \"0123456789abcdef0123456789abcdef\"\n", "every user can read it"},
		"OIDC secret":      {"[oidc]\nclient_secret = \"s\"\n", "every user can read it"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load(write(t, tc.content, 0644))
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("got %v, want an error with %q", err, tc.err)
			}
		})
	}

	// Secrets in a file only its owner (and group) can read
	c, err = Load(write(t, "[macaroons]\nenabled = true\nsecret_key = \"0123456789abcdef0123456789abcdef\"\n", 0640))
	if err != nil || c.MacaroonSecretKey != "0123456789abcdef0123456789abcdef" {
		t.Errorf("got %v, %v", c, err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.toml")); err == nil {
		t.Error("a missing file was accepted")
	}
}

func TestFromArgs(t *testing.T) {
	c, err := FromArgs(nil)
	if err != nil || !reflect.DeepEqual(c, QuickStart()) {
		t.Fatalf("without -config: %+v, %v", c, err)
	}
	if err := c.Validate(); err != nil || !c.Anonymous || c.Address != "127.0.0.1" {
		t.Errorf("without -config: anonymous %t on %q: %v", c.Anonymous, c.Address, err)
	}

	path := write(t, "[server]\nport = 8443\n", 0600)
	for _, args := range [][]string{{"-config", path}, {"--config=" + path}} {
		c, err = FromArgs(args)
		if err != nil || c.Port != 8443 || c.Anonymous || c.Address != "" {
			t.Errorf("%q: %+v, %v", args, c, err)
		}
	}

	if _, err := FromArgs([]string{"-h"}); !errors.Is(err, flag.ErrHelp) {
		t.Errorf("-h: %v", err)
	}
	// The flags weed had before configuration files
	if _, err := FromArgs([]string{"-port", "8443"}); !errors.Is(err, ErrUsage) {
		t.Errorf("-port: %v", err)
	}
	if _, err := FromArgs([]string{"-config", path, "/data"}); err == nil || !strings.Contains(err.Error(), "weed config") {
		t.Errorf("an argument: %v", err)
	}
}

func TestValidate(t *testing.T) {
	for name, tc := range map[string]struct {
		mod func(*Config)
		err string // "" when valid
	}{
		"anonymous on 127.0.0.1": {func(c *Config) { c.Anonymous, c.Address = true, "127.0.0.1" }, ""},
		"anonymous on ::1":       {func(c *Config) { c.Anonymous, c.Address = true, "::1" }, ""},
		"anonymous on localhost": {func(c *Config) { c.Anonymous, c.Address = true, "localhost" }, ""},
		"anonymous everywhere":   {func(c *Config) { c.Anonymous = true }, "loopback"},
		"anonymous on 0.0.0.0":   {func(c *Config) { c.Anonymous, c.Address = true, "0.0.0.0" }, "loopback"},
		"anonymous on a host":    {func(c *Config) { c.Anonymous, c.Address = true, "weed.example.org" }, "loopback"},
		"anonymous Unix users": {func(c *Config) {
			c.Anonymous, c.Address, c.UnixUsers = true, "127.0.0.1", true
		}, "unix_users"},
		"x509 without tls":   {func(c *Config) { c.X509Auth, c.CACert = true, "ca.pem" }, "x509 needs tls"},
		"crl mode":           {func(c *Config) { c.CRLMode = "sometimes" }, "x509.crl_mode"},
		"cgroups":            {func(c *Config) { c.WorkerCgroups = true }, "unix_users.enabled"},
		"short macaroon key": {func(c *Config) { c.MacaroonAuth, c.MacaroonSecretKey = true, "short" }, "macaroons.secret_key"},
		"incomplete OIDC":    {func(c *Config) { c.OIDCAuth, c.OIDCIssuer = true, "https://issuer" }, "oidc needs"},
		"OIDC without tokens": {func(c *Config) {
			c.OIDCAuth, c.OIDCIssuer, c.OIDCClientID, c.OIDCClientSecret, c.OIDCRedirectURL = true, "https://issuer", "weed", "s", "https://weed/oidc_redirect"
		}, "oidc needs tokens.issuers"},
		"TPC without transfers":  {func(c *Config) { c.TPC, c.TPCMaxTransfers = true, 0 }, "tpc.max_transfers"},
		"token CAs, no issuers":  {func(c *Config) { c.TokenCAPath = "ca.pem" }, "tokens.issuers"},
		"negative reload period": {func(c *Config) { c.ReloadInterval = -time.Second }, "server.reload_interval"},
		"log level":              {func(c *Config) { c.LogLevel = "DEBUG" }, ""},
		"unknown log level":      {func(c *Config) { c.LogLevel = "verbose" }, "server.log_level"},
		"offset log level":       {func(c *Config) { c.LogLevel = "info+2" }, "server.log_level"},
		"log format":             {func(c *Config) { c.LogFormat = "json" }, ""},
		"unknown log format":     {func(c *Config) { c.LogFormat = "logfmt" }, "server.log_format"},
	} {
		t.Run(name, func(t *testing.T) {
			c := Default()
			tc.mod(c)
			err := c.Validate()
			if tc.err == "" && err != nil || tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)) {
				t.Errorf("got %v, want %q", err, tc.err)
			}
		})
	}
}
