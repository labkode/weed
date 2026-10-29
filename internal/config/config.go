// Package config holds the configuration of weed, which a TOML file sets (weed
// -config weed.toml; weed config prints one with every option and its default)
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"
)

// Config holds all configuration options
type Config struct {
	Port      int
	Address   string
	Directory string
	// Anonymous serves requests without credentials, as the account nobody (loopback only)
	Anonymous   bool
	TLS         bool
	TLSCert     string
	TLSKey      string
	X509Auth    bool
	CACert      string
	CRLPath     string
	CRLMode     string
	GridmapFile string
	// WorkerIdleTimeout stops a worker that has served no request for this long
	WorkerIdleTimeout time.Duration
	// MaxWorkers bounds the number of workers taking requests
	MaxWorkers int
	// WorkerCgroups runs each worker in a cgroup of its own
	WorkerCgroups bool
	// WorkerCgroupLimits are written to the cgroup of every worker (file=value)
	WorkerCgroupLimits []string
	BasicAuth          bool
	HtpasswdFile       string
	AppTokensFile      string
	LogFile            string
	LogLevel           string // debug, info, warn or error
	LogFormat          string // text or json
	// ReloadInterval is how often credential files are re-read (0: only on SIGHUP)
	ReloadInterval time.Duration
	// MetricsAddress serves /metrics, /status and /healthz without authentication ("" disables)
	MetricsAddress string
	// AdminSocket is the control plane's Unix socket ("" disables), see internal/admin
	AdminSocket string
	// BansFile keeps the banned users across restarts ("": until weed stops)
	BansFile string
	// OIDC login page, which gives out tokens of a token issuer
	OIDCAuth         bool
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string
	OIDCScopes       []string
	OIDCAudience     string
	// Macaroon configuration
	MacaroonAuth        bool
	MacaroonSecretKey   string
	MacaroonLocation    string
	MacaroonMaxValidity time.Duration
	// WLCG and SciTokens JWTs
	TokenIssuers string
	TokenCAPath  string
	// WLCG third-party copy configuration
	TPC               bool
	TPCCAPath         string
	TPCAllowHTTP      bool
	TPCAllowLocal     bool
	TPCAllowPrivate   bool
	TPCMaxTransfers   int
	TPCMarkerInterval time.Duration
	TPCStallTimeout   time.Duration
}

// maxSocketPath is the longest path of a Unix socket (Linux: 108 bytes with a NUL)
const maxSocketPath = 107

// CRL modes (x509.crl_mode)
const (
	CRLRequire = "require"
	CRLIfValid = "if-valid"
)

// Level is the log level (server.log_level)
func (c *Config) Level() (slog.Level, error) {
	var l slog.Level
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
		return l, l.UnmarshalText([]byte(c.LogLevel))
	}
	return l, errors.New(`server.log_level must be "debug", "info", "warn" or "error"`)
}

// cgroupLimitFile is the name of a cgroup interface file that limits may be written to
var cgroupLimitFile = regexp.MustCompile(`^[a-z]+\.[a-z0-9_.]+$`)

// Validate checks that the configuration is consistent
func (c *Config) Validate() error {
	if len(c.AdminSocket) > maxSocketPath {
		return fmt.Errorf("admin.socket is too long for a Unix socket (at most %d bytes): %s", maxSocketPath, c.AdminSocket)
	}
	if c.X509Auth && !c.TLS {
		return errors.New("x509 needs tls")
	}
	if c.X509Auth && c.CACert == "" {
		return errors.New("x509 needs a CA certificate (x509.ca)")
	}
	if c.CRLPath != "" && !c.X509Auth {
		return errors.New("x509.crl_path needs x509.enabled")
	}
	if c.CRLMode == "" {
		c.CRLMode = CRLRequire
	}
	if c.CRLMode != CRLRequire && c.CRLMode != CRLIfValid {
		return errors.New(`x509.crl_mode must be "require" or "if-valid"`)
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if _, err := c.Level(); err != nil {
		return err
	}
	if c.LogFormat == "" {
		c.LogFormat = "text"
	}
	if c.LogFormat != "text" && c.LogFormat != "json" {
		return errors.New(`server.log_format must be "text" or "json"`)
	}
	if c.ReloadInterval < 0 {
		return errors.New("server.reload_interval cannot be negative")
	}
	if c.Anonymous && !loopback(c.Address) {
		return errors.New(`server.anonymous is only allowed on a loopback address (server.address = "127.0.0.1")`)
	}
	for _, l := range c.WorkerCgroupLimits {
		if file, _, ok := strings.Cut(l, "="); !ok || !cgroupLimitFile.MatchString(file) || strings.HasPrefix(file, "cgroup.") {
			return fmt.Errorf("invalid unix_users.cgroup_limits entry %q: want file=value, e.g. memory.max=4G", l)
		}
	}
	if c.TokenCAPath != "" && c.TokenIssuers == "" {
		return errors.New("tokens.ca_path needs tokens.issuers")
	}
	if c.OIDCAuth && (c.OIDCIssuer == "" || c.OIDCClientID == "" || c.OIDCClientSecret == "" || c.OIDCRedirectURL == "") {
		return errors.New("oidc needs issuer, client_id, client_secret and redirect_url")
	}
	if c.OIDCAuth && c.TokenIssuers == "" {
		return errors.New("oidc needs tokens.issuers, with oidc.issuer in it: the login page gives out its tokens")
	}
	if c.MacaroonAuth {
		if len(c.MacaroonSecretKey) < 32 {
			return errors.New("macaroons.secret_key must be at least 32 characters long")
		}
		if c.MacaroonMaxValidity <= 0 {
			return errors.New("macaroons.max_validity must be positive")
		}
	}
	if c.TPC {
		if c.TPCMaxTransfers < 1 {
			return errors.New("tpc.max_transfers must be at least 1")
		}
		if c.TPCMarkerInterval <= 0 {
			return errors.New("tpc.marker_interval must be positive")
		}
		if c.TPCStallTimeout < 0 {
			return errors.New("tpc.stall_timeout cannot be negative")
		}
	}
	return nil
}
