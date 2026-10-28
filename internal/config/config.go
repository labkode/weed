// Package config holds the configuration of weed, which a TOML file sets (weed
// -config weed.toml; weed config prints one with every option and its default)
package config

import (
	"errors"
	"time"
)

// Config holds all configuration options
type Config struct {
	Port      int
	Address   string
	Directory string
	// Anonymous serves requests without credentials, as "anonymous" (loopback only)
	Anonymous   bool
	TLS         bool
	TLSCert     string
	TLSKey      string
	X509Auth    bool
	CACert      string
	CRLPath     string
	CRLMode     string
	GridmapFile string
	// UnixUsers maps every identity to a local account, whose files a worker process
	// running as the account accesses
	UnixUsers bool
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
	// ReloadInterval is how often credential files are re-read (0: only on SIGHUP)
	ReloadInterval time.Duration
	// MetricsAddress serves /metrics and /healthz without authentication ("" disables)
	MetricsAddress string
	// OIDC configuration
	OIDCAuth         bool
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string
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

// CRL modes (x509.crl_mode)
const (
	CRLRequire = "require"
	CRLIfValid = "if-valid"
)

// Validate checks that the configuration is consistent
func (c *Config) Validate() error {
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
	if c.ReloadInterval < 0 {
		return errors.New("server.reload_interval cannot be negative")
	}
	if c.Anonymous {
		if !loopback(c.Address) {
			return errors.New(`server.anonymous is only allowed on a loopback address (server.address = "127.0.0.1")`)
		}
		if c.UnixUsers {
			return errAnonymousUnixUsers
		}
	}
	if (c.WorkerCgroups || len(c.WorkerCgroupLimits) > 0) && !c.UnixUsers {
		return errors.New("unix_users.cgroups and unix_users.cgroup_limits need unix_users.enabled")
	}
	if c.TokenCAPath != "" && c.TokenIssuers == "" {
		return errors.New("tokens.ca_path needs tokens.issuers")
	}
	if c.OIDCAuth && (c.OIDCIssuer == "" || c.OIDCClientID == "" || c.OIDCClientSecret == "" || c.OIDCRedirectURL == "") {
		return errors.New("oidc needs issuer, client_id, client_secret and redirect_url")
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
