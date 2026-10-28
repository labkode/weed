package config

import (
	"flag"
	"fmt"
	"time"
)

// Config holds all configuration options
type Config struct {
	Port          int
	Address       string
	Directory     string
	TLS           bool
	TLSCert       string
	TLSKey        string
	X509Auth      bool
	CACert        string
	GridmapFile   string
	BasicAuth     bool
	HtpasswdFile  string
	AppTokensFile string
	LogFile       string
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
	// WLCG third-party copy configuration
	TPC               bool
	TPCCAPath         string
	TPCAllowHTTP      bool
	TPCAllowLocal     bool
	TPCMaxTransfers   int
	TPCMarkerInterval time.Duration
	TPCStallTimeout   time.Duration
}

// ParseFlags parses command line flags and returns a Config
func ParseFlags() *Config {
	cfg := &Config{}

	flag.IntVar(&cfg.Port, "port", 9000, "tcp port")
	flag.StringVar(&cfg.Address, "address", "", "bind address (default: all interfaces)")
	flag.StringVar(&cfg.Directory, "dir", ".", "local directory to serve")
	flag.BoolVar(&cfg.TLS, "tls", false, "enable tls")
	flag.StringVar(&cfg.TLSCert, "tls-cert", "server.crt", "path to the TLS server certificate")
	flag.StringVar(&cfg.TLSKey, "tls-key", "server.key", "path to the TLS server private key")
	flag.BoolVar(&cfg.X509Auth, "x509-auth", false, "enable X.509 client certificate authentication (requires TLS)")
	flag.StringVar(&cfg.CACert, "ca-cert", "", "path to CA certificate file for X.509 authentication")
	flag.StringVar(&cfg.GridmapFile, "gridmap-file", "/etc/grid-security/grid-mapfile", "path to gridmap file for X.509 DN to username mapping")
	flag.BoolVar(&cfg.BasicAuth, "basic-auth", false, "enable HTTP Basic Authentication")
	flag.StringVar(&cfg.HtpasswdFile, "htpasswd-file", ".htpasswd", "path to htpasswd file for basic authentication")
	flag.StringVar(&cfg.AppTokensFile, "app-tokens-file", ".app-tokens", "path to app tokens file for application password authentication")
	flag.StringVar(&cfg.LogFile, "log-file", "", "path to log file (default: stdout)")

	// OIDC flags
	flag.BoolVar(&cfg.OIDCAuth, "oidc-auth", false, "enable OIDC authentication")
	flag.StringVar(&cfg.OIDCIssuer, "oidc-issuer", "", "OIDC issuer URL (e.g., https://auth.cern.ch/auth/realms/cern)")
	flag.StringVar(&cfg.OIDCClientID, "oidc-client-id", "", "OIDC client ID")
	flag.StringVar(&cfg.OIDCClientSecret, "oidc-client-secret", "", "OIDC client secret")
	flag.StringVar(&cfg.OIDCRedirectURL, "oidc-redirect-url", "", "OIDC redirect URL (e.g., https://mysite.cern.ch/oidc_redirect)")

	// Macaroon flags
	flag.BoolVar(&cfg.MacaroonAuth, "macaroon-auth", false, "enable Macaroon bearer token authentication")
	flag.StringVar(&cfg.MacaroonSecretKey, "macaroon-secret-key", "", "secret key for signing macaroons (required for macaroon auth)")
	flag.StringVar(&cfg.MacaroonLocation, "macaroon-location", "weed-webdav", "macaroon location identifier")
	flag.DurationVar(&cfg.MacaroonMaxValidity, "macaroon-max-validity", 24*time.Hour, "maximum (and default) lifetime of minted macaroons")

	// Third-party copy flags
	flag.BoolVar(&cfg.TPC, "tpc", false, "enable WLCG HTTP third-party copy (COPY with Source or remote Destination)")
	flag.StringVar(&cfg.TPCCAPath, "tpc-ca-path", "", "extra CA certificates (file or directory, e.g. /etc/grid-security/certificates) for verifying remote TPC endpoints, in addition to the system roots")
	flag.BoolVar(&cfg.TPCAllowHTTP, "tpc-allow-http", false, "allow plain-text http:// remote TPC endpoints")
	flag.BoolVar(&cfg.TPCAllowLocal, "tpc-allow-local", false, "allow remote TPC endpoints on loopback/link-local addresses (testing only)")
	flag.IntVar(&cfg.TPCMaxTransfers, "tpc-max-transfers", 32, "maximum number of concurrent third-party copies")
	flag.DurationVar(&cfg.TPCMarkerInterval, "tpc-marker-interval", 5*time.Second, "interval between TPC performance markers")
	flag.DurationVar(&cfg.TPCStallTimeout, "tpc-stall-timeout", 2*time.Minute, "abort a third-party copy that transfers no data for this long (0 disables)")

	flag.Parse()
	return cfg
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.X509Auth && !c.TLS {
		return fmt.Errorf("X.509 authentication requires TLS to be enabled")
	}
	if c.X509Auth && c.CACert == "" {
		return fmt.Errorf("X.509 authentication requires a CA certificate (-ca-cert)")
	}
	if c.OIDCAuth {
		if c.OIDCIssuer == "" {
			return fmt.Errorf("OIDC issuer URL is required when OIDC authentication is enabled")
		}
		if c.OIDCClientID == "" {
			return fmt.Errorf("OIDC client ID is required when OIDC authentication is enabled")
		}
		if c.OIDCClientSecret == "" {
			return fmt.Errorf("OIDC client secret is required when OIDC authentication is enabled")
		}
		if c.OIDCRedirectURL == "" {
			return fmt.Errorf("OIDC redirect URL is required when OIDC authentication is enabled")
		}
	}
	if c.MacaroonAuth {
		if c.MacaroonSecretKey == "" {
			return fmt.Errorf("macaroon secret key is required when macaroon authentication is enabled")
		}
		if len(c.MacaroonSecretKey) < 32 {
			return fmt.Errorf("macaroon secret key must be at least 32 characters long")
		}
		if c.MacaroonMaxValidity <= 0 {
			return fmt.Errorf("macaroon max validity must be positive")
		}
	}
	if c.TPC {
		if c.TPCMaxTransfers < 1 {
			return fmt.Errorf("tpc-max-transfers must be at least 1")
		}
		if c.TPCMarkerInterval <= 0 {
			return fmt.Errorf("tpc-marker-interval must be positive")
		}
		if c.TPCStallTimeout < 0 {
			return fmt.Errorf("tpc-stall-timeout cannot be negative")
		}
	}
	return nil
}
