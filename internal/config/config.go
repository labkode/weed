package config

import (
	"flag"
	"fmt"
)

// Config holds all configuration options
type Config struct {
	Port           int
	Address        string
	Directory      string
	TLS            bool
	X509Auth       bool
	CACert         string
	GridmapFile    string
	BasicAuth      bool
	HtpasswdFile   string
	AppTokensFile  string
}

// ParseFlags parses command line flags and returns a Config
func ParseFlags() *Config {
	cfg := &Config{}
	
	flag.IntVar(&cfg.Port, "port", 9000, "tcp port")
	flag.StringVar(&cfg.Address, "address", "", "bind address (default: all interfaces)")
	flag.StringVar(&cfg.Directory, "dir", ".", "local directory to serve")
	flag.BoolVar(&cfg.TLS, "tls", false, "enable tls")
	flag.BoolVar(&cfg.X509Auth, "x509-auth", false, "enable X.509 client certificate authentication (requires TLS)")
	flag.StringVar(&cfg.CACert, "ca-cert", "", "path to CA certificate file for X.509 authentication")
	flag.StringVar(&cfg.GridmapFile, "gridmap-file", "/etc/grid-security/grid-mapfile", "path to gridmap file for X.509 DN to username mapping")
	flag.BoolVar(&cfg.BasicAuth, "basic-auth", false, "enable HTTP Basic Authentication")
	flag.StringVar(&cfg.HtpasswdFile, "htpasswd-file", ".htpasswd", "path to htpasswd file for basic authentication")
	flag.StringVar(&cfg.AppTokensFile, "app-tokens-file", ".app-tokens", "path to app tokens file for application password authentication")
	
	flag.Parse()
	return cfg
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.X509Auth && !c.TLS {
		return fmt.Errorf("X.509 authentication requires TLS to be enabled")
	}
	return nil
}
