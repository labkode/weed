package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/labkode/weed/internal/auth"
	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/handlers"
	"github.com/labkode/weed/internal/logger"
	"github.com/labkode/weed/internal/tpc"
)

// shutdownGrace is how long in-flight requests get to finish on shutdown
const shutdownGrace = 30 * time.Second

// Server represents the WebDAV server
type Server struct {
	Config    *config.Config
	AuthStore *auth.AuthStore
	Handler   *handlers.WebDAVHandler
	server    *http.Server
}

// New creates a new server instance
func New(cfg *config.Config) *Server {
	authStore := auth.NewAuthStore()
	return &Server{
		Config:    cfg,
		AuthStore: authStore,
		Handler:   handlers.NewWebDAVHandler(cfg.Directory, cfg, authStore),
	}
}

// Initialize sets up authentication and other server components
func (s *Server) Initialize() error {
	// Initialize authentication systems if enabled
	if s.Config.BasicAuth {
		s.AuthStore.BasicEnabled = true
		s.AuthStore.PrepareBasicAuth()
		if err := s.AuthStore.LoadHtpasswd(s.Config.HtpasswdFile); err != nil {
			log.Printf("[HTPASSWD] Warning: Failed to load htpasswd file %s: %v", s.Config.HtpasswdFile, err)
		} else {
			log.Printf("[HTPASSWD] Successfully loaded %d users from %s", len(s.AuthStore.Htpasswd), s.Config.HtpasswdFile)
		}

		// Load app tokens
		if err := s.AuthStore.LoadAppTokens(s.Config.AppTokensFile); err != nil {
			log.Printf("[APP-TOKENS] Warning: Failed to load app tokens file %s: %v", s.Config.AppTokensFile, err)
		} else {
			log.Printf("[APP-TOKENS] Successfully loaded %d app tokens from %s", len(s.AuthStore.AppTokens), s.Config.AppTokensFile)
		}
	}

	if s.Config.X509Auth {
		// Load CA certificate for manual verification
		if err := s.AuthStore.LoadCACert(s.Config.CACert); err != nil {
			return fmt.Errorf("failed to load CA certificate: %w", err)
		}
		log.Printf("[CA-CERT] Successfully loaded CA certificate from %s", s.Config.CACert)
		s.AuthStore.X509Enabled = true

		if err := s.AuthStore.LoadGridmap(s.Config.GridmapFile); err != nil {
			log.Printf("[GRIDMAP] Warning: Failed to load gridmap file %s: %v", s.Config.GridmapFile, err)
		} else {
			log.Printf("[GRIDMAP] Successfully loaded %d DN mappings from %s", len(s.AuthStore.Gridmap), s.Config.GridmapFile)
		}
	}

	// Initialize OIDC if enabled
	if s.Config.OIDCAuth {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.AuthStore.InitializeOIDC(ctx, s.Config.OIDCIssuer, s.Config.OIDCClientID, s.Config.OIDCClientSecret, s.Config.OIDCRedirectURL); err != nil {
			return fmt.Errorf("failed to initialize OIDC: %w", err)
		}
		s.AuthStore.OIDCEnabled = true
		log.Printf("[OIDC] Successfully initialized OIDC authentication")
	}

	// Initialize Macaroon if enabled
	if s.Config.MacaroonAuth {
		if err := s.AuthStore.InitializeMacaroon(s.Config.MacaroonSecretKey, s.Config.MacaroonLocation); err != nil {
			return fmt.Errorf("failed to initialize macaroon: %w", err)
		}
		s.AuthStore.MacaroonEnabled = true
		log.Printf("[MACAROON] Successfully initialized macaroon authentication")
	}

	// Initialize third-party copy if enabled
	if s.Config.TPC {
		tpcCfg := tpc.Config{
			MarkerInterval: s.Config.TPCMarkerInterval,
			StallTimeout:   s.Config.TPCStallTimeout,
			MaxTransfers:   s.Config.TPCMaxTransfers,
			AllowHTTP:      s.Config.TPCAllowHTTP,
			AllowLocal:     s.Config.TPCAllowLocal,
			AllowPrivate:   s.Config.TPCAllowPrivate,
		}
		if s.Config.TPCCAPath != "" {
			pool, err := tpc.LoadCAs(s.Config.TPCCAPath)
			if err != nil {
				return fmt.Errorf("failed to load TPC CA certificates: %w", err)
			}
			tpcCfg.RootCAs = pool
		}
		s.Handler.TPC = tpc.New(tpcCfg)
		log.Printf("[TPC] Third-party copy enabled (max %d concurrent transfers)", s.Config.TPCMaxTransfers)
	}

	return nil
}

// applyAuthMiddleware applies the unified authentication middleware to a handler
func (s *Server) applyAuthMiddleware(handler http.Handler) http.Handler {
	// Unified authentication tries X.509 -> OIDC -> Macaroon -> Basic Auth in order
	handler = s.AuthStore.UnifiedAuthMiddleware(handler)

	// Apply logging middleware
	handler = logger.Middleware(handler)

	return handler
}

// applyBasicAuthMiddleware applies only basic authentication middleware
func (s *Server) applyBasicAuthMiddleware(handler http.Handler) http.Handler {
	handler = s.AuthStore.BasicAuthMiddleware(handler)
	handler = logger.Middleware(handler)
	return handler
}

// applyX509AuthMiddleware applies only X.509 authentication middleware
func (s *Server) applyX509AuthMiddleware(handler http.Handler) http.Handler {
	handler = s.AuthStore.X509AuthMiddleware(handler)
	handler = logger.Middleware(handler)
	return handler
}

// SetupRoutes sets up the HTTP routes
func (s *Server) SetupRoutes() *http.ServeMux {
	mux := http.NewServeMux()

	// Index page is publicly accessible (no auth required)
	mux.HandleFunc("/", s.Handler.IndexHandler)

	// WebDAV content requires authentication - use unified auth middleware
	mux.Handle("/webdav/", s.applyAuthMiddleware(s.Handler))

	// Authentication trigger routes - only create routes for enabled methods
	if s.Config.BasicAuth {
		// Basic auth trigger - any protected resource will prompt for basic auth
		basicHandler := s.applyBasicAuthMiddleware(http.HandlerFunc(s.Handler.BasicAuthSuccessHandler))
		mux.Handle("/auth/basic", basicHandler)
	}

	if s.Config.X509Auth && s.Config.TLS {
		// X.509 auth trigger - protected resource that requires client cert
		x509Handler := s.applyX509AuthMiddleware(http.HandlerFunc(s.Handler.X509AuthSuccessHandler))
		mux.Handle("/auth/x509", x509Handler)
	}

	// OIDC routes if OIDC is enabled
	if s.Config.OIDCAuth {
		mux.Handle("/auth/oidc", logger.Middleware(s.Handler.OIDCHandler(s.AuthStore)))
		mux.Handle("/oidc_redirect", logger.Middleware(s.Handler.OIDCRedirectHandler(s.AuthStore)))
		log.Printf("[OIDC] Added OIDC routes: /auth/oidc and /oidc_redirect")
	}

	// Macaroon routes if macaroon auth is enabled
	if s.Config.MacaroonAuth {
		log.Printf("[MACAROON] Macaroon requests handled via WebDAV POST with application/macaroon-request content-type")
	}

	// Utility routes
	mux.Handle("/proc/x509", logger.Middleware(http.HandlerFunc(s.Handler.ProcX509Handler)))

	// Add whoami route at /proc/whoami - apply auth middleware if any auth is enabled
	if s.Config.BasicAuth || s.Config.X509Auth || s.Config.OIDCAuth || s.Config.MacaroonAuth {
		// Create a whoami handler with authentication middleware
		whoamiHandler := s.applyAuthMiddleware(http.HandlerFunc(s.Handler.WhoAmIHandler))
		mux.Handle("/proc/whoami", whoamiHandler)
	} else {
		// No authentication required, add directly
		mux.HandleFunc("/proc/whoami", s.Handler.WhoAmIHandler)
	}

	log.Printf("[ROUTES] Added routes: / (public), /webdav/* (protected), /proc/whoami, /proc/x509")
	return mux
}

// SetupTLS configures TLS if enabled
func (s *Server) SetupTLS() (*tls.Config, error) {
	if !s.Config.TLS {
		return nil, nil
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

	if s.Config.X509Auth {
		if s.AuthStore.CACertPool == nil {
			return nil, errors.New("CA certificate (-ca-cert) is required when X.509 authentication is enabled")
		}

		// Request client certificates but validate them in the authentication
		// middleware: this allows grid proxy chains, detailed logging and fallback
		// to other methods
		tlsConfig.ClientCAs = s.AuthStore.CACertPool
		tlsConfig.ClientAuth = tls.RequestClientCert
		log.Printf("[TLS] X.509 client authentication enabled with CA verification: %s", s.Config.CACert)
		log.Printf("[TLS] Client certificates will be validated in authentication middleware")
	}

	return tlsConfig, nil
}

// createCustomErrorLogger creates a custom logger for HTTP server errors
func (s *Server) createCustomErrorLogger() *log.Logger {
	return log.New(&customLogWriter{}, "", 0)
}

// customLogWriter formats HTTP server errors to match our logging style
type customLogWriter struct{}

func (w *customLogWriter) Write(p []byte) (n int, err error) {
	msg := string(p)
	// Remove trailing newline if present
	msg = strings.TrimSuffix(msg, "\n")

	// Format TLS handshake errors consistently
	if strings.Contains(msg, "TLS handshake error") {
		log.Printf("[TLS] %s", msg)
	} else {
		// Format other HTTP server errors
		log.Printf("[HTTP-SERVER] %s", msg)
	}

	return len(p), nil
}

// Run serves until ctx is cancelled, then shuts down gracefully: new connections are
// refused, in-flight requests get shutdownGrace to finish, and whatever is still
// running after that (e.g. long third-party copies) is cancelled
func (s *Server) Run(ctx context.Context) error {
	address := fmt.Sprintf("%s:%d", s.Config.Address, s.Config.Port)
	mux := s.SetupRoutes()

	baseCtx, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()

	s.server = &http.Server{
		Addr:     address,
		Handler:  mux,
		ErrorLog: s.createCustomErrorLogger(),
		// No ReadTimeout/WriteTimeout: transfers of large files legitimately take long
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		BaseContext:       func(net.Listener) context.Context { return baseCtx },
	}

	errCh := make(chan error, 1)
	if s.Config.TLS {
		tlsConfig, err := s.SetupTLS()
		if err != nil {
			return err
		}
		s.server.TLSConfig = tlsConfig
		log.Printf("[STARTUP] Starting HTTPS server on %s (serving directory: %s)", address, s.Config.Directory)
		go func() { errCh <- s.server.ListenAndServeTLS(s.Config.TLSCert, s.Config.TLSKey) }()
	} else {
		log.Printf("[STARTUP] Starting HTTP server on %s (serving directory: %s)", address, s.Config.Directory)
		go func() { errCh <- s.server.ListenAndServe() }()
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	log.Printf("[SHUTDOWN] Shutting down (waiting up to %v for in-flight requests)", shutdownGrace)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := s.server.Shutdown(shutdownCtx); err != nil {
		log.Printf("[SHUTDOWN] Cancelling remaining requests: %v", err)
		cancelBase()
		s.server.Close()
	}
	return nil
}

// LogStartupInfo logs the server startup information
func (s *Server) LogStartupInfo() {
	log.Println("=== WebDAV Server Starting ===")
	log.Printf("Configuration:")
	log.Printf("  - Port: %d", s.Config.Port)
	log.Printf("  - Address: %s", s.Config.Address)
	log.Printf("  - Directory: %s", s.Config.Directory)
	log.Printf("  - TLS: %t", s.Config.TLS)
	log.Printf("  - X.509 Auth: %t", s.Config.X509Auth)
	log.Printf("  - Basic Auth: %t", s.Config.BasicAuth)
	log.Printf("  - OIDC Auth: %t", s.Config.OIDCAuth)
	log.Printf("  - Macaroon Auth: %t", s.Config.MacaroonAuth)
	log.Printf("  - Third-party copy: %t", s.Config.TPC)
	if s.Config.BasicAuth {
		log.Printf("  - Htpasswd File: %s", s.Config.HtpasswdFile)
		log.Printf("  - App Tokens File: %s", s.Config.AppTokensFile)
	}
	if s.Config.OIDCAuth {
		log.Printf("  - OIDC Issuer: %s", s.Config.OIDCIssuer)
		log.Printf("  - OIDC Client ID: %s", s.Config.OIDCClientID)
		log.Printf("  - OIDC Redirect URL: %s", s.Config.OIDCRedirectURL)
	}
	if s.Config.MacaroonAuth {
		log.Printf("  - Macaroon Max Validity: %v", s.Config.MacaroonMaxValidity)
	}
	if s.Config.TPC && (s.Config.TPCAllowHTTP || s.Config.TPCAllowLocal || s.Config.TPCAllowPrivate) {
		log.Printf("  - TPC allow http: %t, allow local addresses: %t, allow private addresses: %t",
			s.Config.TPCAllowHTTP, s.Config.TPCAllowLocal, s.Config.TPCAllowPrivate)
	}
	if !s.Config.TLS && (s.Config.BasicAuth || s.Config.MacaroonAuth || s.Config.OIDCAuth) {
		log.Printf("WARNING: TLS is disabled; passwords and tokens are sent in clear text")
	}
	log.Println("===============================")
}
