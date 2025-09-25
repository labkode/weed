package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/labkode/weed/internal/auth"
	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/handlers"
	"github.com/labkode/weed/internal/logger"
)

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
		if s.Config.CACert != "" {
			if err := s.AuthStore.LoadCACert(s.Config.CACert); err != nil {
				return fmt.Errorf("failed to load CA certificate: %w", err)
			}
			log.Printf("[CA-CERT] Successfully loaded CA certificate from %s", s.Config.CACert)
		}

		if err := s.AuthStore.LoadGridmap(s.Config.GridmapFile); err != nil {
			log.Printf("[GRIDMAP] Warning: Failed to load gridmap file %s: %v", s.Config.GridmapFile, err)
		} else {
			log.Printf("[GRIDMAP] Successfully loaded %d DN mappings from %s", len(s.AuthStore.Gridmap), s.Config.GridmapFile)
		}
	}

	// Initialize OIDC if enabled
	if s.Config.OIDCAuth {
		ctx := context.Background()
		if err := s.AuthStore.InitializeOIDC(ctx, s.Config.OIDCIssuer, s.Config.OIDCClientID, s.Config.OIDCClientSecret, s.Config.OIDCRedirectURL); err != nil {
			return fmt.Errorf("failed to initialize OIDC: %w", err)
		}
		log.Printf("[OIDC] Successfully initialized OIDC authentication")
	}

	// Initialize Macaroon if enabled
	if s.Config.MacaroonAuth {
		if err := s.AuthStore.InitializeMacaroon(s.Config.MacaroonSecretKey, s.Config.MacaroonLocation); err != nil {
			return fmt.Errorf("failed to initialize macaroon: %w", err)
		}
		log.Printf("[MACAROON] Successfully initialized macaroon authentication")
	}

	return nil
}

// SetupMiddleware sets up the middleware chain
func (s *Server) SetupMiddleware() http.Handler {
	var middlewareChain http.Handler = s.Handler

	// Add authentication middleware
	if s.Config.BasicAuth {
		middlewareChain = s.AuthStore.BasicAuthMiddleware(middlewareChain)
	}
	if s.Config.X509Auth {
		middlewareChain = s.AuthStore.X509AuthMiddleware(middlewareChain)
	}
	if s.Config.OIDCAuth {
		middlewareChain = s.AuthStore.OIDCAuthMiddleware(middlewareChain)
	}

	// Add logging middleware
	middlewareChain = logger.Middleware(middlewareChain)

	return middlewareChain
}

// createWebDAVHandler creates a WebDAV handler that works with the /webdav prefix
// The WebDAV handler's Prefix field handles path stripping and href generation automatically
func (s *Server) createWebDAVHandler(handler http.Handler) http.Handler {
	return handler
}

// applyAuthMiddleware applies the unified authentication middleware to a handler
func (s *Server) applyAuthMiddleware(handler http.Handler) http.Handler {
	// First apply unified authentication middleware that tries X.509 -> OIDC -> Macaroon -> Basic Auth in order
	handler = s.AuthStore.UnifiedAuthMiddleware(handler)

	// After authentication, apply macaroon minting middleware (if macaroon auth is enabled)
	if s.Config.MacaroonAuth {
		handler = s.Handler.MacaroonMintingMiddleware(handler)
	}

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
	// Create a custom handler that preserves the /webdav prefix for proper href generation
	// but strips it for filesystem access
	webdavHandler := s.applyAuthMiddleware(s.Handler)
	mux.Handle("/webdav/", s.createWebDAVHandler(webdavHandler))

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
		mux.HandleFunc("/auth/oidc", s.Handler.OIDCHandler(s.AuthStore))
		mux.HandleFunc("/oidc_redirect", s.Handler.OIDCRedirectHandler(s.AuthStore))
		log.Printf("[OIDC] Added OIDC routes: /auth/oidc and /oidc_redirect")
	}

	// Macaroon routes if macaroon auth is enabled
	if s.Config.MacaroonAuth {
		log.Printf("[MACAROON] Macaroon requests handled via WebDAV POST with application/macaroon-request content-type")
	}

	// Utility routes
	mux.HandleFunc("/proc/x509", s.Handler.ProcX509Handler)

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
func (s *Server) SetupTLS() *tls.Config {
	if !s.Config.TLS {
		return nil
	}

	tlsConfig := &tls.Config{}

	if s.Config.X509Auth {
		// CA certificate is required for X.509 authentication
		if s.Config.CACert == "" {
			log.Fatal("CA certificate (-ca-cert) is required when X.509 authentication is enabled")
		}

		// Load CA certificate
		caCert, err := os.ReadFile(s.Config.CACert)
		if err != nil {
			log.Fatalf("Failed to read CA certificate from %s: %v", s.Config.CACert, err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			log.Fatalf("Failed to parse CA certificate from %s", s.Config.CACert)
		}

		// Set up TLS to request client certificates but validate them in our middleware
		// This allows us to handle certificate validation with detailed logging and fallback
		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequestClientCert
		log.Printf("[TLS] X.509 client authentication enabled with CA verification: %s", s.Config.CACert)
		log.Printf("[TLS] Client certificates will be validated in authentication middleware")
	}

	return tlsConfig
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

// Start starts the server
func (s *Server) Start() error {
	address := fmt.Sprintf("%s:%d", s.Config.Address, s.Config.Port)
	mux := s.SetupRoutes()

	s.server = &http.Server{
		Addr:     address,
		Handler:  mux,
		ErrorLog: s.createCustomErrorLogger(),
	}

	if s.Config.TLS {
		s.server.TLSConfig = s.SetupTLS()
		log.Printf("[STARTUP] Starting HTTPS server on %s (serving directory: %s)", address, s.Config.Directory)
		return s.server.ListenAndServeTLS("server.crt", "server.key")
	} else {
		log.Printf("[STARTUP] Starting HTTP server on %s (serving directory: %s)", address, s.Config.Directory)
		return s.server.ListenAndServe()
	}
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
	if s.Config.BasicAuth {
		log.Printf("  - Htpasswd File: %s", s.Config.HtpasswdFile)
		log.Printf("  - App Tokens File: %s", s.Config.AppTokensFile)
	}
	if s.Config.OIDCAuth {
		log.Printf("  - OIDC Issuer: %s", s.Config.OIDCIssuer)
		log.Printf("  - OIDC Client ID: %s", s.Config.OIDCClientID)
		log.Printf("  - OIDC Redirect URL: %s", s.Config.OIDCRedirectURL)
	}
	log.Println("===============================")
}
