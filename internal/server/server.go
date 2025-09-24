package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

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
	return &Server{
		Config:    cfg,
		AuthStore: auth.NewAuthStore(),
		Handler:   handlers.NewWebDAVHandler(cfg.Directory),
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
		if err := s.AuthStore.LoadGridmap(s.Config.GridmapFile); err != nil {
			log.Printf("[GRIDMAP] Warning: Failed to load gridmap file %s: %v", s.Config.GridmapFile, err)
		} else {
			log.Printf("[GRIDMAP] Successfully loaded %d DN mappings from %s", len(s.AuthStore.Gridmap), s.Config.GridmapFile)
		}
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

	// Add logging middleware
	middlewareChain = logger.Middleware(middlewareChain)

	return middlewareChain
}

// SetupRoutes sets up the HTTP routes
func (s *Server) SetupRoutes() *http.ServeMux {
	middlewareChain := s.SetupMiddleware()
	
	mux := http.NewServeMux()
	mux.Handle("/", middlewareChain)
	mux.HandleFunc("/proc/x509", s.Handler.ProcX509Handler)
	
	return mux
}

// SetupTLS configures TLS if enabled
func (s *Server) SetupTLS() *tls.Config {
	if !s.Config.TLS {
		return nil
	}

	tlsConfig := &tls.Config{}
	
	if s.Config.X509Auth {
		// Load CA certificate if specified
		if s.Config.CACert != "" {
			caCert, err := ioutil.ReadFile(s.Config.CACert)
			if err != nil {
				log.Fatalf("Failed to read CA certificate: %v", err)
			}
			
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				log.Fatal("Failed to parse CA certificate")
			}
			
			tlsConfig.ClientCAs = caCertPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			log.Printf("[STARTUP] X.509 client authentication enabled with CA: %s", s.Config.CACert)
		} else {
			tlsConfig.ClientAuth = tls.RequestClientCert
			log.Printf("[STARTUP] X.509 client authentication enabled (no CA verification)")
		}
	}
	
	return tlsConfig
}

// Start starts the server
func (s *Server) Start() error {
	address := fmt.Sprintf("%s:%d", s.Config.Address, s.Config.Port)
	mux := s.SetupRoutes()
	
	s.server = &http.Server{
		Addr:    address,
		Handler: mux,
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
	if s.Config.BasicAuth {
		log.Printf("  - Htpasswd File: %s", s.Config.HtpasswdFile)
		log.Printf("  - App Tokens File: %s", s.Config.AppTokensFile)
	}
	log.Println("===============================")
}

