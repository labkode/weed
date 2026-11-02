package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/labkode/weed/internal/auth"
	"github.com/labkode/weed/internal/bans"
	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/handlers"
	"github.com/labkode/weed/internal/limits"
	"github.com/labkode/weed/internal/logger"
	"github.com/labkode/weed/internal/metrics"
	"github.com/labkode/weed/internal/systemd"
	"github.com/labkode/weed/internal/tpc"
	"github.com/labkode/weed/internal/version"
	"github.com/labkode/weed/internal/worker"
	"github.com/labkode/weed/internal/x509utils"
)

// shutdownGrace is how long in-flight requests get to finish on shutdown
const shutdownGrace = 30 * time.Second

// Server represents the WebDAV server
type Server struct {
	Config    *config.Config
	AuthStore *auth.AuthStore
	Handler   *handlers.WebDAVHandler
	// Workers serve the files of each Unix account
	Workers *worker.Pool
	// Bans are the users refused whatever their credentials (weed utils ban)
	Bans *bans.List
	// MonitorOnMainPort also serves /metrics and /status on the main port, as weed
	// does without a configuration file (see config.QuickStart): its clients are local,
	// and can already read and write every file
	MonitorOnMainPort bool
	server            *http.Server

	inProgress inProgress   // the requests being served, by user and kind
	storage    storageProbe // /healthz's stat of the exported directory

	limits  atomic.Pointer[limits.Limits] // what accounts are allowed, replaced on reload
	cgroups bool                          // the workers of each account have a cgroup
	moved   chan error                    // the exported directory is out of reach (see Run)
	// unmounted is set while the storage of the exported directory is not mounted
	// (see worker.UnmountedError): requests get 503
	unmounted atomic.Pointer[unmounted]

	reloadMu sync.Mutex
	cert     atomic.Pointer[tls.Certificate] // TLS server certificate, replaced on reload

	run      running // what runs, compared to what a restart would run (see status.go)
	checking bool    // weed check: only find out whether weed would start
	// inProcess serves files in this process, as its user, without Unix accounts or
	// workers: for tests of request handling, which is what workers run. weed always
	// accesses files as the Unix account of each request.
	inProcess bool
}

// New creates a new server instance
func New(cfg *config.Config) *Server {
	authStore := auth.NewAuthStore()
	return &Server{
		Config:    cfg,
		AuthStore: authStore,
		Handler:   handlers.NewWebDAVHandler(cfg.Directory, cfg, authStore),
		run:       newRunning(cfg),
	}
}

// Initialize sets up authentication and other server components
func (s *Server) Initialize() error {
	if s.Config.RequireMount {
		if err := checkMounted(s.Config.Directory); err != nil {
			return err
		}
	}
	// Initialize authentication systems if enabled
	if s.Config.BasicAuth {
		s.AuthStore.BasicEnabled = true
		s.AuthStore.PrepareBasicAuth()
	}
	s.AuthStore.X509Enabled = s.Config.X509Auth
	s.AuthStore.Anonymous = s.Config.Anonymous
	s.AuthStore.TokenEnabled = s.Config.TokenIssuers != ""
	s.AuthStore.UnixUsers = !s.inProcess
	if s.Config.TokenCAPath != "" {
		pool, err := x509utils.SystemPoolWith(s.Config.TokenCAPath)
		if err != nil {
			return fmt.Errorf("failed to load token issuer CA certificates: %w", err)
		}
		s.AuthStore.SetTokenRootCAs(pool)
	}
	creds, _, err := s.loadCredentials(nil)
	if err != nil {
		return err
	}
	s.AuthStore.SetCredentials(creds)
	if s.Bans, err = bans.Load(s.Config.BansFile); err != nil {
		return fmt.Errorf("cannot read the banned users (admin.bans): %w", err)
	}
	s.AuthStore.Bans = s.Bans
	if n := s.Bans.Len(); n > 0 {
		slog.Info("users are banned", "count", n, "file", s.Config.BansFile)
	}

	// The OIDC login page gives out tokens of one of the token issuers
	if s.Config.OIDCAuth {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c := s.Config
		if err := s.AuthStore.InitializeOIDC(ctx, auth.OIDCConfig{
			Issuer: c.OIDCIssuer, ClientID: c.OIDCClientID, ClientSecret: c.OIDCClientSecret,
			RedirectURL: c.OIDCRedirectURL, Scopes: c.OIDCScopes, Audience: c.OIDCAudience,
		}); err != nil {
			return fmt.Errorf("failed to initialize OIDC: %w", err)
		}
	}

	// Initialize Macaroon if enabled
	if s.Config.MacaroonAuth {
		if err := s.AuthStore.InitializeMacaroon(s.Config.MacaroonSecretKey, s.Config.MacaroonLocation); err != nil {
			return fmt.Errorf("failed to initialize macaroon: %w", err)
		}
		s.AuthStore.MacaroonEnabled = true
	}

	// Initialize third-party copy if enabled
	if s.Config.TPC {
		if s.Handler.TPC, err = newTPCEngine(s.Config); err != nil {
			return err
		}
	}

	if !s.inProcess {
		if err := s.startWorkers(); err != nil {
			return fmt.Errorf("cannot start the worker processes, which access files as Unix accounts: %w", err)
		}
	}
	return nil
}

// newTPCEngine creates the engine that runs third-party copies, which pay with payer
// for the bytes they move (nil: not paced)
func newTPCEngine(cfg *config.Config) (*tpc.Engine, error) {
	tpcCfg := tpc.Config{
		MarkerInterval: cfg.TPCMarkerInterval,
		StallTimeout:   cfg.TPCStallTimeout,
		MaxTransfers:   cfg.TPCMaxTransfers,
		AllowHTTP:      cfg.TPCAllowHTTP,
		AllowLocal:     cfg.TPCAllowLocal,
		AllowPrivate:   cfg.TPCAllowPrivate,
	}
	if cfg.TPCCAPath != "" {
		pool, err := x509utils.SystemPoolWith(cfg.TPCCAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load TPC CA certificates: %w", err)
		}
		tpcCfg.RootCAs = pool
	}
	return tpc.New(tpcCfg), nil
}

// loadCredentials reads the credential files of the enabled authentication methods.
// When a file cannot be read, its previous contents (from prev) are kept, so that a
// file being rewritten or broken during a reload neither locks everybody out nor
// lets anybody in. At startup (prev == nil) unreadable CAs or CRLs are fatal.
func (s *Server) loadCredentials(prev *auth.Credentials) (c *auth.Credentials, complete bool, err error) {
	startup := prev == nil
	if startup {
		prev = &auth.Credentials{}
	}
	next := *prev
	c, complete = &next, true
	loadMap := func(what, file string, load func(string) (map[string]string, error), dst *map[string]string) {
		m, err := load(file)
		if errors.Is(err, fs.ErrNotExist) && len(*dst) == 0 {
			// Not configured (e.g. the default .app-tokens does not exist): not a problem
			if startup {
				slog.Info("no "+what+" file", "file", file)
			}
			return
		}
		if err != nil {
			slog.Warn("cannot read "+what+" file, keeping the previous entries", "file", file, "entries", len(*dst), "error", err)
			complete = false
			return
		}
		*dst = m
		slog.Info("loaded "+what+" file", "file", file, "entries", len(m))
	}

	if s.Config.BasicAuth {
		loadMap("htpasswd", s.Config.HtpasswdFile, auth.LoadHtpasswd, &next.Htpasswd)
		loadMap("app tokens", s.Config.AppTokensFile, auth.LoadAppTokens, &next.AppTokens)
	}
	if s.Config.X509Auth {
		// Only certificates listed in the grid-mapfile are accepted, so X.509 needs one
		gridmap, err := auth.LoadGridmap(s.Config.GridmapFile)
		switch {
		case err == nil:
			c.Gridmap = gridmap
			slog.Info("loaded grid-mapfile", "file", s.Config.GridmapFile, "entries", len(gridmap))
		case startup:
			return nil, false, fmt.Errorf("failed to load the grid-mapfile: %w", err)
		default:
			slog.Warn("cannot read grid-mapfile, keeping the previous entries", "file", s.Config.GridmapFile, "entries", len(prev.Gridmap), "error", err)
			complete = false
		}

		roots, n, err := auth.LoadCAs(s.Config.CACert)
		switch {
		case err == nil:
			c.Roots = roots
			slog.Info("loaded CA certificates", "path", s.Config.CACert, "certificates", n)
		case prev.Roots == nil:
			return nil, false, fmt.Errorf("failed to load CA certificates: %w", err)
		default:
			slog.Warn("cannot read CA certificates, keeping the previous ones", "path", s.Config.CACert, "error", err)
			complete = false
		}

		if s.Config.CRLPath != "" {
			crls, err := x509utils.LoadCRLs(s.Config.CRLPath, s.Config.CRLMode != config.CRLIfValid)
			switch {
			case err == nil:
				c.CRLs = crls
				slog.Info("loaded CRLs", "path", s.Config.CRLPath, "crls", crls.Len(), "mode", s.Config.CRLMode)
			case prev.CRLs == nil:
				return nil, false, fmt.Errorf("failed to load CRLs: %w", err)
			default:
				slog.Warn("cannot read CRLs, keeping the previous ones", "path", s.Config.CRLPath, "error", err)
				complete = false
			}
		}
	}
	if s.Config.TokenIssuers != "" {
		issuers, err := auth.LoadTokenIssuers(s.Config.TokenIssuers)
		switch {
		case err == nil:
			c.TokenIssuers = issuers
			slog.Info("loaded token issuers", "file", s.Config.TokenIssuers, "issuers", len(issuers))
		case startup:
			return nil, false, fmt.Errorf("failed to load token issuers: %w", err)
		default:
			slog.Warn("cannot read token issuers, keeping the previous ones", "file", s.Config.TokenIssuers, "error", err)
			complete = false
		}
	}
	return c, complete, nil
}

// loadCertificate reads the TLS server certificate and key
func (s *Server) loadCertificate() error {
	cert, err := tls.LoadX509KeyPair(s.Config.TLSCert, s.Config.TLSKey)
	if err != nil {
		return err
	}
	s.cert.Store(&cert)
	return nil
}

// Reload re-reads the credential files, the TLS server certificate and the CAs used
// to verify third-party copy endpoints; whatever cannot be read is kept as it was.
// New connections and requests use the new data; established ones are not affected.
func (s *Server) Reload() {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	slog.Info("reloading credentials")

	creds, complete, err := s.loadCredentials(s.AuthStore.Credentials())
	if err != nil {
		slog.Warn("cannot reload credentials", "error", err) // only possible at startup
		complete = false
	} else {
		s.AuthStore.SetCredentials(creds)
	}
	s.AuthStore.ForgetUnixUsers()
	if s.Workers != nil {
		if ok, _ := s.loadLimits(); !ok {
			complete = false
		}
		if err := s.Workers.Reload(); err != nil {
			slog.Warn("cannot write the cgroup limits of accounts", "error", err)
			complete = false
		}
	}
	if s.Config.TLS && s.cert.Load() != nil {
		if err := s.loadCertificate(); err != nil {
			slog.Warn("cannot read the TLS certificate, keeping the previous one", "cert", s.Config.TLSCert, "error", err)
			complete = false
		}
	}
	if s.Handler.TPC != nil && s.Config.TPCCAPath != "" {
		if pool, err := x509utils.SystemPoolWith(s.Config.TPCCAPath); err != nil {
			slog.Warn("cannot read the CA certificates of TPC endpoints, keeping the previous ones", "path", s.Config.TPCCAPath, "error", err)
			complete = false
		} else {
			s.Handler.TPC.SetRootCAs(pool)
		}
	}
	if s.Config.TokenCAPath != "" {
		if pool, err := x509utils.SystemPoolWith(s.Config.TokenCAPath); err != nil {
			slog.Warn("cannot read the CA certificates of token issuers, keeping the previous ones", "path", s.Config.TokenCAPath, "error", err)
			complete = false
		} else {
			s.AuthStore.SetTokenRootCAs(pool)
		}
	}
	if complete {
		metrics.Reloads.Inc("success")
	} else {
		metrics.Reloads.Inc("partial")
	}
	s.reloaded(complete)
}

// writeGauges writes the metrics computed when scraped: when credentials expire
func (s *Server) writeGauges(w io.Writer) {
	if crls := s.AuthStore.Credentials().CRLs; crls != nil {
		if t := crls.Expiry(); !t.IsZero() {
			metrics.WriteGauge(w, "weed_crl_expiry_timestamp_seconds",
				"When the first CA runs out of current CRLs (with x509.crl_mode = \"require\" its users are rejected from then on).",
				float64(t.Unix()), nil, nil)
		}
	}
	if cert := s.cert.Load(); cert != nil && cert.Leaf != nil {
		metrics.WriteGauge(w, "weed_tls_certificate_expiry_timestamp_seconds", "When the TLS server certificate expires.",
			float64(cert.Leaf.NotAfter.Unix()), nil, nil)
	}
	s.writeStatusGauges(w)
	blocked := 0
	if s.Workers != nil {
		for _, wk := range s.Workers.Workers() {
			blocked += wk.BlockedThreads
		}
	}
	metrics.WriteGauge(w, "weed_worker_blocked_threads",
		"Threads of the worker processes that wait in the kernel, uninterruptibly: for a moment while they read or write files; for long while the storage does not answer, and then their requests do not end, nor do their workers exit, even when killed.",
		float64(blocked), nil, nil)
}

// healthz reports whether the exported directory responds (a hung network
// filesystem would otherwise only show up as hanging requests), and whether its
// storage is mounted: the directory beneath it would answer
func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	if s.unmounted.Load() != nil {
		http.Error(w, "storage not mounted", http.StatusServiceUnavailable)
		return
	}
	p := s.storage.check(func() error {
		_, err := os.Stat(s.Config.Directory)
		return err
	})
	select {
	case <-p.done:
		if p.err != nil {
			http.Error(w, "storage unavailable", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	case <-time.After(5 * time.Second):
		http.Error(w, "storage not responding", http.StatusServiceUnavailable)
	}
}

// storageProbe makes one stat of the exported directory at a time. While the storage
// does not answer, a stat waits in the kernel, and so does the thread that makes it:
// later calls wait for that stat rather than each block another thread (until there
// are too many for the Go runtime, which then stops weed).
type storageProbe struct {
	mu   sync.Mutex
	last *probe // in progress, or the last one
}

type probe struct {
	done chan struct{}
	err  error // once done is closed
}

// check returns the stat in progress, or else starts one with stat
func (sp *storageProbe) check(stat func() error) *probe {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if sp.last != nil {
		select {
		case <-sp.last.done:
		default:
			return sp.last
		}
	}
	p := &probe{done: make(chan struct{})}
	sp.last = p
	go func() {
		p.err = stat()
		close(p.done)
	}()
	return p
}

// MetricsHandler serves /metrics, /healthz, /status and the dashboard, to which /
// leads
func (s *Server) MetricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.healthz)
	mux.Handle("GET /{$}", http.RedirectHandler("dashboard/", http.StatusFound))
	s.handleMonitoring(mux)
	return mux
}

// handleMonitoring adds /metrics, /status and the dashboard to mux
func (s *Server) handleMonitoring(mux *http.ServeMux) {
	mux.Handle("/metrics", metrics.Handler(s.writeGauges))
	mux.HandleFunc("/status", s.statusHandler)
	mux.Handle("GET /dashboard/", dashboardHandler())
}

// applyAuthMiddleware applies the unified authentication middleware to a handler
func (s *Server) applyAuthMiddleware(handler http.Handler) http.Handler {
	// Unified authentication tries X.509 -> token -> macaroon -> Basic in order
	return s.AuthStore.UnifiedAuthMiddleware(handler)
}

// applyBasicAuthMiddleware applies only basic authentication middleware
func (s *Server) applyBasicAuthMiddleware(handler http.Handler) http.Handler {
	return s.AuthStore.BasicAuthMiddleware(handler)
}

// applyX509AuthMiddleware applies only X.509 authentication middleware
func (s *Server) applyX509AuthMiddleware(handler http.Handler) http.Handler {
	return s.AuthStore.X509AuthMiddleware(handler)
}

// SetupRoutes sets up the HTTP routes of the main port. Every request is logged
// ("request") and counted (weed_http_requests_total) once, whatever it is for.
func (s *Server) SetupRoutes() http.Handler {
	mux := http.NewServeMux()

	// Index page is publicly accessible (no auth required)
	mux.HandleFunc("/", s.Handler.IndexHandler)

	// WebDAV content requires authentication - use unified auth middleware
	mux.Handle("/webdav/", s.applyAuthMiddleware(s.track(s.webdavHandler())))

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

	// The OIDC login page, and the provider's redirect back to weed
	if s.Config.OIDCAuth {
		mux.Handle("/auth/oidc", s.Handler.OIDCHandler(s.AuthStore))
		mux.Handle("/oidc_redirect", s.Handler.OIDCRedirectHandler(s.AuthStore))
	}

	// Utility routes
	mux.HandleFunc("/proc/x509", s.Handler.ProcX509Handler)
	mux.HandleFunc("/healthz", s.healthz)
	if s.MonitorOnMainPort {
		s.handleMonitoring(mux)
	}

	// Add whoami route at /proc/whoami - apply auth middleware if any auth is enabled
	if s.Config.BasicAuth || s.Config.X509Auth || s.Config.MacaroonAuth || s.Config.TokenIssuers != "" {
		// Create a whoami handler with authentication middleware
		whoamiHandler := s.applyAuthMiddleware(http.HandlerFunc(s.Handler.WhoAmIHandler))
		mux.Handle("/proc/whoami", whoamiHandler)
	} else {
		// No authentication required, add directly
		mux.HandleFunc("/proc/whoami", s.Handler.WhoAmIHandler)
	}

	return logger.Middleware(mux)
}

// SetupTLS configures TLS if enabled
func (s *Server) SetupTLS() (*tls.Config, error) {
	if !s.Config.TLS {
		return nil, nil
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

	if s.Config.X509Auth {
		if s.AuthStore.Credentials().Roots == nil {
			return nil, errors.New("CA certificate (x509.ca) is required when X.509 authentication is enabled")
		}

		// Request client certificates but validate them in the authentication
		// middleware: this allows grid proxy chains, detailed logging and fallback
		// to other methods
		tlsConfig.ClientCAs = s.AuthStore.Credentials().Roots
		tlsConfig.ClientAuth = tls.RequestClientCert
	}

	return tlsConfig, nil
}

// ErrRestart is returned by Run when weed must be started again: confined with
// Landlock to the exported directory as it was, it no longer reaches it
var ErrRestart = errors.New("weed exits, to be started again")

// RestartStatus is weed's exit status after ErrRestart (EX_TEMPFAIL), on which
// supervisors start it again (systemd: Restart=on-failure)
const RestartStatus = 75

// Run serves until ctx is cancelled, then shuts down gracefully: new connections are
// refused, in-flight requests get shutdownGrace to finish, and whatever is still
// running after that (e.g. long third-party copies) is cancelled. It does so too,
// returning ErrRestart, once the exported directory is out of its reach.
func (s *Server) Run(ctx context.Context) error {
	address := fmt.Sprintf("%s:%d", s.Config.Address, s.Config.Port)
	mux := s.SetupRoutes()

	baseCtx, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()

	s.server = &http.Server{
		Addr:     address,
		Handler:  mux,
		ErrorLog: logger.ErrorLog(),
		// No ReadTimeout/WriteTimeout: transfers of large files legitimately take long
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		BaseContext:       func(net.Listener) context.Context { return baseCtx },
	}

	// Listen first, so that a port in use stops weed at once and systemd hears it is
	// ready only once it is; on the sockets that systemd passed, if it did
	passed, err := passedListeners()
	if err != nil {
		return err
	}
	ln, activated, err := listen(passed, address)
	if err != nil {
		closeAll(passed)
		return err
	}
	var ml net.Listener
	var mlActivated bool
	if s.Config.MetricsAddress != "" {
		if ml, mlActivated, err = listen(passed, s.Config.MetricsAddress); err != nil {
			ln.Close()
			closeAll(passed)
			return fmt.Errorf("metrics server: %w", err)
		}
	}
	if len(passed) > 0 {
		ln.Close()
		if ml != nil {
			ml.Close()
		}
		var ports []string
		for port := range passed {
			ports = append(ports, strconv.Itoa(port))
		}
		closeAll(passed)
		return fmt.Errorf("systemd passed sockets on ports %s, which are neither server.port nor that of server.metrics_address", strings.Join(ports, ", "))
	}
	errCh := make(chan error, 2)
	if s.Config.TLS {
		tlsConfig, err := s.SetupTLS()
		if err != nil {
			ln.Close()
			return err
		}
		if err := s.loadCertificate(); err != nil {
			ln.Close()
			return fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		// Certificates and the CAs advertised to clients follow reloads
		tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return s.cert.Load(), nil }
		if s.Config.X509Auth {
			base := tlsConfig.Clone()
			tlsConfig.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
				c := base.Clone()
				c.ClientCAs = s.AuthStore.Credentials().Roots
				return c, nil
			}
		}
		s.server.TLSConfig = tlsConfig
		slog.Info("listening", append([]any{"address", ln.Addr().String(), "scheme", "https"}, passedBy(activated)...)...)
		go func() { errCh <- s.server.ServeTLS(ln, "", "") }()
	} else {
		slog.Info("listening", append([]any{"address", ln.Addr().String(), "scheme", "http"}, passedBy(activated)...)...)
		go func() { errCh <- s.server.Serve(ln) }()
	}
	if s.MonitorOnMainPort {
		slog.Info("serving metrics", "address", ln.Addr().String())
	}
	stopAdmin, err := s.startAdmin()
	if err != nil {
		s.server.Close()
		if ml != nil {
			ml.Close()
		}
		return err
	}
	defer stopAdmin()

	if ml != nil {
		ms := &http.Server{Handler: s.MetricsHandler(), ReadHeaderTimeout: 10 * time.Second}
		slog.Info("serving metrics", append([]any{"address", ml.Addr().String()}, passedBy(mlActivated)...)...)
		go func() {
			if err := ms.Serve(ml); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("metrics server: %w", err)
			}
		}()
		defer ms.Close()
	}
	go s.watchRestart(ctx)
	systemd.Ready(s.StatusLine())
	if s.Config.ReloadInterval > 0 {
		go func() {
			ticker := time.NewTicker(s.Config.ReloadInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					s.Reload()
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	var restart error
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	case restart = <-s.moved:
		slog.Warn("weed exits, to be started again by its supervisor, confined to the exported directory as it now is",
			"status", RestartStatus, "error", restart)
	}

	systemd.Stopping()
	slog.Info("shutting down, waiting for requests in progress", "grace", shutdownGrace)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := s.server.Shutdown(shutdownCtx); err != nil {
		slog.Warn("cancelling the remaining requests", "error", err)
		cancelBase()
		s.server.Close()
	}
	s.Close()
	if restart != nil {
		return fmt.Errorf("%w: %w", ErrRestart, restart)
	}
	return nil
}

// passedListeners are the sockets that systemd passed (socket activation), by port
func passedListeners() (map[int]net.Listener, error) {
	ls, err := systemd.Listeners()
	if err != nil {
		return nil, err
	}
	byPort := make(map[int]net.Listener)
	for _, l := range ls {
		a, ok := l.Addr().(*net.TCPAddr)
		if !ok || byPort[a.Port] != nil {
			closeAll(byPort)
			for _, l := range ls {
				l.Close()
			}
			return nil, fmt.Errorf("systemd passed a socket on %s: weed takes one TCP socket per port (ListenStream=)", l.Addr())
		}
		byPort[a.Port] = l
	}
	return byPort, nil
}

// listen takes the socket that systemd passed for the port of address, or listens on
// address; activated says which
func listen(passed map[int]net.Listener, address string) (l net.Listener, activated bool, err error) {
	if _, p, err := net.SplitHostPort(address); err == nil {
		if port, err := strconv.Atoi(p); err == nil && passed[port] != nil {
			l = passed[port]
			delete(passed, port)
			return l, true, nil
		}
	}
	l, err = net.Listen("tcp", address)
	return l, false, err
}

func closeAll(ls map[int]net.Listener) {
	for _, l := range ls {
		l.Close()
	}
}

func passedBy(activated bool) []any {
	if activated {
		return []any{"socket", "passed by systemd"}
	}
	return nil
}

// Check does what starting does, without serving, to report what would keep weed
// from starting with its configuration (weed check). Listening on the configured
// addresses and the control plane's socket is not tried: they are in use while weed
// runs; nor are worker cgroups set up (see startWorkers).
func (s *Server) Check() error {
	defer s.Close()
	s.checking = true
	if err := s.Initialize(); err != nil {
		return err
	}
	if s.Config.TLS {
		if _, err := s.SetupTLS(); err != nil {
			return err
		}
		if err := s.loadCertificate(); err != nil {
			return fmt.Errorf("failed to load TLS certificate: %w", err)
		}
	}
	return nil
}

// Close stops the worker processes, if any
func (s *Server) Close() {
	if s.Workers != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.Workers.Close(ctx)
	}
}

// LogStartupInfo logs what the configuration enables
func (s *Server) LogStartupInfo() {
	c := s.Config
	var methods []string
	for _, m := range []struct {
		name    string
		enabled bool
	}{
		{"x509", c.X509Auth}, {"tokens", c.TokenIssuers != ""},
		{"macaroons", c.MacaroonAuth}, {"basic", c.BasicAuth}, {"anonymous", c.Anonymous},
	} {
		if m.enabled {
			methods = append(methods, m.name)
		}
	}
	v := version.Current()
	slog.Info("starting weed", "version", v.Version, "commit", v.Revision, "commit_time", v.Time, "modified", v.Modified,
		"build", v.Build, "go", v.Go, "platform", v.Platform, "pid", os.Getpid(), "executable", executablePath,
		"dir", c.Directory, "tls", c.TLS, "authentication", strings.Join(methods, ","), "tpc", c.TPC,
		"reload_interval", c.ReloadInterval)
	s.run.mu.Lock()
	src, loaded := s.run.source, s.run.config
	s.run.mu.Unlock()
	slog.Info("configuration", "file", src.Path, "sha256", src.SHA256, "config", loaded)
	if c.X509Auth {
		slog.Info("X.509 authentication", "ca", c.CACert, "gridmap", c.GridmapFile, "crl_path", c.CRLPath, "crl_mode", c.CRLMode)
		if c.CRLPath == "" {
			slog.Warn("no CRLs (x509.crl_path): revoked certificates are accepted")
		}
	}
	for _, iss := range s.AuthStore.Credentials().TokenIssuers {
		slog.Info("token issuer", "issuer", iss.Issuer, "base_path", iss.BasePath, "audiences", append(slices.Clone(iss.Audiences), auth.AudienceAny))
	}
	if c.OIDCAuth {
		slog.Info("OIDC login page for tokens", "issuer", c.OIDCIssuer, "client_id", c.OIDCClientID, "redirect_url", c.OIDCRedirectURL,
			"scopes", strings.Join(c.OIDCScopes, " "), "audience", c.OIDCAudience)
	}
	if c.MacaroonAuth {
		slog.Info("macaroons", "location", c.MacaroonLocation, "max_validity", c.MacaroonMaxValidity)
	}
	if c.BasicAuth {
		slog.Info("Basic authentication", "htpasswd", c.HtpasswdFile, "app_tokens", c.AppTokensFile)
	}
	if c.TPC {
		slog.Info("third-party copy", "max_transfers", c.TPCMaxTransfers, "allow_http", c.TPCAllowHTTP,
			"allow_local", c.TPCAllowLocal, "allow_private", c.TPCAllowPrivate)
	}
	if c.Anonymous {
		slog.Warn("requests without credentials are served, read-write, as nobody (server.anonymous)", "address", c.Address)
	}
	if !c.TLS && (c.BasicAuth || c.MacaroonAuth || c.OIDCAuth || c.TokenIssuers != "") {
		slog.Warn("TLS is disabled: passwords and tokens are sent in clear text")
	}
}
