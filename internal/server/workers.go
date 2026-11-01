package server

import (
	"cmp"
	"context"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/labkode/weed/internal/auth"
	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/davreq"
	"github.com/labkode/weed/internal/handlers"
	"github.com/labkode/weed/internal/limits"
	"github.com/labkode/weed/internal/logger"
	"github.com/labkode/weed/internal/worker"
	"github.com/labkode/weed/internal/x509utils"
)

// WebDAV requests are served by a worker process per Unix account (see
// internal/worker): this process authenticates them and forwards them

// startWorkers prepares the workers, and starts one to check that they can start
func (s *Server) startWorkers() error {
	// Workers run in /, not in this process's working directory
	dir, err := filepath.Abs(s.Config.Directory)
	if err != nil {
		return err
	}
	if _, err := s.loadLimits(); err != nil {
		return err
	}
	if s.limitsConfigured() {
		s.shaper = limits.NewShaper(s.limits.Load())
	}
	s.cgroups = s.Config.WorkerCgroups || len(s.Config.WorkerCgroupLimits) > 0 || s.limits.Load().HasCgroupLimits()
	opts := worker.Options{
		Config:       workerConfig(s.Config, dir),
		IdleTimeout:  s.Config.WorkerIdleTimeout,
		MaxWorkers:   s.Config.MaxWorkers,
		Cgroups:      s.cgroups,
		CgroupLimits: s.cgroupLimits,
		Shaper:       s.shaper,
		Landlock:     s.Config.WorkerLandlock,
		Refused: func(account string) bool {
			_, banned := s.Bans.Get(account)
			return banned
		},
	}
	if s.checking {
		// Setting cgroups up moves this process and enables controllers in its cgroup,
		// which would then refuse weed (systemd: ExecStartPre) or the shell weed check
		// runs in
		opts.Cgroups = false
	}
	pool, err := worker.New(opts)
	if err != nil {
		return err
	}
	if err := pool.Check(); err != nil {
		pool.Close(context.Background())
		return err // which says when weed lacks the privileges for it
	}
	s.Workers = pool
	slog.Info("files are accessed by a worker process per Unix account",
		"idle_timeout", s.Config.WorkerIdleTimeout, "max_workers", s.Config.MaxWorkers, "max_requests", s.Config.WorkerMaxRequests, "cgroups", s.cgroups)
	if s.shaper != nil {
		c := s.Config
		slog.Info("network rates are limited", "egress_rate", cmp.Or(c.EgressRate, "max"), "ingress_rate", cmp.Or(c.IngressRate, "max"),
			"account_egress_rate", cmp.Or(c.AccountEgressRate, "max"), "account_ingress_rate", cmp.Or(c.AccountIngressRate, "max"), "limits_file", c.LimitsFile)
	}
	return nil
}

// workerConfig is the configuration that workers serve dir with: what serving files
// needs, and no credentials
func workerConfig(c *config.Config, dir string) config.Config {
	return config.Config{
		Directory:         dir,
		LogLevel:          c.LogLevel,
		WorkerMaxRequests: c.WorkerMaxRequests,
		TPC:               c.TPC,
		TPCCAPath:         c.TPCCAPath,
		TPCAllowHTTP:      c.TPCAllowHTTP,
		TPCAllowLocal:     c.TPCAllowLocal,
		TPCAllowPrivate:   c.TPCAllowPrivate,
		TPCMaxTransfers:   c.TPCMaxTransfers,
		TPCMarkerInterval: c.TPCMarkerInterval,
		TPCStallTimeout:   c.TPCStallTimeout,
	}
}

// webdavHandler serves the WebDAV namespace, after authentication
func (s *Server) webdavHandler() http.Handler {
	if s.Workers == nil {
		return s.Handler
	}
	return http.HandlerFunc(s.forward)
}

// forward hands a request to the worker of its Unix account
func (s *Server) forward(w http.ResponseWriter, r *http.Request) {
	if davreq.IsMacaroonRequest(r) {
		// Minting needs the macaroon secret, which workers do not have, and no files
		s.Handler.ServeHTTP(w, r)
		return
	}
	info, ok := auth.GetAuthInfoFromContext(r.Context())
	if !ok || info.Unix == nil {
		http.Error(w, "No Unix account for this identity", http.StatusForbidden)
		return
	}
	// The limit on concurrent third-party copies is for all accounts together
	if r.Method == "COPY" && s.Handler.TPC != nil {
		if t, err := davreq.ParseTarget(r); err == nil && t.Kind != davreq.CopyLocal {
			release, ok := s.Handler.TPC.Reserve(w)
			if !ok {
				return
			}
			defer release()
		}
	}
	s.Workers.ServeHTTP(w, r, info.Unix)
}

// RunWorker is the main function of worker processes ("weed worker <account>"),
// which weed starts: it serves the requests forwarded to it, as the account, until
// the front process stops it
func RunWorker() error {
	// JSON records, which the front process logs as the worker's
	level := new(slog.LevelVar)
	slog.SetDefault(slog.New(logger.NewHandler(os.Stderr, logger.FormatJSON, level)))
	c, err := worker.Attach()
	if err != nil {
		return err
	}
	cfg := c.Settings.Config
	if l, err := cfg.Level(); err == nil {
		level.Set(l)
	}
	h := handlers.NewWebDAVHandler(cfg.Directory, &cfg, nil)
	if cfg.TPC {
		if h.TPC, err = newTPCEngine(&cfg, c.Payer()); err != nil {
			return c.Fail(err)
		}
	}
	return c.Serve(h, func() {
		if h.TPC != nil && cfg.TPCCAPath != "" {
			if pool, err := x509utils.SystemPoolWith(cfg.TPCCAPath); err != nil {
				slog.Warn("cannot read the CA certificates of TPC endpoints, keeping the previous ones", "path", cfg.TPCCAPath, "error", err)
			} else {
				h.TPC.SetRootCAs(pool)
			}
		}
	})
}
