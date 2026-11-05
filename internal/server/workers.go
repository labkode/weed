package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/labkode/weed/internal/auth"
	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/davreq"
	"github.com/labkode/weed/internal/handlers"
	"github.com/labkode/weed/internal/limits"
	"github.com/labkode/weed/internal/logger"
	"github.com/labkode/weed/internal/systemd"
	"github.com/labkode/weed/internal/worker"
	"github.com/labkode/weed/internal/x509utils"
	"golang.org/x/sys/unix"
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
	s.cgroups = wantCgroups(s.Config, s.limits.Load())
	s.lost = make(chan error, 1)
	opts := worker.Options{
		Config:       workerConfig(s.Config, dir),
		IdleTimeout:  s.Config.WorkerIdleTimeout,
		MaxWorkers:   s.Config.MaxWorkers,
		Cgroups:      s.cgroups,
		CgroupLimits: s.cgroupLimits,
		Lost: func(err error) {
			select {
			case s.lost <- err:
			default:
			}
		},
		Unmounted: func(lost bool) {
			var u *unmounted
			if lost {
				u = &unmounted{since: time.Now(), dir: dir}
			}
			s.unmounted.Store(u)
			systemd.Status(s.StatusLine())
		},
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
	} else if starter != nil {
		// weed itself, which has given up its privileges to the starter (see Confine)
		opts.Starter, opts.ConfigSHA256 = starter, s.run.source.SHA256
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
		"idle_timeout", s.Config.WorkerIdleTimeout, "max_workers", s.Config.MaxWorkers, "max_requests", s.Config.WorkerMaxRequests,
		"max_storage_calls", s.Config.WorkerMaxStorageCalls, "cgroups", s.cgroups)
	return nil
}

// wantCgroups says whether the workers of each account get a cgroup of their own: when
// the configuration asks for them, or sets cgroup limits, or the limits file does
func wantCgroups(c *config.Config, l *limits.Limits) bool {
	return c.WorkerCgroups || len(c.WorkerCgroupLimits) > 0 || l.HasCgroupLimits()
}

// workerConfig is the configuration that workers serve dir with: what serving files
// needs, and no credentials
func workerConfig(c *config.Config, dir string) config.Config {
	return config.Config{
		Directory:             dir,
		LogLevel:              c.LogLevel,
		WorkerMaxRequests:     c.WorkerMaxRequests,
		WorkerMaxStorageCalls: c.WorkerMaxStorageCalls,
		TPC:                   c.TPC,
		TPCCAPath:             c.TPCCAPath,
		TPCAllowHTTP:          c.TPCAllowHTTP,
		TPCAllowLocal:         c.TPCAllowLocal,
		TPCAllowPrivate:       c.TPCAllowPrivate,
		TPCMaxTransfers:       c.TPCMaxTransfers,
		TPCMarkerInterval:     c.TPCMarkerInterval,
		TPCStallTimeout:       c.TPCStallTimeout,
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

// ErrReported is in the errors of RunStarter that weed has logged already
var ErrReported = worker.ErrReported

// RunStarter is the main function of the starter ("weed starter <weed's arguments>"),
// which weed starts before it confines itself (see Confine and worker.Starter): it
// reads weed's configuration, and starts the workers that weed asks for, until weed
// exits
func RunStarter() error {
	// systemd stops weed and its processes with SIGTERM: the starter stops once weed
	// has, and its workers
	signal.Ignore(syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	// Nor may weed, which runs as the same account, look into it
	unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
	level := new(slog.LevelVar)
	sc, err := worker.AttachStarter(level)
	if err != nil {
		return err
	}
	cfg, src, err := config.FromArgs(os.Args[2:])
	if err == nil {
		err = cfg.Validate()
	}
	if err != nil {
		return sc.Fail(fmt.Errorf("cannot read the configuration: %w", err))
	}
	if l, err := cfg.Level(); err == nil {
		level.Set(l)
	}
	if err := worker.CheckStarter(worker.Sockets(cfg)); err != nil {
		return sc.Fail(err)
	}
	dir, err := filepath.Abs(cfg.Directory)
	if err != nil {
		return sc.Fail(err)
	}
	l := &limits.Limits{Default: limits.Account{Cgroup: cfg.WorkerCgroupLimits}}
	if cfg.LimitsFile != "" {
		if l.Rules, err = limits.Load(cfg.LimitsFile); err != nil {
			return sc.Fail(fmt.Errorf("failed to load the limits file (unix_users.limits): %w", err))
		}
	}
	// Its paths read, it keeps no storage busy, as its workers
	if err := os.Chdir("/"); err != nil {
		return sc.Fail(err)
	}
	return sc.Serve(worker.StarterOptions{Config: workerConfig(cfg, dir), Cgroups: wantCgroups(cfg, l),
		Front: sc.Front(), SHA256: src.SHA256})
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
		if h.TPC, err = newTPCEngine(&cfg); err != nil {
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
