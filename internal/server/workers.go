package server

import (
	"context"
	"log"
	"net/http"

	"github.com/labkode/weed/internal/auth"
	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/davreq"
	"github.com/labkode/weed/internal/handlers"
	"github.com/labkode/weed/internal/worker"
	"github.com/labkode/weed/internal/x509utils"
)

// With -unix-users, WebDAV requests are served by a worker process per Unix account
// (see internal/worker): this process authenticates them and forwards them

// startWorkers prepares the workers, and starts one to check that they can start
func (s *Server) startWorkers() error {
	pool, err := worker.New(worker.Options{
		Config:       workerConfig(s.Config),
		IdleTimeout:  s.Config.WorkerIdleTimeout,
		MaxWorkers:   s.Config.MaxWorkers,
		Cgroups:      s.Config.WorkerCgroups,
		CgroupLimits: s.Config.WorkerCgroupLimits,
	})
	if err != nil {
		return err
	}
	if err := pool.Check(); err != nil {
		pool.Close(context.Background())
		return err
	}
	s.Workers = pool
	log.Printf("[WORKER] Files are accessed by a worker process per Unix account")
	return nil
}

// workerConfig is the configuration that workers serve with: what serving files
// needs, and no credentials
func workerConfig(c *config.Config) config.Config {
	return config.Config{
		Directory:         c.Directory,
		UnixUsers:         true,
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
// which weed -unix-users starts: it serves the requests forwarded to it, as the
// account, until the front process stops it
func RunWorker() error {
	log.SetFlags(0) // the front process adds the time and which worker it is
	c, err := worker.Attach()
	if err != nil {
		return err
	}
	cfg := c.Settings.Config
	h := handlers.NewWebDAVHandler(cfg.Directory, &cfg, nil)
	if cfg.TPC {
		if h.TPC, err = newTPCEngine(&cfg); err != nil {
			return c.Fail(err)
		}
	}
	return c.Serve(h, func() {
		if h.TPC != nil && cfg.TPCCAPath != "" {
			if pool, err := x509utils.SystemPoolWith(cfg.TPCCAPath); err != nil {
				log.Printf("[RELOAD] Cannot read TPC CA certificates, keeping the previous ones: %v", err)
			} else {
				h.TPC.SetRootCAs(pool)
			}
		}
	})
}
