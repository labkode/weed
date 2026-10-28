package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/metrics"
	"github.com/labkode/weed/internal/systemd"
	"github.com/labkode/weed/internal/version"
	"github.com/labkode/weed/internal/worker"
)

// What weed reports about itself, so that its administrators know what runs: which
// build (version.Current), since when, with which configuration, and whether a
// restart would run something else, because the configuration file or the
// executable has changed since weed started. It is in the log at startup and when
// it changes, in the metrics, in systemd's status, and at /status.

// startTime is when weed started
var startTime = time.Now()

// executablePath is weed's executable, which a restart runs
var executablePath, _ = os.Executable()

// restartCheckInterval is how often weed checks whether a restart is pending
const restartCheckInterval = time.Minute

// Restart reasons
const (
	restartConfig = "config" // the configuration file has changed
	restartBinary = "binary" // the executable has
)

// running is what weed runs, compared to what a restart would run
type running struct {
	source     config.Source
	config     *config.Config // as loaded, before the server used it
	executable string

	mu      sync.Mutex
	pending map[string]pendingRestart // by reason
	stamps  map[string]os.FileInfo    // of the files when they were last examined

	lastReload        time.Time // zero until the first reload
	lastReloadSuccess time.Time
	lastReloadOK      bool
}

// pendingRestart says why a restart would run something else ("" if it would not)
type pendingRestart struct {
	level slog.Level
	why   string
}

func newRunning(cfg *config.Config) running {
	return running{
		config:            cfg,
		executable:        executablePath,
		pending:           make(map[string]pendingRestart),
		stamps:            make(map[string]os.FileInfo),
		lastReloadSuccess: startTime, // the credentials loaded at startup
		lastReloadOK:      true,
	}
}

// SetSource records where the configuration comes from, so that weed notices when
// that file changes. It takes a copy of the configuration as it is now.
func (s *Server) SetSource(src config.Source) {
	cfg := *s.Config
	s.run.mu.Lock()
	defer s.run.mu.Unlock()
	s.run.source, s.run.config = src, &cfg
}

// checkRestart finds out whether a restart would run something else: the
// configuration file as it is now, or the executable on disk. Each change is logged
// once, and goes to systemd's status.
func (s *Server) checkRestart() {
	r := &s.run
	r.mu.Lock()
	changed := false
	if r.source.Path != "" {
		changed = r.check(restartConfig, r.source.Path, r.configChange) || changed
	}
	if r.executable != "" {
		changed = r.check(restartBinary, r.executable, r.binaryChange) || changed
	}
	r.mu.Unlock()
	if changed {
		systemd.Status(s.StatusLine())
	}
}

// check examines the file of a reason again if it has changed since the last time,
// and reports whether what is pending for that reason changed
func (r *running) check(reason, path string, examine func() pendingRestart) bool {
	fi, err := os.Stat(path)
	if prev := r.stamps[reason]; err == nil && prev != nil &&
		os.SameFile(prev, fi) && prev.ModTime().Equal(fi.ModTime()) && prev.Size() == fi.Size() {
		return false
	}
	r.stamps[reason] = fi // nil if it cannot be stat'ed: examined every time
	p := examine()
	if p == r.pending[reason] {
		return false
	}
	if p.why == "" {
		delete(r.pending, reason)
		slog.Info("restart no longer pending", "reason", reason)
	} else {
		r.pending[reason] = p
		slog.Log(context.Background(), p.level, "restart pending: "+p.why, "reason", reason)
	}
	return true
}

func (r *running) configChange() pendingRestart {
	c, src, err := config.Read(r.source.Path)
	if err == nil {
		err = c.Validate()
	}
	switch {
	case err != nil:
		return pendingRestart{slog.LevelError, "the configuration file has changed, and weed would not start with it: " + err.Error()}
	case src.SHA256 == r.source.SHA256:
		return pendingRestart{}
	}
	if keys := config.Changed(r.config, c); len(keys) > 0 {
		return pendingRestart{slog.LevelWarn, "the configuration file has changed: " + strings.Join(keys, ", ")}
	}
	return pendingRestart{} // comments or layout
}

func (r *running) binaryChange() pendingRestart {
	i, err := version.OfFile(r.executable)
	switch {
	case err != nil:
		return pendingRestart{slog.LevelError, fmt.Sprintf("weed's executable %s cannot be read, and weed would not restart: %v", r.executable, err)}
	case i.Build == version.Current().Build:
		return pendingRestart{}
	}
	return pendingRestart{slog.LevelWarn, fmt.Sprintf("weed's executable %s is now %s, build %s", r.executable, i, i.Build)}
}

// watchRestart checks every restartCheckInterval whether a restart is pending
func (s *Server) watchRestart(ctx context.Context) {
	ticker := time.NewTicker(restartCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.checkRestart()
		case <-ctx.Done():
			return
		}
	}
}

// reloaded records the outcome of a reload
func (s *Server) reloaded(complete bool) {
	now := time.Now()
	s.run.mu.Lock()
	s.run.lastReload, s.run.lastReloadOK = now, complete
	if complete {
		s.run.lastReloadSuccess = now
	}
	s.run.mu.Unlock()
	s.checkRestart()
}

// StatusLine summarizes what runs, for systemctl status
func (s *Server) StatusLine() string {
	s.run.mu.Lock()
	defer s.run.mu.Unlock()
	line := fmt.Sprintf("Serving since %s: weed %s", startTime.UTC().Format(time.DateTime+" MST"), version.Current().Version)
	if s.run.source.Path != "" {
		line += fmt.Sprintf(", %s (sha256 %.12s)", s.run.source.Path, s.run.source.SHA256)
	}
	for _, reason := range []string{restartConfig, restartBinary} {
		if p, ok := s.run.pending[reason]; ok {
			line += "; restart pending: " + p.why
		}
	}
	return line
}

// writeStatusGauges writes the metrics about what runs
func (s *Server) writeStatusGauges(w io.Writer) {
	s.checkRestart()
	s.run.mu.Lock()
	defer s.run.mu.Unlock()
	metrics.WriteGauge(w, "process_start_time_seconds", "Start time of the process since unix epoch in seconds.",
		float64(startTime.UnixMilli())/1000, nil, nil)
	i := version.Current()
	metrics.WriteGauge(w, "weed_build_info", "The build of weed that runs: version, commit, whether it had uncommitted changes, Go version and build ID.", 1,
		[]string{"version", "revision", "modified", "goversion", "build"}, []string{i.Version, i.Revision, fmt.Sprint(i.Modified), i.Go, i.Build})
	metrics.WriteGauge(w, "weed_config_info", "The configuration file weed runs with, and the SHA-256 of its content when weed started (empty without a file).", 1,
		[]string{"file", "sha256"}, []string{s.run.source.Path, s.run.source.SHA256})
	pending := func(reason string) float64 {
		if _, ok := s.run.pending[reason]; ok {
			return 1
		}
		return 0
	}
	metrics.WriteGaugeSamples(w, "weed_restart_pending", "1 if a restart would run something else than what runs: the configuration file (config) or the executable (binary) has changed since weed started.",
		[]string{"reason"}, [][]string{{restartConfig}, {restartBinary}}, []float64{pending(restartConfig), pending(restartBinary)})
	metrics.WriteGauge(w, "weed_reload_last_success_timestamp_seconds", "When credentials were last reloaded completely (or loaded at startup).",
		float64(s.run.lastReloadSuccess.UnixMilli())/1000, nil, nil)
	ok := 0.0
	if s.run.lastReloadOK {
		ok = 1
	}
	metrics.WriteGauge(w, "weed_reload_last_successful", "1 if the last reload read every credential file, CA and certificate (0: some kept their previous contents).", ok, nil, nil)
}

// status is what /status reports
type status struct {
	Version        version.Info      `json:"version"`
	PID            int               `json:"pid"`
	Started        time.Time         `json:"started"`
	Uptime         string            `json:"uptime"`
	Config         statusConfig      `json:"config"`
	Reload         statusReload      `json:"reload"`
	RestartPending map[string]string `json:"restart_pending"` // why, by reason
	Workers        []worker.Info     `json:"workers"`         // with unix_users
}

type statusConfig struct {
	File     string                    `json:"file"`   // "" without one
	SHA256   string                    `json:"sha256"` // of its content when weed started
	Settings map[string]map[string]any `json:"settings"`
}

type statusReload struct {
	Last        time.Time `json:"last,omitzero"` // none since startup if absent
	LastSuccess time.Time `json:"last_success"`
	Successful  bool      `json:"successful"` // the last reload read everything
}

// statusHandler serves /status: what runs, as JSON
func (s *Server) statusHandler(w http.ResponseWriter, r *http.Request) {
	s.checkRestart()
	s.run.mu.Lock()
	cfg := s.run.config
	st := status{
		Version:        version.Current(),
		PID:            os.Getpid(),
		Started:        startTime,
		Uptime:         time.Since(startTime).Round(time.Second).String(),
		Config:         statusConfig{File: s.run.source.Path, SHA256: s.run.source.SHA256, Settings: make(map[string]map[string]any)},
		Reload:         statusReload{Last: s.run.lastReload, LastSuccess: s.run.lastReloadSuccess, Successful: s.run.lastReloadOK},
		RestartPending: make(map[string]string),
		Workers:        []worker.Info{},
	}
	for reason, p := range s.run.pending {
		st.RestartPending[reason] = p.why
	}
	s.run.mu.Unlock()
	for _, set := range cfg.Settings() {
		if st.Config.Settings[set.Section] == nil {
			st.Config.Settings[set.Section] = make(map[string]any)
		}
		st.Config.Settings[set.Section][set.Key] = set.Value
	}
	if s.Workers != nil {
		st.Workers = s.Workers.Workers()
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(st)
}
