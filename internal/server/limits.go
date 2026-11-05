package server

import (
	"fmt"
	"log/slog"

	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/fsuser"
	"github.com/labkode/weed/internal/limits"
)

// What each account is allowed: the limits of its workers' cgroup, which the kernel
// applies (see internal/limits)

// readLimits are the limits of c: the cgroup limits of its configuration, and the
// rules of its limits file (unix_users.limits), which weed and the starter of its
// workers read
func readLimits(c *config.Config) (*limits.Limits, error) {
	l := &limits.Limits{Default: limits.Account{Cgroup: c.WorkerCgroupLimits}}
	if c.LimitsFile != "" {
		rules, err := limits.Load(c.LimitsFile)
		if err != nil {
			return l, fmt.Errorf("failed to load the limits file (unix_users.limits): %w", err)
		}
		l.Rules = rules
	}
	return l, nil
}

// loadLimits reads the limits file (unix_users.limits). After startup, a file that
// cannot be read leaves the previous rules: complete is false.
func (s *Server) loadLimits() (complete bool, err error) {
	prev := s.limits.Load()
	c := s.Config
	l, err := readLimits(c)
	complete = true
	switch {
	case err == nil && c.LimitsFile != "":
		slog.Info("loaded limits file", "file", c.LimitsFile, "rules", len(l.Rules))
	case err == nil:
	case prev == nil:
		return false, err
	default:
		slog.Warn("cannot read limits file, keeping the previous rules", "file", c.LimitsFile, "rules", len(prev.Rules), "error", err)
		l.Rules = prev.Rules
		complete = false
	}
	if prev != nil && l.HasCgroupLimits() && !s.cgroups {
		slog.Warn("the limits file sets cgroup limits, which need cgroups: weed sets them up at startup, when its configuration or limits file asks for them; restart weed",
			"file", c.LimitsFile)
	}
	s.limits.Store(l)
	return complete, nil
}

// cgroupLimits are those of u's cgroup
func (s *Server) cgroupLimits(u *fsuser.User) []string {
	return s.limits.Load().For(u).Cgroup
}
