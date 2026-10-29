package server

import (
	"fmt"
	"log/slog"

	"github.com/labkode/weed/internal/fsuser"
	"github.com/labkode/weed/internal/limits"
)

// What each account is allowed: the limits of its workers' cgroup, its network
// rates and its share of the total ones (see internal/limits)

// limitsConfigured reports whether network rates may apply: without them, or a limits
// file that could set them on reload, nothing is paced
func (s *Server) limitsConfigured() bool {
	c := s.Config
	return c.LimitsFile != "" || c.EgressRate != "" || c.IngressRate != "" || c.AccountEgressRate != "" || c.AccountIngressRate != ""
}

// loadLimits reads the limits file (unix_users.limits) and applies the limits. After
// startup, a file that cannot be read leaves the previous rules: complete is false.
func (s *Server) loadLimits() (complete bool, err error) {
	prev := s.limits.Load()
	c := s.Config
	rate := func(r string) int64 {
		n, _ := limits.ParseRate(r) // checked by config.Validate
		return n
	}
	l := &limits.Limits{
		EgressRate: rate(c.EgressRate), IngressRate: rate(c.IngressRate),
		Default: limits.Account{Cgroup: c.WorkerCgroupLimits, EgressRate: rate(c.AccountEgressRate),
			IngressRate: rate(c.AccountIngressRate), Weight: limits.DefaultWeight},
	}
	complete = true
	if c.LimitsFile != "" {
		rules, err := limits.Load(c.LimitsFile)
		switch {
		case err == nil:
			l.Rules = rules
			slog.Info("loaded limits file", "file", c.LimitsFile, "rules", len(rules))
		case prev == nil:
			return false, fmt.Errorf("failed to load the limits file (unix_users.limits): %w", err)
		default:
			slog.Warn("cannot read limits file, keeping the previous rules", "file", c.LimitsFile, "rules", len(prev.Rules), "error", err)
			l.Rules = prev.Rules
			complete = false
		}
	}
	if prev != nil && l.HasCgroupLimits() && !s.cgroups {
		slog.Warn("the limits file sets cgroup limits, which need cgroups: weed sets them up at startup, when its configuration or limits file asks for them; restart weed",
			"file", c.LimitsFile)
	}
	s.limits.Store(l)
	if s.shaper != nil {
		s.shaper.SetLimits(l)
	}
	return complete, nil
}

// cgroupLimits are those of u's cgroup
func (s *Server) cgroupLimits(u *fsuser.User) []string {
	return s.limits.Load().For(u).Cgroup
}
