// Package limits holds what each account is allowed: the limits of its workers'
// cgroup, the network rates it may not exceed, and its share of weed's total rates.
// The configuration sets them for every account; a file of rules
// (unix_users.limits) sets them otherwise for some users and Unix groups.
package limits

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/user"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/labkode/weed/internal/fsuser"
)

// Account is what an account is allowed
type Account struct {
	// Cgroup are the file=value settings of its workers' cgroup
	Cgroup []string
	// EgressRate and IngressRate bound the bytes per second it sends and receives
	// (0: no limit)
	EgressRate, IngressRate int64
	// Weight is its share of weed's total rates against the other accounts', when
	// those rates are the bottleneck
	Weight int
}

func (a Account) rate(d Direction) int64 {
	if d == Egress {
		return a.EgressRate
	}
	return a.IngressRate
}

// DefaultWeight is the weight of accounts that nothing gives another
const DefaultWeight = 100

// MaxWeight bounds weights, which are between 1 and MaxWeight (as cgroups' cpu.weight)
const MaxWeight = 10000

// Rule is an entry of the limits file: the settings it has replace the defaults for
// the user, or for the members of the group
type Rule struct {
	User         string   `json:"user,omitempty"`
	Group        string   `json:"group,omitempty"`
	CgroupLimits []string `json:"cgroup_limits,omitempty"`
	EgressRate   string   `json:"egress_rate,omitempty"`
	IngressRate  string   `json:"ingress_rate,omitempty"`
	Weight       int      `json:"weight,omitempty"`

	gid             int // of Group
	egress, ingress int64
}

// Limits are weed's total rates, what accounts are allowed by default, and the rules
// of the limits file
type Limits struct {
	// EgressRate and IngressRate bound the bytes per second of all accounts together
	// (0: no limit)
	EgressRate, IngressRate int64
	Default                 Account
	Rules                   []Rule
}

// For returns what u is allowed. Each setting comes from the first rule for the user
// that has it, else from the first rule for one of the user's groups that has it,
// else from the defaults; cgroup limits are taken file by file in the same way.
func (l *Limits) For(u *fsuser.User) Account {
	var user, group []*Rule
	for i := range l.Rules {
		r := &l.Rules[i]
		switch {
		case r.User != "" && r.User == u.Name:
			user = append(user, r)
		case r.Group != "" && slices.Contains(u.Groups, r.gid):
			group = append(group, r)
		}
	}
	rules := append(user, group...)
	a := l.Default
	if a.Weight == 0 {
		a.Weight = DefaultWeight
	}
	a.Cgroup = cgroupFor(l.Default.Cgroup, rules)
	for _, r := range rules {
		if r.EgressRate != "" {
			a.EgressRate = r.egress
			break
		}
	}
	for _, r := range rules {
		if r.IngressRate != "" {
			a.IngressRate = r.ingress
			break
		}
	}
	for _, r := range rules {
		if r.Weight != 0 {
			a.Weight = r.Weight
			break
		}
	}
	return a
}

// HasCgroupLimits reports whether a rule sets cgroup limits
func (l *Limits) HasCgroupLimits() bool {
	for _, r := range l.Rules {
		if len(r.CgroupLimits) > 0 {
			return true
		}
	}
	return false
}

// cgroupFor merges the cgroup limits of rules over defaults, file by file: the first
// rule that sets a file wins. The defaults' files come first, in their order.
func cgroupFor(defaults []string, rules []*Rule) []string {
	value := make(map[string]string)
	var files []string
	add := func(l string) {
		file, v, _ := strings.Cut(l, "=")
		if _, ok := value[file]; !ok {
			value[file] = v
			files = append(files, file)
		}
	}
	for _, r := range rules {
		for _, l := range r.CgroupLimits {
			add(l)
		}
	}
	for _, l := range defaults {
		add(l)
	}
	var out []string
	seen := make(map[string]bool)
	for _, l := range defaults {
		file, _, _ := strings.Cut(l, "=")
		if !seen[file] {
			seen[file] = true
			out = append(out, file+"="+value[file])
		}
	}
	for _, file := range files {
		if !seen[file] {
			seen[file] = true
			out = append(out, file+"="+value[file])
		}
	}
	return out
}

// Load reads a limits file: a JSON list of rules, each for a "user" or a "group"
func Load(path string) ([]Rule, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields() // a misspelt "egress_rate" must not go unnoticed
	var rules []Rule
	if err := dec.Decode(&rules); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for i := range rules {
		if err := rules[i].resolve(); err != nil {
			return nil, fmt.Errorf("%s: rule %d: %w", path, i+1, err)
		}
	}
	return rules, nil
}

func (r *Rule) resolve() error {
	switch {
	case (r.User == "") == (r.Group == ""):
		return errors.New(`a rule is for a "user" or for a "group"`)
	case r.Group != "":
		g, err := user.LookupGroup(r.Group)
		if err != nil {
			return err
		}
		if r.gid, err = strconv.Atoi(g.Gid); err != nil {
			return fmt.Errorf("group %s: gid %q: %w", r.Group, g.Gid, err)
		}
	}
	for _, l := range r.CgroupLimits {
		if err := CheckCgroupLimit(l); err != nil {
			return err
		}
	}
	var err error
	if r.egress, err = ParseRate(r.EgressRate); err != nil {
		return fmt.Errorf("egress_rate: %w", err)
	}
	if r.ingress, err = ParseRate(r.IngressRate); err != nil {
		return fmt.Errorf("ingress_rate: %w", err)
	}
	if r.Weight != 0 {
		if err := CheckWeight(r.Weight); err != nil {
			return err
		}
	}
	return nil
}

// cgroupLimitFile is the name of a cgroup interface file that limits may be written to
var cgroupLimitFile = regexp.MustCompile(`^[a-z]+\.[a-z0-9_.]+$`)

// CheckCgroupLimit checks that l has the form file=value, for a cgroup interface
// file other than cgroup.*; the kernel checks the value when it is written
func CheckCgroupLimit(l string) error {
	if file, _, ok := strings.Cut(l, "="); !ok || !cgroupLimitFile.MatchString(file) || strings.HasPrefix(file, "cgroup.") {
		return fmt.Errorf("invalid cgroup limit %q: want file=value, e.g. memory.max=4G", l)
	}
	return nil
}

// CheckWeight checks that a weight is between 1 and MaxWeight
func CheckWeight(w int) error {
	if w < 1 || w > MaxWeight {
		return fmt.Errorf("weight %d is not between 1 and %d", w, MaxWeight)
	}
	return nil
}

// rateSyntax is a rate: a number, a unit of bytes (B) or bits (bit) with an optional
// SI (k, M, G, T) or binary (Ki, Mi, Gi, Ti) prefix, and an optional "/s"
var rateSyntax = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?) ?([kKMGT]i?)?(B|bit)(?:/s)?$`)

// ParseRate parses a rate such as "100MB/s" or "10Gbit/s" into bytes per second. ""
// and "max" are no limit (0).
func ParseRate(s string) (int64, error) {
	if s == "" || s == "max" {
		return 0, nil
	}
	m := rateSyntax.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf(`invalid rate %q: want e.g. "100MB/s", "10Gbit/s", "1GiB/s", or "max"`, s)
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid rate %q: %w", s, err)
	}
	if p := m[2]; p != "" {
		base := 1000.0
		if strings.HasSuffix(p, "i") {
			base = 1024
		}
		v *= math.Pow(base, float64(map[byte]int{'k': 1, 'K': 1, 'M': 2, 'G': 3, 'T': 4}[p[0]]))
	}
	if m[3] == "bit" {
		v /= 8
	}
	if v < 1 || v > math.MaxInt64/2 {
		return 0, fmt.Errorf("invalid rate %q: out of range", s)
	}
	return int64(v), nil
}
