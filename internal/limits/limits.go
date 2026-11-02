// Package limits holds the limits of the cgroup of each account's workers, which the
// kernel applies. The configuration sets them for every account; a file of rules
// (unix_users.limits) sets them otherwise for some users and Unix groups.
package limits

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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
}

// Rule is an entry of the limits file: the settings it has replace the defaults for
// the user, or for the members of the group
type Rule struct {
	User         string   `json:"user,omitempty"`
	Group        string   `json:"group,omitempty"`
	CgroupLimits []string `json:"cgroup_limits,omitempty"`

	gid int // of Group
}

// Limits are what accounts are allowed by default, and the rules of the limits file
type Limits struct {
	Default Account
	Rules   []Rule
}

// For returns what u is allowed: each cgroup limit comes from the first rule for the
// user that sets its file, else from the first rule for one of the user's groups that
// does, else from the defaults.
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
	return Account{Cgroup: cgroupFor(l.Default.Cgroup, append(user, group...))}
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
	dec.DisallowUnknownFields() // a misspelt "cgroup_limits" must not go unnoticed
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
