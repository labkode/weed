package limits

import (
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/labkode/weed/internal/fsuser"
)

func TestParseRate(t *testing.T) {
	for s, want := range map[string]int64{
		"":          0,
		"max":       0,
		"100MB/s":   100e6,
		"100MB":     100e6,
		"10Gbit/s":  10e9 / 8,
		"1GiB/s":    1 << 30,
		"500kB/s":   500e3,
		"500KB/s":   500e3,
		"2.5 MiB/s": 5 << 19,
		"800bit/s":  100,
		"1TB/s":     1e12,
	} {
		if got, err := ParseRate(s); err != nil || got != want {
			t.Errorf("ParseRate(%q) = %d, %v; want %d", s, got, err, want)
		}
	}
	for _, s := range []string{"100", "100M", "100 MB / s", "-1MB/s", "1mB/s", "0B/s", "1bit/s", "fast"} {
		if _, err := ParseRate(s); err == nil {
			t.Errorf("ParseRate(%q) accepted", s)
		}
	}
}

// A group of the test's own user, which the rules can name
func ownGroup(t *testing.T) (*fsuser.User, string) {
	t.Helper()
	cur, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	g, err := user.LookupGroupId(cur.Gid)
	if err != nil {
		t.Skip(err)
	}
	gid, _ := strconv.Atoi(cur.Gid)
	return &fsuser.User{Name: "alice", UID: 6001, GID: gid, Groups: []int{gid}}, g.Name
}

func TestFor(t *testing.T) {
	alice, group := ownGroup(t)
	path := filepath.Join(t.TempDir(), "limits.json")
	os.WriteFile(path, []byte(`[
		{"group": "`+group+`", "cgroup_limits": ["memory.max=32G", "cpu.weight=400"], "egress_rate": "2GB/s", "weight": 400},
		{"user": "alice", "cgroup_limits": ["memory.max=2G", "io.max=8:16 wbps=1000"], "ingress_rate": "100MB/s"},
		{"user": "alice", "egress_rate": "1GB/s", "ingress_rate": "1MB/s"},
		{"user": "bob", "weight": 50}
	]`), 0644)
	rules, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	l := &Limits{Default: Account{Cgroup: []string{"pids.max=5000", "memory.max=8G"}, EgressRate: 10, IngressRate: 20, Weight: DefaultWeight}, Rules: rules}

	// The user's rules before the group's, the first that sets a setting winning
	want := Account{
		Cgroup:     []string{"pids.max=5000", "memory.max=2G", "io.max=8:16 wbps=1000", "cpu.weight=400"},
		EgressRate: 1e9, IngressRate: 100e6, Weight: 400,
	}
	if got := l.For(alice); !reflect.DeepEqual(got, want) {
		t.Errorf("alice: %+v, want %+v", got, want)
	}
	carol := &fsuser.User{Name: "carol", GID: alice.GID, Groups: alice.Groups}
	want = Account{Cgroup: []string{"pids.max=5000", "memory.max=32G", "cpu.weight=400"}, EgressRate: 2e9, IngressRate: 20, Weight: 400}
	if got := l.For(carol); !reflect.DeepEqual(got, want) {
		t.Errorf("carol, of the group: %+v, want %+v", got, want)
	}
	bob := &fsuser.User{Name: "bob", GID: -2, Groups: []int{-2}}
	want = Account{Cgroup: []string{"pids.max=5000", "memory.max=8G"}, EgressRate: 10, IngressRate: 20, Weight: 50}
	if got := l.For(bob); !reflect.DeepEqual(got, want) {
		t.Errorf("bob: %+v, want %+v", got, want)
	}
	if !l.HasCgroupLimits() {
		t.Error("HasCgroupLimits")
	}

	// "max" lifts a limit that a group or the defaults set
	os.WriteFile(path, []byte(`[{"user": "bob", "egress_rate": "max"}]`), 0644)
	rules, _ = Load(path)
	l.Rules = rules
	if got := l.For(bob); got.EgressRate != 0 || got.IngressRate != 20 {
		t.Errorf(`bob with "max": %+v`, got)
	}
}

func TestLoadRefuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "limits.json")
	for content, want := range map[string]string{
		`[{"user": "alice", "egress": "1GB/s"}]`:                   "unknown field",
		`[{"egress_rate": "1GB/s"}]`:                               `for a "user" or for a "group"`,
		`[{"user": "a", "group": "b"}]`:                            `for a "user" or for a "group"`,
		`[{"group": "no-such-group-weed"}]`:                        "no-such-group-weed",
		`[{"user": "alice", "egress_rate": "fast"}]`:               "egress_rate",
		`[{"user": "alice", "weight": 20000}]`:                     "weight",
		`[{"user": "alice", "cgroup_limits": ["cgroup.procs=1"]}]`: "invalid cgroup limit",
		`[{"user": "alice", "cgroup_limits": ["memory.max"]}]`:     "invalid cgroup limit",
		`{"user": "alice"}`:                                        "cannot unmarshal",
	} {
		os.WriteFile(path, []byte(content), 0644)
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", content, err, want)
		}
	}
}
