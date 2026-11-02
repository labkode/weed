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
		{"group": "`+group+`", "cgroup_limits": ["memory.max=32G", "cpu.weight=400"]},
		{"user": "alice", "cgroup_limits": ["memory.max=2G", "io.max=8:16 wbps=1000"]},
		{"user": "alice", "cgroup_limits": ["memory.max=1G"]},
		{"user": "bob", "cgroup_limits": ["pids.max=100"]}
	]`), 0644)
	rules, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	l := &Limits{Default: Account{Cgroup: []string{"pids.max=5000", "memory.max=8G"}}, Rules: rules}

	// The user's rules before the group's, the first that sets a file winning
	want := Account{Cgroup: []string{"pids.max=5000", "memory.max=2G", "io.max=8:16 wbps=1000", "cpu.weight=400"}}
	if got := l.For(alice); !reflect.DeepEqual(got, want) {
		t.Errorf("alice: %+v, want %+v", got, want)
	}
	carol := &fsuser.User{Name: "carol", GID: alice.GID, Groups: alice.Groups}
	want = Account{Cgroup: []string{"pids.max=5000", "memory.max=32G", "cpu.weight=400"}}
	if got := l.For(carol); !reflect.DeepEqual(got, want) {
		t.Errorf("carol, of the group: %+v, want %+v", got, want)
	}
	bob := &fsuser.User{Name: "bob", GID: -2, Groups: []int{-2}}
	want = Account{Cgroup: []string{"pids.max=100", "memory.max=8G"}}
	if got := l.For(bob); !reflect.DeepEqual(got, want) {
		t.Errorf("bob: %+v, want %+v", got, want)
	}
	if !l.HasCgroupLimits() {
		t.Error("HasCgroupLimits")
	}
}

func TestLoadRefuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "limits.json")
	for content, want := range map[string]string{
		`[{"user": "alice", "egress_rate": "1GB/s"}]`:              "unknown field",
		`[{"cgroup_limits": ["memory.max=1G"]}]`:                   `for a "user" or for a "group"`,
		`[{"user": "a", "group": "b"}]`:                            `for a "user" or for a "group"`,
		`[{"group": "no-such-group-weed"}]`:                        "no-such-group-weed",
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
