package worker

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/labkode/weed/internal/fsuser"
	"golang.org/x/sys/unix"
)

// cgroupRoot is where the cgroup v2 hierarchy is mounted
const cgroupRoot = "/sys/fs/cgroup"

// cgroups gives each worker a cgroup of its own below weed's (cgroup v2): systemd
// shows them (systemd-cgls, systemd-cgtop), the kernel accounts for the CPU, memory,
// I/O and processes of each, and limits can apply to each
type cgroups struct {
	base   string // weed's cgroup
	limits [][2]string
}

// controllers are enabled for the workers' cgroups when weed's cgroup has them
var controllers = []string{"cpu", "io", "memory", "pids"}

func newCgroups(limits []string) (*cgroups, error) {
	c := &cgroups{}
	for _, l := range limits {
		file, value, ok := strings.Cut(l, "=") // checked by config.Validate
		if !ok {
			return nil, fmt.Errorf("invalid cgroup limit %q: want file=value, e.g. memory.max=4G", l)
		}
		c.limits = append(c.limits, [2]string{file, value})
	}

	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return nil, err
	}
	var path string
	for _, line := range strings.Split(string(data), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			path = p
		}
	}
	if path == "" {
		return nil, errors.New("worker cgroups need the cgroup v2 hierarchy")
	}
	c.base = filepath.Join(cgroupRoot, path)

	// Once controllers are enabled below a cgroup, it may have no processes of its
	// own, so weed moves into a cgroup next to those of the workers
	hint := " (the cgroup must be delegated to weed, e.g. with systemd's Delegate=yes)"
	main := filepath.Join(c.base, "main")
	if err := os.Mkdir(main, 0755); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("cannot create cgroups in %s: %w%s", c.base, err, hint)
	}
	if err := os.WriteFile(filepath.Join(main, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
		return nil, fmt.Errorf("cannot move weed to %s: %w%s", main, err, hint)
	}
	available, err := os.ReadFile(filepath.Join(c.base, "cgroup.controllers"))
	if err != nil {
		return nil, err
	}
	var enable []string
	for _, ctrl := range strings.Fields(string(available)) {
		for _, want := range controllers {
			if ctrl == want {
				enable = append(enable, "+"+ctrl)
			}
		}
	}
	if len(enable) > 0 {
		if err := os.WriteFile(filepath.Join(c.base, "cgroup.subtree_control"), []byte(strings.Join(enable, " ")), 0); err != nil {
			return nil, fmt.Errorf("cannot enable the %s controllers in %s: %w%s", strings.Join(enable, " "), c.base, err, hint)
		}
	}
	return c, nil
}

// safeName matches account names that can name a cgroup
var safeName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,200}$`)

// dir is the cgroup of the workers of u
func (c *cgroups) dir(u *fsuser.User) string {
	name := u.Name
	if !safeName.MatchString(name) {
		name = "uid" + strconv.Itoa(u.UID)
	}
	return filepath.Join(c.base, "worker-"+name)
}

// prepare creates the cgroup of a worker of u, applies the limits, and returns a file
// descriptor for starting the worker in it
func (c *cgroups) prepare(u *fsuser.User) (int, error) {
	dir := c.dir(u)
	if err := os.Mkdir(dir, 0755); err != nil && !errors.Is(err, fs.ErrExist) {
		return -1, err
	}
	for _, l := range c.limits {
		if err := os.WriteFile(filepath.Join(dir, l[0]), []byte(l[1]), 0); err != nil {
			return -1, fmt.Errorf("cannot set %s=%s in %s: %w", l[0], l[1], dir, err)
		}
	}
	return unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
}

// remove removes the cgroup of u's workers, unless another worker of u is in it
func (c *cgroups) remove(u *fsuser.User) {
	os.Remove(c.dir(u))
}
