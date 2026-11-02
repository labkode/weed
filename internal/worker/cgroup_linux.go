package worker

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/labkode/weed/internal/fsuser"
	"golang.org/x/sys/unix"
)

// cgroupRoot is where the cgroup v2 hierarchy is mounted
const cgroupRoot = "/sys/fs/cgroup"

// cgroups gives the workers of each account a cgroup of their own below weed's
// (cgroup v2): systemd shows them (systemd-cgls, systemd-cgtop), the kernel accounts
// for the CPU, memory, I/O and processes of each, and limits can apply to each
type cgroups struct {
	base string // weed's cgroup

	mu      sync.Mutex
	written map[string]map[string]string // by cgroup: the limits written, file -> value
}

// controllers are enabled for the workers' cgroups when weed's cgroup has them
var controllers = []string{"cpu", "io", "memory", "pids"}

// Cgroup is the directory of this process's cgroup, in the cgroup v2 hierarchy ("" if
// it has none)
func Cgroup() string {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			return filepath.Join(cgroupRoot, p)
		}
	}
	return ""
}

func newCgroups() (*cgroups, error) {
	c := &cgroups{written: make(map[string]map[string]string), base: Cgroup()}
	if c.base == "" {
		return nil, errors.New("worker cgroups need the cgroup v2 hierarchy")
	}

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

// prepare creates the cgroup of a worker of u, writes the limits (file=value) to it,
// and returns a file descriptor for starting the worker in it
func (c *cgroups) prepare(u *fsuser.User, limits []string) (int, error) {
	if err := c.apply(u, limits); err != nil {
		return -1, err
	}
	return unix.Open(c.dir(u), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
}

// apply writes the limits (file=value) to the cgroup of u's workers, which it creates
// if need be. A limit written before and no longer among them stays: the kernel has
// no way back to the value it had, which depends on the file (memory.max=max,
// cpu.weight=100, ...). It is logged, once.
func (c *cgroups) apply(u *fsuser.User, limits []string) error {
	dir := c.dir(u)
	c.mu.Lock() // also against remove
	defer c.mu.Unlock()
	if err := os.Mkdir(dir, 0755); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	written := maps.Clone(c.written[dir])
	if written == nil {
		written = make(map[string]string)
	}
	c.written[dir] = written
	configured := make(map[string]bool)
	for _, l := range limits {
		file, value, _ := strings.Cut(l, "=") // checked by limits.CheckCgroupLimit
		if err := os.WriteFile(filepath.Join(dir, file), []byte(value), 0); err != nil {
			return fmt.Errorf("cannot set %s=%s in %s: %w", file, value, dir, err)
		}
		written[file] = value
		configured[file] = true
	}
	for file, value := range written {
		if !configured[file] {
			slog.Warn("a cgroup limit that is no longer configured stays until the account's workers have all exited; to lift it now, set it to the value without limit, e.g. memory.max=max",
				"account", u.Name, "cgroup", dir, "limit", file+"="+value)
			delete(written, file)
		}
	}
	return nil
}

// remove removes the cgroup of u's workers, unless another worker of u is in it
func (c *cgroups) remove(u *fsuser.User) {
	dir := c.dir(u)
	c.mu.Lock()
	defer c.mu.Unlock()
	if os.Remove(dir) == nil {
		delete(c.written, dir)
	}
}
