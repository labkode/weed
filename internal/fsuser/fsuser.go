// Package fsuser describes the local Unix accounts that identities are mapped to,
// whose files are then accessed by a worker process running as the account (see
// internal/worker).
package fsuser

import (
	"fmt"
	"log/slog"
	"os/user"
	"strconv"
)

// User is a local account
type User struct {
	Name string
	UID  int
	GID  int
	// Groups are all the groups the account belongs to, including GID
	Groups []int
}

func (u *User) String() string {
	return fmt.Sprintf("%s (uid %d, gid %d, groups %v)", u.Name, u.UID, u.GID, u.Groups)
}

// LogValue describes the account in log records
func (u *User) LogValue() slog.Value {
	return slog.GroupValue(slog.String("name", u.Name), slog.Int("uid", u.UID), slog.Int("gid", u.GID), slog.Any("groups", u.Groups))
}

// Lookup finds a local account by name. The superuser is refused: acting as root
// would bypass every permission check.
func Lookup(name string) (*User, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return nil, fmt.Errorf("account %s: uid %q: %w", name, u.Uid, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return nil, fmt.Errorf("account %s: gid %q: %w", name, u.Gid, err)
	}
	if uid == 0 {
		return nil, fmt.Errorf("account %s is the superuser", name)
	}
	ids, err := u.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("groups of account %s: %w", name, err)
	}
	groups := []int{gid}
	for _, id := range ids {
		g, err := strconv.Atoi(id)
		if err != nil {
			return nil, fmt.Errorf("account %s: gid %q: %w", name, id, err)
		}
		if g != gid {
			groups = append(groups, g)
		}
	}
	return &User{Name: name, UID: uid, GID: gid, Groups: groups}, nil
}
