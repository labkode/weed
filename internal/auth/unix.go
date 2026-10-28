package auth

import (
	"fmt"
	"time"

	"github.com/labkode/weed/internal/fsuser"
)

// Every identity must be a local account, as which the request then accesses files
// (see fsuser); accounts are looked up again after unixUserCacheTTL, so changes to
// them (new groups, say) apply within that time

const (
	unixUserCacheTTL   = time.Minute
	maxCachedUnixUsers = 4096
)

type cachedUnixUser struct {
	user *fsuser.User
	err  error
	at   time.Time
}

// unixUser returns the local account that a username names
func (as *AuthStore) unixUser(name string) (*fsuser.User, error) {
	now := time.Now()
	as.unixMu.Lock()
	c, ok := as.unixUsers[name]
	as.unixMu.Unlock()
	if ok && now.Sub(c.at) < unixUserCacheTTL {
		return c.user, c.err
	}

	lookup := as.LookupUnixUser
	if lookup == nil {
		lookup = fsuser.Lookup
	}
	u, err := lookup(name)
	if err != nil {
		u, err = nil, fmt.Errorf("%w: %q is not a usable Unix account: %v", errForbidden, name, err)
	}
	as.unixMu.Lock()
	if as.unixUsers == nil || len(as.unixUsers) >= maxCachedUnixUsers {
		as.unixUsers = make(map[string]cachedUnixUser)
	}
	as.unixUsers[name] = cachedUnixUser{user: u, err: err, at: now}
	as.unixMu.Unlock()
	return u, err
}

// ForgetUnixUsers makes accounts be looked up again on their next use
func (as *AuthStore) ForgetUnixUsers() {
	as.unixMu.Lock()
	as.unixUsers = nil
	as.unixMu.Unlock()
}
