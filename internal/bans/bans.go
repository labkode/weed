// Package bans keeps the users that weed refuses, whatever their credentials (weed
// utils ban), in a file that survives restarts. The file is weed's: it writes it on
// every change, and reads it only at startup.
package bans

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// Ban refuses a user: the name that credentials map to, as the request records log it
// ("nobody" for anonymous requests)
type Ban struct {
	User   string    `json:"user"`
	Since  time.Time `json:"since"`
	Reason string    `json:"reason,omitempty"`
	By     string    `json:"by,omitempty"` // who banned the user, e.g. "uid 0, pid 4242"
}

// List is the set of bans, saved to a file ("" keeps them in memory). A nil List bans
// no one.
type List struct {
	path string
	mu   sync.RWMutex
	bans map[string]Ban
}

// Load reads the bans saved in path ("": none, kept in memory); there are none if it
// does not exist
func Load(path string) (*List, error) {
	l := &List{path: path, bans: make(map[string]Ban)}
	if path == "" {
		return l, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	var list []Ban
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, ban := range list {
		if ban.User == "" {
			return nil, fmt.Errorf("%s: a ban without a user", path)
		}
		l.bans[ban.User] = ban
	}
	return l, nil
}

// Get returns the ban of user, if banned
func (l *List) Get(user string) (Ban, bool) {
	if l == nil {
		return Ban{}, false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	b, ok := l.bans[user]
	return b, ok
}

// All returns the bans, by user
func (l *List) All() []Ban {
	if l == nil {
		return nil
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.sortedLocked()
}

// Len returns the number of banned users
func (l *List) Len() int {
	if l == nil {
		return 0
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.bans)
}

func (l *List) sortedLocked() []Ban {
	list := make([]Ban, 0, len(l.bans))
	for _, b := range l.bans {
		list = append(list, b)
	}
	slices.SortFunc(list, func(a, b Ban) int { return cmp.Compare(a.User, b.User) })
	return list
}

// Add bans b.User, unless already banned (added is false then, and the ban kept as
// it was). The ban applies even if it cannot be saved, which err then says: it lasts
// until weed restarts.
func (l *List) Add(b Ban) (added bool, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.bans[b.User]; ok {
		return false, nil
	}
	l.bans[b.User] = b
	return true, l.saveLocked()
}

// Remove lifts the ban of user, if banned; as with Add, err says that the change was
// not saved
func (l *List) Remove(user string) (removed bool, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.bans[user]; !ok {
		return false, nil
	}
	delete(l.bans, user)
	return true, l.saveLocked()
}

// saveLocked replaces the file with the bans: a new file, synced, renamed over it
func (l *List) saveLocked() error {
	if l.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(l.sortedLocked(), "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(l.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("cannot save the bans: %w", err)
	}
	f, err := os.CreateTemp(dir, ".bans-*")
	if err != nil {
		return fmt.Errorf("cannot save the bans: %w", err)
	}
	defer os.Remove(f.Name())
	_, err = f.Write(append(data, '\n'))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), l.path)
	}
	if err != nil {
		return fmt.Errorf("cannot save the bans to %s: %w", l.path, err)
	}
	return nil
}
