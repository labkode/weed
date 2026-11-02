//go:build !linux

package landlock

import "errors"

var errUnsupported = errors.New("Landlock is only on Linux")

// ABI is 0: Landlock is Linux's
func ABI() int { return 0 }

// Ruleset is only supported on Linux
type Ruleset struct{}

// New is only supported on Linux
func New([]Rule, Net) (*Ruleset, error) { return nil, errUnsupported }

func (rs *Ruleset) Restrict() error                       { return errUnsupported }
func (rs *Ruleset) Exec(argv, env []string) error         { return errUnsupported }
func (rs *Ruleset) Unreachable(...string) (string, error) { return "", errUnsupported }
func (rs *Ruleset) Dup() (*Ruleset, error)                { return nil, errUnsupported }
func (rs *Ruleset) Close() error                          { return nil }
