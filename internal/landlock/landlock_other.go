//go:build !linux

package landlock

import (
	"errors"
	"os"
)

// Access is what a Rule allows
type Access uint8

const (
	Read Access = iota + 1
	Exec
	Write
)

// Rule allows Access beneath Path
type Rule struct {
	Path   string
	Access Access
	File   *os.File
}

// MinABI is the version of Landlock that New needs
const MinABI = 2

// ABI is 0: Landlock is Linux's
func ABI() int { return 0 }

// Ruleset is only supported on Linux
type Ruleset struct{}

// New is only supported on Linux
func New([]Rule) (*Ruleset, error) { return nil, errors.New("Landlock is only on Linux") }

func (rs *Ruleset) Restrict() error { return errors.New("Landlock is only on Linux") }

func (rs *Ruleset) Dup() (*Ruleset, error) { return nil, errors.New("Landlock is only on Linux") }

func (rs *Ruleset) Close() error { return nil }
