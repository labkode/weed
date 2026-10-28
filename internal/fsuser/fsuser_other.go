//go:build !linux

package fsuser

import "errors"

var errUnsupported = errors.New("acting as Unix users is only supported on Linux")

// Run is only supported on Linux
func (u *User) Run(f func()) error { return errUnsupported }

// Writable is only supported on Linux
func Writable(p string) error { return errUnsupported }

// Check is only supported on Linux
func Check() error { return errUnsupported }
