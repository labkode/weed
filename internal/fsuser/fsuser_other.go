//go:build !linux

package fsuser

import "errors"

// Writable is only supported on Linux
func Writable(p string) error { return errors.New("only supported on Linux") }
