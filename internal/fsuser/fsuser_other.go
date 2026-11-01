//go:build !linux

package fsuser

import (
	"errors"
	"os"
)

// WritableDir is only supported on Linux
func WritableDir(d *os.File) error { return errors.New("only supported on Linux") }
