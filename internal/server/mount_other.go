//go:build !unix

package server

import "errors"

func onRootFS(string) (bool, error) {
	return false, errors.New("not on this system")
}
