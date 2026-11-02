//go:build unix

package server

import (
	"strings"
	"testing"
)

func TestCheckMounted(t *testing.T) {
	if err := checkMounted("/"); err == nil || !strings.Contains(err.Error(), "is on the file system of /") {
		t.Errorf("/: %v", err)
	}
	if err := checkMounted("/no/such/dir"); err == nil || !strings.Contains(err.Error(), "cannot tell") {
		t.Errorf("a missing directory: %v", err)
	}
}
