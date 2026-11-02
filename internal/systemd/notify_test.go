package systemd

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNotify(t *testing.T) {
	// Not t.TempDir(): socket paths are limited to about 100 bytes
	dir, err := os.MkdirTemp("", "sd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	addr := &net.UnixAddr{Name: filepath.Join(dir, "notify"), Net: "unixgram"}
	ln, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	t.Setenv("NOTIFY_SOCKET", addr.Name)
	read := func() string {
		t.Helper()
		ln.SetReadDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, 4096)
		n, err := ln.Read(b)
		if err != nil {
			t.Fatal(err)
		}
		return string(b[:n])
	}

	Ready("serving\nsince now")
	if got := read(); got != "READY=1\nSTATUS=serving since now" {
		t.Errorf("Ready: %q", got)
	}
	Reloading()
	if got := read(); !strings.HasPrefix(got, "RELOADING=1") || !strings.Contains(got, "\nMONOTONIC_USEC=") {
		t.Errorf("Reloading: %q", got)
	}
	Status("restart pending")
	if got := read(); got != "STATUS=restart pending" {
		t.Errorf("Status: %q", got)
	}
	Stopping()
	if got := read(); got != "STOPPING=1" {
		t.Errorf("Stopping: %q", got)
	}

	// Without systemd, nothing happens
	t.Setenv("NOTIFY_SOCKET", "")
	if err := notify("READY=1"); err != nil {
		t.Error(err)
	}
}
