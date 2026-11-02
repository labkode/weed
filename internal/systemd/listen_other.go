//go:build !linux

package systemd

// ListenPorts: systemd only runs on Linux
func ListenPorts() []int { return nil }
