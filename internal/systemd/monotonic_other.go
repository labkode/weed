//go:build !linux

package systemd

// monotonicUsec is only needed by systemd, which only runs on Linux
func monotonicUsec() (int64, bool) { return 0, false }
