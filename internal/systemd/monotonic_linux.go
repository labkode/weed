package systemd

import "golang.org/x/sys/unix"

// monotonicUsec is CLOCK_MONOTONIC in microseconds, as systemd counts
func monotonicUsec() (int64, bool) {
	var ts unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts) != nil {
		return 0, false
	}
	return ts.Nano() / 1000, true
}
