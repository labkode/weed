package stress

import "syscall"

// loadCPU is the CPU time this process has used, in seconds
func loadCPU() float64 {
	var ru syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &ru) != nil {
		return 0
	}
	return float64(ru.Utime.Nano()+ru.Stime.Nano()) / 1e9
}
