//go:build !unix

package main

// loadCPU is the CPU time this process has used, unknown here
func loadCPU() float64 { return 0 }
