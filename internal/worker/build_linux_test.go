package worker

import (
	"context"
	"log"
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	// The pool tests start this binary as their workers
	if len(os.Args) > 1 && os.Args[1] == "worker" {
		c, err := Attach()
		if err == nil {
			err = c.Serve(anyFile, func() {})
		}
		if err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// Workers that do not run the front process's build are refused
func TestWorkerBuild(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("starting workers as other accounts needs root")
	}
	p, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close(context.Background()) })
	if err := p.Check(); err != nil {
		t.Fatalf("worker of the same build: %v", err)
	}

	// Upgrades rename a new executable over the old one: new workers still run this
	// process's build, not the new one (which here would fail to start)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe+".new", []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(exe+".new", exe); err != nil {
		t.Fatal(err)
	}
	if err := p.Check(); err != nil {
		t.Fatalf("worker started after the executable was replaced: %v", err)
	}

	own := p.build
	p.build = "go:another"
	if err := p.Check(); err == nil || !strings.Contains(err.Error(), "runs build "+own+" of weed, not this process's go:another") {
		t.Fatalf("worker of another build: %v", err)
	}
}
