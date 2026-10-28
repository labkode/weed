package worker

import (
	"context"
	"encoding/binary"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	// The pool tests start this binary as their workers
	if len(os.Args) > 1 && os.Args[1] == "worker" {
		c, err := Attach()
		if err == nil {
			err = c.Serve(http.NotFoundHandler(), func() {})
		}
		if err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestExecutableBuild(t *testing.T) {
	build, err := executableBuild()
	if err != nil || !strings.HasPrefix(build, "go:") {
		t.Fatalf("build %q, %v", build, err)
	}
	// The ID is the one the go command sees
	if exe, err := os.Executable(); err == nil {
		if out, err := exec.Command("go", "tool", "buildid", exe).Output(); err == nil {
			if want := "go:" + strings.TrimSpace(string(out)); build != want {
				t.Errorf("build %q, go tool buildid says %q", build, want)
			}
		} else {
			t.Logf("not compared with go tool buildid: %v", err)
		}
	}

	note := func(nameSize uint32, name string, typ uint32, desc string) []byte {
		b := binary.LittleEndian.AppendUint32(nil, nameSize)
		b = binary.LittleEndian.AppendUint32(b, uint32(len(desc)))
		b = binary.LittleEndian.AppendUint32(b, typ)
		return append(append(b, name...), desc...)
	}
	for _, c := range []struct {
		name string
		data []byte
		id   string // "" for an error
	}{
		{"build ID", note(4, "Go\x00\x00", 4, "abc/def"), "abc/def"},
		{"other type", note(4, "Go\x00\x00", 1, "abc/def"), ""},
		{"other name", note(4, "GNU\x00", 4, "abc/def"), ""},
		{"truncated", note(4, "Go\x00\x00", 4, "abc/def")[:16], ""},
		{"name size beyond the note", note(1<<31, "Go\x00\x00", 4, ""), ""},
		{"short", []byte{4, 0, 0}, ""},
	} {
		id, err := parseGoNote(c.data, binary.LittleEndian)
		if id != c.id || (err == nil) != (c.id != "") {
			t.Errorf("%s: %q, %v", c.name, id, err)
		}
	}
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
