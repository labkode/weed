package version

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCurrent(t *testing.T) {
	i := Current()
	if i.Go != runtime.Version() || i.Platform != runtime.GOOS+"/"+runtime.GOARCH || !strings.HasPrefix(i.Build, "go:") {
		t.Fatalf("%+v", i)
	}
	if s := i.String(); !strings.HasPrefix(s, i.Version) || !strings.Contains(s, i.Go) {
		t.Errorf("String() = %q", s)
	}
	if s := i.Text(); !strings.Contains(s, "build    "+i.Build+"\n") {
		t.Errorf("Text() = %q", s)
	}

	// The build ID is the one the go command sees
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("go", "tool", "buildid", exe).Output(); err == nil {
		if want := "go:" + strings.TrimSpace(string(out)); i.Build != want {
			t.Errorf("build %q, go tool buildid says %q", i.Build, want)
		}
	} else {
		t.Logf("not compared with go tool buildid: %v", err)
	}

	// The executable on disk is described as the running one
	f, err := OfFile(exe)
	if err != nil || f.Build != i.Build || f.Version != i.Version || f.Go != i.Go || f.Platform != i.Platform {
		t.Errorf("OfFile: %+v, %v; running %+v", f, err, i)
	}
}

func TestBuildWithoutBuildID(t *testing.T) {
	p := filepath.Join(t.TempDir(), "script")
	os.WriteFile(p, []byte("#!/bin/sh\n"), 0755)
	sum := sha256.Sum256([]byte("#!/bin/sh\n"))
	if b, err := Build(p); err != nil || b != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Errorf("build %q, %v", b, err)
	}
	if _, err := OfFile(p); err == nil {
		t.Error("a script was described as a Go executable")
	}
	if _, err := Build(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing file has a build")
	}
}

func TestParseGoNote(t *testing.T) {
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

func TestMarkedBuildID(t *testing.T) {
	for in, want := range map[string]string{
		"\xff Go build ID: \"abc/def\"\n \xff\x00\x00": "abc/def",
		"\xff Go build ID: \"abc/def":                  "",
		"\x90\x90\xff Go build ID: \"abc\"\n \xff":     "",
	} {
		if got := markedBuildID(strings.NewReader(in)); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
