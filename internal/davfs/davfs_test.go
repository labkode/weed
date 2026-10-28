package davfs

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failingReader struct{ n int }

func (f *failingReader) Read(p []byte) (int, error) {
	if f.n == 0 {
		return 0, errors.New("disk on fire")
	}
	f.n--
	return copy(p, "chunk"), nil
}

// x/net/webdav's local COPY does io.Copy(dst, src) and then Close: a source read
// error must not commit the half-written destination
func TestReadErrorDoesNotCommit(t *testing.T) {
	fs := FS{Root: t.TempDir()}
	f, err := fs.OpenFile(context.Background(), "/dst", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(f, &failingReader{n: 3}); err == nil {
		t.Fatal("copy should fail")
	}
	if err := f.Close(); err == nil {
		t.Fatal("Close committed after a failed copy")
	}
	entries, _ := os.ReadDir(fs.Root)
	if len(entries) != 0 {
		t.Fatalf("left behind: %v", entries)
	}
}

func TestCommitIsAtomicAndHidesTemporaryFiles(t *testing.T) {
	fs := FS{Root: t.TempDir()}
	os.WriteFile(filepath.Join(fs.Root, "f"), []byte("old"), 0644)
	f, _ := fs.OpenFile(context.Background(), "/f", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	io.Copy(f, strings.NewReader("new"))

	// Before Close the old version is still in place and the upload is invisible
	if b, _ := os.ReadFile(filepath.Join(fs.Root, "f")); string(b) != "old" {
		t.Fatalf("visible before commit: %q", b)
	}
	dir, _ := fs.OpenFile(context.Background(), "/", os.O_RDONLY, 0)
	fis, _ := dir.Readdir(-1)
	dir.Close()
	if len(fis) != 1 || fis[0].Name() != "f" {
		t.Fatalf("listing during upload: %v", fis)
	}

	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(fs.Root, "f")); string(b) != "new" {
		t.Fatalf("after commit: %q", b)
	}
	if err := fs.RemoveAll(context.Background(), "/"); err == nil {
		t.Fatal("the exported root can be removed")
	}
}

// x/net/webdav's PROPFIND skips entries whose Stat fails with an *os.PathError but
// aborts the whole listing on any other error, so in-progress uploads must look like
// ordinary missing files
func TestTemporaryFilesDoNotExist(t *testing.T) {
	fs := FS{Root: t.TempDir()}
	os.WriteFile(filepath.Join(fs.Root, TempPrefix+"123"), []byte("partial"), 0600)
	for _, name := range []string{"/" + TempPrefix + "123", "/" + TempPrefix + "123/../x", "/a\x00b"} {
		_, err := fs.Stat(context.Background(), name)
		var pe *os.PathError
		if !errors.Is(err, os.ErrNotExist) || !errors.As(err, &pe) {
			t.Errorf("Stat(%q) = %v, want an *os.PathError for ErrNotExist", name, err)
		}
	}
}

func TestCommitNoReplace(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "f")

	af, err := CreateAtomic(target, 0644)
	if err != nil {
		t.Fatal(err)
	}
	af.Write([]byte("new"))
	if err := af.CommitNoReplace(); err != nil {
		t.Fatalf("new file: %v", err)
	}

	// The target appears while the file is being written
	af, err = CreateAtomic(target+"2", 0644)
	if err != nil {
		t.Fatal(err)
	}
	af.Write([]byte("late"))
	os.WriteFile(target+"2", []byte("first"), 0644)
	if err := af.CommitNoReplace(); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing target: %v", err)
	}
	for name, want := range map[string]string{"f": "new", "f2": "first"} {
		if b, _ := os.ReadFile(filepath.Join(dir, name)); string(b) != want {
			t.Errorf("%s = %q, want %q", name, b, want)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Errorf("leftover temporary files: %v", entries)
	}
}
