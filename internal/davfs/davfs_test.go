package davfs

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// open opens a tree of a new directory, closed at the end of the test
func open(t *testing.T) (*Tree, string) {
	dir := t.TempDir()
	tree, err := FS{Root: dir}.Open()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tree.Close() })
	return tree, dir
}

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
	tree, dir := open(t)
	f, err := tree.OpenFile(context.Background(), "/dst", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(f, &failingReader{n: 3}); err == nil {
		t.Fatal("copy should fail")
	}
	if err := f.Close(); err == nil {
		t.Fatal("Close committed after a failed copy")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("left behind: %v", entries)
	}
}

func TestCommitIsAtomicAndHidesTemporaryFiles(t *testing.T) {
	tree, root := open(t)
	os.WriteFile(filepath.Join(root, "f"), []byte("old"), 0644)
	f, _ := tree.OpenFile(context.Background(), "/f", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	io.Copy(f, strings.NewReader("new"))

	// Before Close the old version is still in place and the upload is invisible
	if b, _ := os.ReadFile(filepath.Join(root, "f")); string(b) != "old" {
		t.Fatalf("visible before commit: %q", b)
	}
	dir, _ := tree.OpenFile(context.Background(), "/", os.O_RDONLY, 0)
	fis, _ := dir.Readdir(-1)
	dir.Close()
	if len(fis) != 1 || fis[0].Name() != "f" {
		t.Fatalf("listing during upload: %v", fis)
	}

	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "f")); string(b) != "new" {
		t.Fatalf("after commit: %q", b)
	}
	if err := tree.RemoveAll(context.Background(), "/"); err == nil {
		t.Fatal("the exported root can be removed")
	}
}

// x/net/webdav's PROPFIND skips entries whose Stat fails with an *os.PathError but
// aborts the whole listing on any other error, so in-progress uploads must look like
// ordinary missing files
func TestTemporaryFilesDoNotExist(t *testing.T) {
	tree, dir := open(t)
	os.WriteFile(filepath.Join(dir, TempPrefix+"123"), []byte("partial"), 0600)
	for _, name := range []string{"/" + TempPrefix + "123", "/" + TempPrefix + "123/../x", "/a\x00b"} {
		_, err := tree.Stat(context.Background(), name)
		var pe *os.PathError
		if !errors.Is(err, os.ErrNotExist) || !errors.As(err, &pe) {
			t.Errorf("Stat(%q) = %v, want an *os.PathError for ErrNotExist", name, err)
		}
	}
}

func TestCommitNoReplace(t *testing.T) {
	ctx := context.Background()
	tree, dir := open(t)
	target := filepath.Join(dir, "f")

	af, err := tree.CreateAtomic(ctx, "/f", 0644)
	if err != nil {
		t.Fatal(err)
	}
	af.Write([]byte("new"))
	if err := af.CommitNoReplace(); err != nil {
		t.Fatalf("new file: %v", err)
	}

	// The target appears while the file is being written
	af, err = tree.CreateAtomic(ctx, "/f2", 0644)
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

// No name leads out of the tree: neither a symbolic link that points outside, nor an
// absolute one, wherever it is in the name; links that stay inside are followed
func TestNoNameLeadsOutside(t *testing.T) {
	ctx := context.Background()
	tree, dir := open(t)
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret"), []byte("secret"), 0o644)
	os.Mkdir(filepath.Join(dir, "sub"), 0o755)
	os.WriteFile(filepath.Join(dir, "sub", "f"), []byte("f"), 0o644)
	for link, target := range map[string]string{
		"out":     outside,                                     // absolute, outside
		"up":      filepath.Join("..", filepath.Base(outside)), // relative, outside (both are below the same temporary directory)
		"abs":     filepath.Join(dir, "sub"),                   // absolute, though inside
		"sub/in":  "f",                                         // relative, inside
		"sub/top": "..",                                        // relative, the tree itself
	} {
		if err := os.Symlink(target, filepath.Join(dir, link)); err != nil {
			t.Skip("no symbolic links here:", err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "up", "secret")); err != nil {
		t.Fatalf("the test's own link: %v", err)
	}

	for _, name := range []string{"/out/secret", "/up/secret", "/abs/f", "/sub/top/out/secret"} {
		var denied atomic.Bool
		_, err := tree.Stat(TrackDenied(ctx, &denied), name)
		if !errors.Is(err, ErrOutside) || !errors.Is(err, fs.ErrPermission) || !denied.Load() {
			t.Errorf("Stat(%s) = %v, want ErrOutside, a permission error, noted (%v)", name, err, denied.Load())
		}
		if f, err := tree.OpenFile(ctx, name, os.O_RDONLY, 0); !errors.Is(err, ErrOutside) {
			t.Errorf("OpenFile(%s) = %v", name, err)
			if f != nil {
				f.Close()
			}
		}
	}
	for _, name := range []string{"/sub/in", "/sub/top/sub/f"} {
		if fi, err := tree.Stat(ctx, name); err != nil || fi.Size() != 1 {
			t.Errorf("Stat(%s) = %v, %v; links inside are followed", name, fi, err)
		}
	}

	// Nothing is written outside, through any operation
	if _, err := tree.CreateAtomic(ctx, "/out/new", 0o644); !errors.Is(err, ErrOutside) {
		t.Errorf("CreateAtomic through the link: %v", err)
	}
	if f, err := tree.OpenFile(ctx, "/up/new", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644); !errors.Is(err, ErrOutside) {
		t.Errorf("OpenFile to write through the link: %v", err)
		if f != nil {
			f.Close()
		}
	}
	if err := tree.Mkdir(ctx, "/out/d", 0o755); !errors.Is(err, ErrOutside) {
		t.Errorf("Mkdir through the link: %v", err)
	}
	if err := tree.Rename(ctx, "/out/secret", "/stolen"); !errors.Is(err, ErrOutside) {
		t.Errorf("Rename from outside: %v", err)
	}
	if err := tree.Rename(ctx, "/sub/f", "/out/f"); !errors.Is(err, ErrOutside) {
		t.Errorf("Rename to outside: %v", err)
	}
	if err := tree.Writable(ctx, "/out/secret"); !errors.Is(err, ErrOutside) {
		t.Errorf("Writable through the link: %v", err)
	}
	// Removing the link removes the link
	if err := tree.RemoveAll(ctx, "/out"); err != nil {
		t.Errorf("RemoveAll of the link: %v", err)
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 1 || entries[0].Name() != "secret" {
		t.Errorf("outside: %v, want only secret", entries)
	}
}

// Writable says whether files and directories may be written, without changing them
func TestWritable(t *testing.T) {
	ctx := context.Background()
	tree, dir := open(t)
	os.WriteFile(filepath.Join(dir, "f"), []byte("f"), 0o644)
	if err := tree.Writable(ctx, "/f"); err != nil {
		t.Errorf("a file of ours: %v", err)
	}
	if err := tree.Writable(ctx, "/missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing file: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "f")); string(b) != "f" {
		t.Errorf("changed: %q", b)
	}
}
