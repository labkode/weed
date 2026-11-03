package davfs

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// open opens a tree of a new directory, closed at the end of the test
func open(t *testing.T) (*Tree, string) {
	dir := t.TempDir()
	tree, err := FS{Root: dir}.Open(context.Background())
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

// No symbolic link is followed, wherever it is in a name and wherever it points: out
// of the tree, absolutely or relatively, or inside it
func TestNoSymlinkFollowed(t *testing.T) {
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
		"proc":    "/proc/self",                                // to /proc's magic links
	} {
		if err := os.Symlink(target, filepath.Join(dir, link)); err != nil {
			t.Skip("no symbolic links here:", err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "up", "secret")); err != nil {
		t.Fatalf("the test's own link: %v", err)
	}

	for _, name := range []string{"/out/secret", "/up/secret", "/abs/f", "/sub/top/out/secret", "/sub/top/sub/f",
		"/sub/in", "/out", "/proc/environ", "/proc/fd/0"} {
		var denied atomic.Bool
		_, err := tree.Stat(TrackDenied(ctx, &denied), name)
		if !errors.Is(err, ErrSymlink) || !errors.Is(err, fs.ErrPermission) || !denied.Load() {
			t.Errorf("Stat(%s) = %v, want ErrSymlink, a permission error, noted (%v)", name, err, denied.Load())
		}
		if f, err := tree.OpenFile(ctx, name, os.O_RDONLY, 0); !errors.Is(err, ErrSymlink) {
			t.Errorf("OpenFile(%s) = %v", name, err)
			if f != nil {
				f.Close()
			}
		}
		if f, err := tree.Open(ctx, name); !errors.Is(err, ErrSymlink) {
			t.Errorf("Open(%s) = %v", name, err)
			if f != nil {
				f.Close()
			}
		}
	}
	// Lstat sees a link at the end of a name, as the link
	if fi, err := tree.Lstat(ctx, "/sub/in"); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		t.Errorf("Lstat of a link: %v, %v", fi, err)
	}
	if _, err := tree.Lstat(ctx, "/sub/top/sub/f"); !errors.Is(err, ErrSymlink) {
		t.Errorf("Lstat through a link: %v", err)
	}

	// Nothing is written through a link, by any operation
	if _, err := tree.CreateAtomic(ctx, "/out/new", 0o644); !errors.Is(err, ErrSymlink) {
		t.Errorf("CreateAtomic through the link: %v", err)
	}
	if _, err := tree.CreateAtomic(ctx, "/sub/in", 0o644); !errors.Is(err, ErrSymlink) {
		t.Errorf("CreateAtomic over a link: %v", err)
	}
	if f, err := tree.OpenFile(ctx, "/up/new", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644); !errors.Is(err, ErrSymlink) {
		t.Errorf("OpenFile to write through the link: %v", err)
		if f != nil {
			f.Close()
		}
	}
	if err := tree.Mkdir(ctx, "/out/d", 0o755); !errors.Is(err, ErrSymlink) {
		t.Errorf("Mkdir through the link: %v", err)
	}
	if err := tree.Rename(ctx, "/out/secret", "/stolen"); !errors.Is(err, ErrSymlink) {
		t.Errorf("Rename from outside: %v", err)
	}
	if err := tree.Rename(ctx, "/sub/f", "/out/f"); !errors.Is(err, ErrSymlink) {
		t.Errorf("Rename to outside: %v", err)
	}
	if err := tree.Rename(ctx, "/sub/in", "/moved"); !errors.Is(err, ErrSymlink) {
		t.Errorf("Rename of a link: %v", err)
	}
	if err := tree.Writable(ctx, "/out/secret"); !errors.Is(err, ErrSymlink) {
		t.Errorf("Writable through the link: %v", err)
	}
	if err := tree.RemoveAll(ctx, "/sub/top/sub"); !errors.Is(err, ErrSymlink) {
		t.Errorf("RemoveAll through the link: %v", err)
	}

	// Listings leave links out
	d, err := tree.OpenFile(ctx, "/", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	fis, _ := d.Readdir(-1)
	d.Close()
	if len(fis) != 1 || fis[0].Name() != "sub" {
		t.Errorf("listing: %v, want sub alone", fis)
	}

	// Removing a link removes the link, and removing a directory the links in it
	if err := tree.RemoveAll(ctx, "/out"); err != nil {
		t.Errorf("RemoveAll of the link: %v", err)
	}
	if err := tree.RemoveAll(ctx, "/sub"); err != nil {
		t.Errorf("RemoveAll of a directory with links in it: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "sub")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("sub after RemoveAll: %v", err)
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 1 || entries[0].Name() != "secret" {
		t.Errorf("outside: %v, want only secret", entries)
	}
}

// A name needs search permission on the directories on its way, not read: reading
// a file through them, and uploading to one of write and search permission
func TestSearchPermissionSuffices(t *testing.T) {
	ctx := context.Background()
	tree, dir := open(t)
	through := filepath.Join(dir, "through")
	os.Mkdir(through, 0o755)
	os.WriteFile(filepath.Join(through, "f"), []byte("f"), 0o644)
	os.Chmod(through, 0o100)
	t.Cleanup(func() { os.Chmod(through, 0o755) })
	if f, err := tree.Open(ctx, "/through/f"); err != nil {
		t.Errorf("reading through a directory of search permission alone: %v", err)
	} else {
		f.Close()
	}
	if fi, err := tree.Stat(ctx, "/through/f"); err != nil || fi.Size() != 1 {
		t.Errorf("Stat through a directory of search permission alone: %v, %v", fi, err)
	}

	drop := filepath.Join(dir, "drop")
	os.Mkdir(drop, 0o300)
	t.Cleanup(func() { os.Chmod(drop, 0o755) })
	af, err := tree.CreateAtomic(ctx, "/drop/f", 0o644)
	if err != nil {
		t.Fatal(err)
	}
	af.Write([]byte("x"))
	if err := af.Commit(); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(drop, "f")); err != nil || string(b) != "x" {
		t.Errorf("drop/f: %q, %v", b, err)
	}
}

// RemoveAll removes directories of more entries than it reads at once
func TestRemoveAllLargeDirectory(t *testing.T) {
	tree, dir := open(t)
	big := filepath.Join(dir, "big", "sub")
	os.MkdirAll(big, 0o755)
	for i := range 2500 {
		os.WriteFile(filepath.Join(big, strconv.Itoa(i)), nil, 0o644)
	}
	if err := tree.RemoveAll(context.Background(), "/big"); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("left: %v", entries)
	}
}

// Check passes on the systems weed runs on
func TestCheck(t *testing.T) {
	if err := Check(); err != nil {
		t.Fatal(err)
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
