package davfs

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A listing is what os.ReadDir and os.Lstat say of the directory, without symbolic
// links nor in-progress uploads, over several batches of getdents64
func TestList(t *testing.T) {
	tree, dir := open(t)
	d := filepath.Join(dir, "d")
	os.Mkdir(d, 0o755)
	long := strings.Repeat("x", 200)
	for i := range 3000 { // 3000 × ~224 bytes: some 20 batches of 32 KiB
		name := filepath.Join(d, long+string(rune('a'+i%26))+strings.Repeat("y", i%7)+"-"+strconv.Itoa(i))
		if err := os.WriteFile(name, make([]byte, i), 0o644); err != nil {
			t.Fatal(err)
		}
		if i%3 == 0 {
			os.Chtimes(name, time.Time{}, time.Unix(int64(i)*1e6, int64(i)))
		}
	}
	os.Mkdir(filepath.Join(d, "sub"), 0o700)
	os.WriteFile(filepath.Join(d, TempPrefix+"up"), nil, 0o600)
	os.Symlink("sub", filepath.Join(d, "link"))
	os.Symlink("missing", filepath.Join(d, "dangling"))
	syscall.Mkfifo(filepath.Join(d, "fifo"), 0o600)
	os.WriteFile(filepath.Join(d, "é \xff\n"), []byte("odd"), 0o644)

	want := map[string]Entry{}
	des, err := os.ReadDir(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range des {
		fi, err := os.Lstat(filepath.Join(d, de.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode()&os.ModeSymlink != 0 || strings.HasPrefix(de.Name(), TempPrefix) {
			continue
		}
		mt := fi.ModTime()
		want[de.Name()] = Entry{Dir: fi.IsDir(), Size: fi.Size(), MtimeSec: mt.Unix(), MtimeNsec: int64(mt.Nanosecond())}
	}

	l, err := tree.List(context.Background(), "/d")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got, batches := map[string]Entry{}, 0
	for {
		entries, err := l.Next()
		if err == io.EOF {
			if len(entries) != 0 {
				t.Fatalf("io.EOF with %d entries", len(entries))
			}
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) == 0 {
			t.Fatal("a batch without entries, nor an error")
		}
		batches++
		for _, e := range entries {
			name := string(e.Name)
			if _, dup := got[name]; dup {
				t.Fatalf("%q listed twice", name)
			}
			e.Name = nil
			got[name] = e
		}
	}
	if batches < 10 {
		t.Errorf("%d batches: the test lists too little", batches)
	}
	if len(got) != len(want) {
		t.Errorf("%d entries, want %d", len(got), len(want))
	}
	for name, w := range want {
		if g, ok := got[name]; !ok {
			t.Errorf("%q not listed", name)
		} else if !reflect.DeepEqual(g, w) {
			t.Errorf("%q: %+v, want %+v", name, g, w)
		}
	}
	if _, err := l.Next(); err != io.EOF {
		t.Errorf("Next after the end: %v", err)
	}
}

func TestListRefused(t *testing.T) {
	tree, dir := open(t)
	os.WriteFile(filepath.Join(dir, "f"), nil, 0o644)
	os.Symlink(".", filepath.Join(dir, "link"))
	ctx := context.Background()
	if _, err := tree.List(ctx, "/f"); !errors.Is(err, syscall.ENOTDIR) {
		t.Errorf("List of a file: %v", err)
	}
	if _, err := tree.List(ctx, "/link"); !errors.Is(err, ErrSymlink) {
		t.Errorf("List of a symbolic link: %v", err)
	}
	if _, err := tree.List(ctx, "/missing"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("List of nothing: %v", err)
	}
}

// Opening for reading what is not a regular file does not wait, as opening a FIFO
// would for a writer: it is refused
func TestOpenNotRegular(t *testing.T) {
	tree, dir := open(t)
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	os.Mkdir(filepath.Join(dir, "d"), 0o755)
	os.WriteFile(filepath.Join(dir, "f"), []byte("data"), 0o644)
	ctx := context.Background()

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := tree.Open(ctx, "/fifo"); !errors.Is(err, ErrNotRegular) || !errors.Is(err, os.ErrPermission) {
			t.Errorf("Open of a FIFO: %v", err)
		}
		if _, err := tree.OpenFile(ctx, "/fifo", os.O_RDONLY, 0); !errors.Is(err, ErrNotRegular) {
			t.Errorf("OpenFile of a FIFO: %v", err)
		}
		if _, err := tree.Open(ctx, "/d"); !errors.Is(err, ErrNotRegular) {
			t.Errorf("Open of a directory: %v", err)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("opening a FIFO waits")
	}

	f, err := tree.OpenFile(ctx, "/d", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile of a directory: %v", err)
	}
	f.Close()
	r, err := tree.Open(ctx, "/f")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil || string(b) != "data" {
		t.Fatalf("read %q, %v", b, err)
	}
}
