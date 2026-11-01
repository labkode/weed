// Package davfs provides the local filesystem behind the WebDAV namespace.
//
// It behaves like webdav.Dir with three differences: files are written to a
// temporary file and atomically renamed into place once complete, so an interrupted
// upload never leaves a truncated file behind; those in-progress temporary files are
// invisible to WebDAV clients; and no name leads out of the exported directory. Each
// request opens it as an os.Root (a Tree), which refuses "..", and symbolic links
// that point outside it or are absolute, wherever they are in a name.
package davfs

import (
	"cmp"
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"math/rand/v2"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/labkode/weed/internal/fsuser"
	"golang.org/x/net/webdav"
)

// TempPrefix names in-progress uploads
const TempPrefix = ".weed-upload-"

var errWriteFailed = errors.New("write failed; upload discarded")

// ErrOutside is the error of a name that leads outside the exported directory,
// through a symbolic link that points outside it or is absolute. It is a permission
// error: weed answers 403.
var ErrOutside error = outsideError{}

type outsideError struct{}

func (outsideError) Error() string { return "leads outside the exported directory" }

func (outsideError) Is(target error) bool { return target == fs.ErrPermission }

// FS is the exported directory, which each request opens as a Tree
type FS struct {
	Root string
}

// Open opens the exported directory for one request. Opened for each, it is the
// directory of the moment: a storage mounted over it is seen at once, and idle
// workers keep nothing open that would keep it from being unmounted.
func (fs FS) Open() (*Tree, error) {
	root, err := os.OpenRoot(cmp.Or(fs.Root, "."))
	if err != nil {
		return nil, err
	}
	return &Tree{root: root}, nil
}

// Tree is the exported directory opened for a request (FS.Open): a webdav.FileSystem
// whose names never lead out of it. Close it at the end of the request.
type Tree struct {
	root *os.Root
}

// Close closes the directory; the files opened in it stay open
func (t *Tree) Close() error { return t.root.Close() }

type deniedKey struct{}

// TrackDenied returns a context in which FS operations that fail for lack of
// permission set *denied: x/net/webdav reports those failures as 404, 405 or 500
func TrackDenied(ctx context.Context, denied *atomic.Bool) context.Context {
	return context.WithValue(ctx, deniedKey{}, denied)
}

func noteDenied(ctx context.Context, err error) {
	if errors.Is(err, fs.ErrPermission) {
		if denied, ok := ctx.Value(deniedKey{}).(*atomic.Bool); ok {
			denied.Store(true)
		}
	}
}

// local maps a namespace name ("/a/b") to its name in the tree ("a/b"; "." for the
// directory itself). Names that cannot be represented, or that refer to in-progress
// uploads, do not exist.
func local(name string) (string, error) {
	// A *PathError (not a bare ErrNotExist) lets PROPFIND skip the entry instead of failing
	notExist := &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
	if filepath.Separator != '/' && strings.ContainsRune(name, filepath.Separator) ||
		strings.Contains(name, "\x00") {
		return "", notExist
	}
	clean := path.Clean("/" + name)
	if strings.Contains(clean, "/"+TempPrefix) {
		return "", notExist
	}
	if clean == "/" {
		return ".", nil
	}
	return filepath.FromSlash(clean[1:]), nil
}

// Valid reports whether name can be that of a file: neither one that cannot be
// represented, nor that of an in-progress upload
func Valid(name string) bool {
	_, err := local(name)
	return err == nil
}

var (
	escapeOnce sync.Once
	escapeErr  error
)

// checked is err of an operation on name: os.Root's error for a name that leads
// outside the tree becomes ErrOutside, and is logged; a permission error is noted
// for TrackDenied
func (t *Tree) checked(ctx context.Context, name string, err error) error {
	if err == nil {
		return nil
	}
	// Package os does not export its error, but it is that of an absolute name, which
	// no Root accepts
	escapeOnce.Do(func() {
		_, e := t.root.Lstat(string(filepath.Separator))
		escapeErr = errors.Unwrap(e)
	})
	if escapeErr != nil && errors.Is(err, escapeErr) {
		slog.WarnContext(ctx, "refused a name that leads outside the exported directory, through a symbolic link", "path", name)
		err = &os.PathError{Op: "open", Path: name, Err: ErrOutside}
	}
	noteDenied(ctx, err)
	return err
}

// Mkdir implements webdav.FileSystem
func (t *Tree) Mkdir(ctx context.Context, name string, perm os.FileMode) (err error) {
	defer func() { err = t.checked(ctx, name, err) }()
	p, err := local(name)
	if err != nil {
		return err
	}
	return t.root.Mkdir(p, perm)
}

// OpenFile implements webdav.FileSystem. Writes that truncate the target go through
// an AtomicFile that is committed when closed.
func (t *Tree) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (_ webdav.File, err error) {
	defer func() { err = t.checked(ctx, name, err) }()
	p, err := local(name)
	if err != nil {
		return nil, err
	}
	if flag&(os.O_WRONLY|os.O_RDWR) != 0 && flag&os.O_CREATE != 0 && flag&os.O_TRUNC != 0 {
		af, err := t.createAtomic(p, perm)
		if err != nil {
			return nil, err
		}
		return &davFile{af: af}, nil
	}
	f, err := t.root.OpenFile(p, flag, perm)
	if err != nil {
		return nil, err
	}
	return &dirFilter{f}, nil
}

// RemoveAll implements webdav.FileSystem
func (t *Tree) RemoveAll(ctx context.Context, name string) (err error) {
	defer func() { err = t.checked(ctx, name, err) }()
	p, err := local(name)
	if err != nil {
		return err
	}
	if p == "." {
		return os.ErrInvalid // never remove the exported directory itself
	}
	return t.root.RemoveAll(p)
}

// Rename implements webdav.FileSystem
func (t *Tree) Rename(ctx context.Context, oldName, newName string) (err error) {
	defer func() { err = t.checked(ctx, oldName, err) }()
	oldPath, err := local(oldName)
	if err != nil {
		return err
	}
	newPath, err := local(newName)
	if err != nil {
		return err
	}
	if oldPath == "." || newPath == "." {
		return os.ErrInvalid
	}
	return t.root.Rename(oldPath, newPath)
}

// Stat implements webdav.FileSystem
func (t *Tree) Stat(ctx context.Context, name string) (_ os.FileInfo, err error) {
	defer func() { err = t.checked(ctx, name, err) }()
	p, err := local(name)
	if err != nil {
		return nil, err
	}
	return t.root.Stat(p)
}

// Lstat is Stat, but of a symbolic link itself
func (t *Tree) Lstat(ctx context.Context, name string) (_ os.FileInfo, err error) {
	defer func() { err = t.checked(ctx, name, err) }()
	p, err := local(name)
	if err != nil {
		return nil, err
	}
	return t.root.Lstat(p)
}

// Open opens name for reading
func (t *Tree) Open(ctx context.Context, name string) (_ *os.File, err error) {
	defer func() { err = t.checked(ctx, name, err) }()
	p, err := local(name)
	if err != nil {
		return nil, err
	}
	return t.root.Open(p)
}

// Writable reports whether this process may write name: a file it can open for
// writing, or a directory the kernel says it may write (on Linux; see fsuser)
func (t *Tree) Writable(ctx context.Context, name string) (err error) {
	defer func() { err = t.checked(ctx, name, err) }()
	p, err := local(name)
	if err != nil {
		return err
	}
	fi, err := t.root.Stat(p)
	if err != nil {
		return err
	}
	switch {
	case fi.Mode().IsRegular():
		f, err := t.root.OpenFile(p, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		return f.Close()
	case fi.IsDir():
		d, err := t.root.Open(p)
		if err != nil {
			return err
		}
		defer d.Close()
		return fsuser.WritableDir(d)
	}
	// Opening a FIFO or a device could block, or do something
	return &os.PathError{Op: "access", Path: name, Err: fs.ErrPermission}
}

// AtomicFile is a file that only appears at its target name once Commit succeeds
type AtomicFile struct {
	*os.File    // the temporary file
	root        *os.Root
	tmp, target string // in root
	done        bool
}

// CreateAtomic starts writing a new version of name. Its directory must exist.
func (t *Tree) CreateAtomic(ctx context.Context, name string, perm os.FileMode) (_ *AtomicFile, err error) {
	defer func() { err = t.checked(ctx, name, err) }()
	p, err := local(name)
	if err != nil {
		return nil, err
	}
	return t.createAtomic(p, perm)
}

func (t *Tree) createAtomic(target string, perm os.FileMode) (*AtomicFile, error) {
	fi, err := t.root.Stat(target)
	switch {
	case err == nil && fi.IsDir():
		return nil, &os.PathError{Op: "open", Path: target, Err: syscall.EISDIR}
	case err == nil && fi.Mode().IsRegular():
		// Renaming over a file only needs write permission on its directory; replacing
		// it needs write permission on the file too, as writing it in place would
		f, err := t.root.OpenFile(target, os.O_WRONLY, 0)
		if err != nil {
			return nil, err
		}
		f.Close()
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return nil, err // e.g. a symbolic link that leads outside
	}
	dir := filepath.Dir(target)
	for range 100 {
		tmp := filepath.Join(dir, TempPrefix+strconv.FormatUint(rand.Uint64(), 36))
		f, err := t.root.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := f.Chmod(perm &^ umask); err != nil {
			f.Close()
			t.root.Remove(tmp)
			return nil, err
		}
		return &AtomicFile{File: f, root: t.root, tmp: tmp, target: target}, nil
	}
	return nil, &os.PathError{Op: "createtemp", Path: target, Err: fs.ErrExist}
}

// Commit flushes the data to stable storage and moves the file into place
func (a *AtomicFile) Commit() error { return a.commit(true) }

// CommitNoReplace is Commit, but fails with an error matching os.ErrExist if the
// target exists, even if it was created while the file was being written
func (a *AtomicFile) CommitNoReplace() error { return a.commit(false) }

func (a *AtomicFile) commit(replace bool) error {
	if a.done {
		return os.ErrClosed
	}
	a.done = true
	if err := a.File.Sync(); err != nil {
		a.File.Close()
		a.root.Remove(a.tmp)
		return err
	}
	if err := a.File.Close(); err != nil {
		a.root.Remove(a.tmp)
		return err
	}
	if replace {
		if err := a.root.Rename(a.tmp, a.target); err != nil {
			a.root.Remove(a.tmp)
			return err
		}
	} else if err := a.linkNoReplace(); err != nil {
		a.root.Remove(a.tmp)
		return err
	}
	syncDir(a.root, filepath.Dir(a.target))
	return nil
}

// linkNoReplace moves the file to its target unless that exists. A hard link is
// created atomically or not at all; on filesystems without hard links the check and
// the rename are separate steps.
func (a *AtomicFile) linkNoReplace() error {
	err := a.root.Link(a.tmp, a.target)
	if err == nil || errors.Is(err, fs.ErrExist) {
		a.root.Remove(a.tmp)
		return err
	}
	if _, statErr := a.root.Lstat(a.target); statErr == nil {
		return &os.PathError{Op: "create", Path: a.target, Err: fs.ErrExist}
	}
	return a.root.Rename(a.tmp, a.target)
}

// Abort discards the upload. It is a no-op after Commit.
func (a *AtomicFile) Abort() {
	if a.done {
		return
	}
	a.done = true
	a.File.Close()
	a.root.Remove(a.tmp)
}

// syncDir makes a rename durable; best effort (not supported on every platform)
func syncDir(root *os.Root, dir string) {
	if d, err := root.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}

// davFile adapts AtomicFile to webdav.File. It deliberately does not embed *os.File:
// that would promote ReadFrom, letting io.Copy bypass Write and its error tracking.
type davFile struct {
	af     *AtomicFile
	failed bool
}

func (f *davFile) Read(p []byte) (int, error)                { return f.af.Read(p) }
func (f *davFile) Seek(off int64, whence int) (int64, error) { return f.af.Seek(off, whence) }
func (f *davFile) Readdir(count int) ([]os.FileInfo, error)  { return nil, syscall.ENOTDIR }
func (f *davFile) Stat() (os.FileInfo, error)                { return f.af.Stat() }

func (f *davFile) Write(p []byte) (int, error) {
	n, err := f.af.Write(p)
	if err != nil {
		f.failed = true
	}
	return n, err
}

// ReadFrom is what io.Copy uses (x/net/webdav copies through it for local COPY); it
// sees read errors too, so a failed source read never commits a truncated file
func (f *davFile) ReadFrom(r io.Reader) (int64, error) {
	n, err := io.Copy(struct{ io.Writer }{f.af.File}, r)
	if err != nil {
		f.failed = true
	}
	return n, err
}

func (f *davFile) Close() error {
	if f.failed {
		f.af.Abort()
		return errWriteFailed
	}
	return f.af.Commit()
}

// dirFilter hides in-progress uploads from directory listings
type dirFilter struct {
	*os.File
}

func (d *dirFilter) Readdir(count int) ([]os.FileInfo, error) {
	for {
		fis, err := d.File.Readdir(count)
		kept := fis[:0]
		for _, fi := range fis {
			if !strings.HasPrefix(fi.Name(), TempPrefix) {
				kept = append(kept, fi)
			}
		}
		// With count > 0 an empty result must carry an error; keep reading instead
		if count <= 0 || len(kept) > 0 || err != nil {
			return kept, err
		}
	}
}
