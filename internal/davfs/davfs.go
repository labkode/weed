// Package davfs provides the local filesystem behind the WebDAV namespace.
//
// It behaves like webdav.Dir with two differences: files are written to a temporary
// file and atomically renamed into place once complete, so an interrupted upload never
// leaves a truncated file behind; and those in-progress temporary files are invisible
// to WebDAV clients.
package davfs

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"

	"golang.org/x/net/webdav"
)

// TempPrefix names in-progress uploads
const TempPrefix = ".weed-upload-"

var errWriteFailed = errors.New("write failed; upload discarded")

// FS is a webdav.FileSystem rooted at a local directory
type FS struct {
	Root string
}

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

// Resolve maps a namespace name ("/a/b") to a local path. Names that cannot be
// represented, or that refer to in-progress uploads, do not exist.
func (fs FS) Resolve(name string) (string, error) {
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
	root := fs.Root
	if root == "" {
		root = "."
	}
	return filepath.Join(root, filepath.FromSlash(clean)), nil
}

func (fs FS) isRoot(p string) bool {
	root := fs.Root
	if root == "" {
		root = "."
	}
	return p == filepath.Clean(root)
}

// Mkdir implements webdav.FileSystem
func (fs FS) Mkdir(ctx context.Context, name string, perm os.FileMode) (err error) {
	defer func() { noteDenied(ctx, err) }()
	p, err := fs.Resolve(name)
	if err != nil {
		return err
	}
	return os.Mkdir(p, perm)
}

// OpenFile implements webdav.FileSystem. Writes that truncate the target go through
// an AtomicFile that is committed when closed.
func (fs FS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (_ webdav.File, err error) {
	defer func() { noteDenied(ctx, err) }()
	p, err := fs.Resolve(name)
	if err != nil {
		return nil, err
	}
	if flag&(os.O_WRONLY|os.O_RDWR) != 0 && flag&os.O_CREATE != 0 && flag&os.O_TRUNC != 0 {
		af, err := CreateAtomic(p, perm)
		if err != nil {
			return nil, err
		}
		return &davFile{af: af}, nil
	}
	f, err := os.OpenFile(p, flag, perm)
	if err != nil {
		return nil, err
	}
	return &dirFilter{f}, nil
}

// RemoveAll implements webdav.FileSystem
func (fs FS) RemoveAll(ctx context.Context, name string) (err error) {
	defer func() { noteDenied(ctx, err) }()
	p, err := fs.Resolve(name)
	if err != nil {
		return err
	}
	if fs.isRoot(p) {
		return os.ErrInvalid // never remove the exported directory itself
	}
	return os.RemoveAll(p)
}

// Rename implements webdav.FileSystem
func (fs FS) Rename(ctx context.Context, oldName, newName string) (err error) {
	defer func() { noteDenied(ctx, err) }()
	oldPath, err := fs.Resolve(oldName)
	if err != nil {
		return err
	}
	newPath, err := fs.Resolve(newName)
	if err != nil {
		return err
	}
	if fs.isRoot(oldPath) || fs.isRoot(newPath) {
		return os.ErrInvalid
	}
	return os.Rename(oldPath, newPath)
}

// Stat implements webdav.FileSystem
func (fs FS) Stat(ctx context.Context, name string) (_ os.FileInfo, err error) {
	defer func() { noteDenied(ctx, err) }()
	p, err := fs.Resolve(name)
	if err != nil {
		return nil, err
	}
	return os.Stat(p)
}

// AtomicFile is a file that only appears at its target path once Commit succeeds
type AtomicFile struct {
	*os.File // the temporary file
	target   string
	done     bool
}

// CreateAtomic starts writing a new version of target. The parent directory must exist.
func CreateAtomic(target string, perm os.FileMode) (*AtomicFile, error) {
	fi, err := os.Stat(target)
	if err == nil && fi.IsDir() {
		return nil, &os.PathError{Op: "open", Path: target, Err: syscall.EISDIR}
	}
	// Renaming over a file only needs write permission on its directory; replacing it
	// needs write permission on the file too, as writing it in place would
	if err == nil && fi.Mode().IsRegular() {
		f, err := os.OpenFile(target, os.O_WRONLY, 0)
		if err != nil {
			return nil, err
		}
		f.Close()
	}
	f, err := os.CreateTemp(filepath.Dir(target), TempPrefix+"*")
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(perm &^ umask); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, err
	}
	return &AtomicFile{File: f, target: target}, nil
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
	tmp := a.File.Name()
	if err := a.File.Sync(); err != nil {
		a.File.Close()
		os.Remove(tmp)
		return err
	}
	if err := a.File.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if replace {
		if err := os.Rename(tmp, a.target); err != nil {
			os.Remove(tmp)
			return err
		}
	} else if err := linkNoReplace(tmp, a.target); err != nil {
		os.Remove(tmp)
		return err
	}
	syncDir(filepath.Dir(a.target))
	return nil
}

// linkNoReplace moves tmp to target unless target exists. A hard link is created
// atomically or not at all; on filesystems without hard links the check and the
// rename are separate steps.
func linkNoReplace(tmp, target string) error {
	err := os.Link(tmp, target)
	if err == nil || errors.Is(err, fs.ErrExist) {
		os.Remove(tmp)
		return err
	}
	if _, statErr := os.Lstat(target); statErr == nil {
		return &os.PathError{Op: "create", Path: target, Err: fs.ErrExist}
	}
	return os.Rename(tmp, target)
}

// Abort discards the upload. It is a no-op after Commit.
func (a *AtomicFile) Abort() {
	if a.done {
		return
	}
	a.done = true
	a.File.Close()
	os.Remove(a.File.Name())
}

// syncDir makes a rename durable; best effort (not supported on every platform)
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
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
