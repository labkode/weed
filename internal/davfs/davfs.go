// Package davfs provides the local filesystem behind the WebDAV namespace.
//
// It behaves like webdav.Dir with three differences: files are written to a
// temporary file and atomically renamed into place once complete, so an interrupted
// upload never leaves a truncated file behind; those in-progress temporary files are
// invisible to WebDAV clients; and no name leads out of the exported directory. Each
// request opens it (a Tree), and resolves every name beneath it with openat2(2),
// which refuses ".." and every symbolic link, wherever it is in a name: weed follows
// no symbolic link, and lists none. Its calls to the storage go through a Gate, which
// bounds how many are in progress at once, and with them the threads they hold.
package davfs

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/rand/v2"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/labkode/weed/internal/fsuser"
	"golang.org/x/net/webdav"
	"golang.org/x/sys/unix"
)

// TempPrefix names in-progress uploads
const TempPrefix = ".weed-upload-"

var errWriteFailed = errors.New("write failed; upload discarded")

// ErrSymlink is the error of a name with a symbolic link in it, anywhere: weed
// follows none. It is a permission error: weed answers 403.
var ErrSymlink error = symlinkError{}

type symlinkError struct{}

func (symlinkError) Error() string { return "a symbolic link, which weed does not follow" }

func (symlinkError) Is(target error) bool { return target == fs.ErrPermission }

// ErrNotRegular is the error of opening for reading what is neither a regular file
// nor, where one is allowed, a directory: a FIFO, whose open would wait for a writer,
// or a device. It is a permission error.
var ErrNotRegular error = notRegularError{}

type notRegularError struct{}

func (notRegularError) Error() string { return "not a regular file" }

func (notRegularError) Is(target error) bool { return target == fs.ErrPermission }

// resolve is how openat2 resolves every name: beneath the directory it starts from,
// and through no symbolic link (nor /proc's magic links), the last component of the
// name included
const resolve = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS

// openat2fd opens name, in the directory dirfd, as resolve says
func openat2fd(dirfd int, name string, flags int, perm os.FileMode) (int, error) {
	how := unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC), Resolve: resolve}
	if flags&unix.O_CREAT != 0 {
		how.Mode = uint64(perm.Perm()) // and zero otherwise, or openat2 refuses
	}
	for {
		fd, err := unix.Openat2(dirfd, name, &how)
		if err == unix.EINTR {
			continue
		}
		if err == unix.EXDEV {
			err = unix.EACCES // a name that leads above dirfd, which local never makes
		}
		if err != nil {
			return -1, &os.PathError{Op: "openat2", Path: name, Err: err}
		}
		return fd, nil
	}
}

// openat is openat2fd, as an *os.File
func openat(dirfd int, name string, flags int, perm os.FileMode) (*os.File, error) {
	fd, err := openat2fd(dirfd, name, flags, perm)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

// openRead opens p for reading, without waiting, as opening a FIFO would until it has
// a writer; what is neither a regular file nor, if dirs, a directory is refused
// (ErrNotRegular)
func (t *Tree) openRead(p string, dirs bool) (*os.File, error) {
	fd, err := openat2fd(t.dir, p, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := ignoringEINTR(func() error { return unix.Fstat(fd, &st) }); err != nil {
		unix.Close(fd)
		return nil, pathError("fstat", p, err)
	}
	if typ := st.Mode & unix.S_IFMT; typ != unix.S_IFREG && !(dirs && typ == unix.S_IFDIR) {
		unix.Close(fd)
		return nil, pathError("open", p, ErrNotRegular)
	}
	// Linux ignores O_NONBLOCK on regular files, but open(2) warns that it may not
	// always: a read that fails with EAGAIN would cut a download short
	if err := unix.SetNonblock(fd, false); err != nil {
		unix.Close(fd)
		return nil, pathError("fcntl", p, err)
	}
	return os.NewFile(uintptr(fd), p), nil
}

// Check reports why this system does not let weed open files as it does (openat2,
// from Linux 5.6, which a seccomp filter may refuse)
func Check() error {
	root, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(root)
	f, err := openat(root, ".", unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("weed opens files with openat2(2), which this system refuses (it needs Linux 5.6 or later, and no seccomp filter that refuses it): %w", err)
	}
	return f.Close()
}

// FS is the exported directory, which each request opens as a Tree
type FS struct {
	Root string
	// Gate bounds the calls to the storage in progress at once, of all the trees
	// opened (nil: no bound)
	Gate *Gate
}

// Open opens the exported directory for one request. Opened for each, it is the
// directory of the moment: a storage mounted over it is seen at once, and idle
// workers keep nothing open that would keep it from being unmounted.
func (fs FS) Open(ctx context.Context) (*Tree, error) {
	if err := fs.Gate.enter(ctx); err != nil {
		return nil, err
	}
	defer fs.Gate.leave()
	fd, err := unix.Open(cmp.Or(fs.Root, "."), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: fs.Root, Err: err}
	}
	return &Tree{dir: fd, gate: fs.Gate}, nil
}

// Tree is the exported directory opened for a request (FS.Open): a webdav.FileSystem
// whose names never lead out of it. Close it at the end of the request. Each of its
// methods takes a slot of the gate for its calls to the storage; none of them calls
// another, which could wait for a slot while holding one.
type Tree struct {
	dir  int // the exported directory, O_PATH
	gate *Gate
}

// Close closes the directory; the files opened in it stay open
func (t *Tree) Close() error { return unix.Close(t.dir) }

// parent opens the directory that holds p, for the *at system calls, which act on
// the last component of a name without following it; done closes it
func (t *Tree) parent(p string) (dirfd int, base string, done func(), err error) {
	dir, base := filepath.Split(p)
	if dir == "" {
		return t.dir, base, func() {}, nil
	}
	d, err := openat(t.dir, dir, unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		return -1, "", nil, err
	}
	return int(d.Fd()), base, func() { d.Close() }, nil
}

// stat is Stat of p, in the tree; lstat that of a symbolic link itself
func (t *Tree) stat(p string, lstat bool) (os.FileInfo, error) {
	flags := unix.O_PATH
	if lstat {
		flags |= unix.O_NOFOLLOW // a symbolic link at the end is opened, not refused
	}
	f, err := openat(t.dir, p, flags, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Stat()
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

// checked is err of an operation on name: an error for a symbolic link in the name
// becomes ErrSymlink, and is logged; a permission error is noted for TrackDenied
func (t *Tree) checked(ctx context.Context, name string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.ELOOP) {
		slog.WarnContext(ctx, "refused a name with a symbolic link in it: weed follows none", "path", name)
		err = &os.PathError{Op: "open", Path: name, Err: ErrSymlink}
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
	if err := t.gate.enter(ctx); err != nil {
		return err
	}
	defer t.gate.leave()
	dirfd, base, done, err := t.parent(p)
	if err != nil {
		return err
	}
	defer done()
	return pathError("mkdirat", p, unix.Mkdirat(dirfd, base, uint32(perm.Perm())))
}

// OpenFile implements webdav.FileSystem. Writes that truncate the target go through
// an AtomicFile that is committed when closed. Opened for reading, what is neither a
// regular file nor a directory is refused (ErrNotRegular).
func (t *Tree) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (_ webdav.File, err error) {
	defer func() { err = t.checked(ctx, name, err) }()
	p, err := local(name)
	if err != nil {
		return nil, err
	}
	if err := t.gate.enter(ctx); err != nil {
		return nil, err
	}
	defer t.gate.leave()
	if flag&(os.O_WRONLY|os.O_RDWR) != 0 && flag&os.O_CREATE != 0 && flag&os.O_TRUNC != 0 {
		af, err := t.createAtomic(ctx, p, perm)
		if err != nil {
			return nil, err
		}
		return &davFile{af: af}, nil
	}
	var f *os.File
	if flag&(os.O_WRONLY|os.O_RDWR) == 0 {
		f, err = t.openRead(p, true)
	} else {
		f, err = openat(t.dir, p, flag, perm)
	}
	if err != nil {
		return nil, err
	}
	return t.file(ctx, f), nil
}

// RemoveAll implements webdav.FileSystem. A symbolic link is removed, not what it
// points to.
func (t *Tree) RemoveAll(ctx context.Context, name string) (err error) {
	defer func() { err = t.checked(ctx, name, err) }()
	p, err := local(name)
	if err != nil {
		return err
	}
	if p == "." {
		return os.ErrInvalid // never remove the exported directory itself
	}
	// One slot for all the removal: its calls follow each other, on one thread
	if err := t.gate.enter(ctx); err != nil {
		return err
	}
	defer t.gate.leave()
	dirfd, base, done, err := t.parent(p)
	if err != nil {
		return err
	}
	defer done()
	return removeAll(dirfd, base, p)
}

// removeAll removes name, in the directory dirfd, and whatever it holds, following
// no symbolic link; p is its name in the tree, for errors
func removeAll(dirfd int, name, p string) error {
	err := ignoringEINTR(func() error { return unix.Unlinkat(dirfd, name, 0) })
	if err == nil || err == unix.ENOENT {
		return nil
	}
	if err != unix.EISDIR {
		return pathError("unlinkat", p, err)
	}
	// A directory: empty it, a batch of names at a time, then remove it
	for {
		fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err == unix.ENOENT {
			return nil
		}
		if err != nil {
			return pathError("openat", p, err)
		}
		d := os.NewFile(uintptr(fd), p)
		names, readErr := d.Readdirnames(1024)
		var first error
		for _, n := range names {
			if err := removeAll(fd, n, path.Join(p, n)); err != nil && first == nil {
				first = err
			}
		}
		d.Close()
		if first != nil {
			return first
		}
		if readErr != nil && readErr != io.EOF {
			return readErr
		}
		if len(names) < 1024 {
			break
		}
	}
	err = ignoringEINTR(func() error { return unix.Unlinkat(dirfd, name, unix.AT_REMOVEDIR) })
	if err == unix.ENOENT {
		return nil
	}
	return pathError("unlinkat", p, err)
}

// Rename implements webdav.FileSystem. A symbolic link at the end of oldName is
// refused, as everywhere else; one at the end of newName is replaced (x/net/webdav
// stats it first, which refuses it).
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
	if err := t.gate.enter(ctx); err != nil {
		return err
	}
	defer t.gate.leave()
	oldDir, oldBase, done, err := t.parent(oldPath)
	if err != nil {
		return err
	}
	defer done()
	newDir, newBase, done2, err := t.parent(newPath)
	if err != nil {
		return err
	}
	defer done2()
	var st unix.Stat_t
	if unix.Fstatat(oldDir, oldBase, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return pathError("rename", oldPath, unix.ELOOP)
	}
	if err := unix.Renameat(oldDir, oldBase, newDir, newBase); err != nil {
		return &os.LinkError{Op: "renameat", Old: oldPath, New: newPath, Err: err}
	}
	return nil
}

// Stat implements webdav.FileSystem
func (t *Tree) Stat(ctx context.Context, name string) (_ os.FileInfo, err error) {
	defer func() { err = t.checked(ctx, name, err) }()
	p, err := local(name)
	if err != nil {
		return nil, err
	}
	if err := t.gate.enter(ctx); err != nil {
		return nil, err
	}
	defer t.gate.leave()
	return t.stat(p, false)
}

// Lstat is Stat, but of a symbolic link itself, at the end of name (one elsewhere in
// it is refused)
func (t *Tree) Lstat(ctx context.Context, name string) (_ os.FileInfo, err error) {
	defer func() { err = t.checked(ctx, name, err) }()
	p, err := local(name)
	if err != nil {
		return nil, err
	}
	if err := t.gate.enter(ctx); err != nil {
		return nil, err
	}
	defer t.gate.leave()
	return t.stat(p, true)
}

// Open opens name, a regular file, for reading; anything else is refused
// (ErrNotRegular), without waiting, as opening a FIFO would
func (t *Tree) Open(ctx context.Context, name string) (_ *File, err error) {
	defer func() { err = t.checked(ctx, name, err) }()
	p, err := local(name)
	if err != nil {
		return nil, err
	}
	if err := t.gate.enter(ctx); err != nil {
		return nil, err
	}
	defer t.gate.leave()
	f, err := t.openRead(p, false)
	if err != nil {
		return nil, err
	}
	return t.file(ctx, f), nil
}

// Writable reports whether this process may write name: a file it can open for
// writing, or a directory the kernel says it may write (on Linux; see fsuser)
func (t *Tree) Writable(ctx context.Context, name string) (err error) {
	defer func() { err = t.checked(ctx, name, err) }()
	p, err := local(name)
	if err != nil {
		return err
	}
	if err := t.gate.enter(ctx); err != nil {
		return err
	}
	defer t.gate.leave()
	fi, err := t.stat(p, false)
	if err != nil {
		return err
	}
	switch {
	case fi.Mode().IsRegular():
		f, err := openat(t.dir, p, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		return f.Close()
	case fi.IsDir():
		d, err := openat(t.dir, p, os.O_RDONLY, 0)
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
	*File                // the temporary file
	dir         *os.File // the directory of both, O_PATH
	tmp, target string   // in dir
	path        string   // the target's name in the tree, for errors
	done        bool
}

// CreateAtomic starts writing a new version of name. Its directory must exist.
func (t *Tree) CreateAtomic(ctx context.Context, name string, perm os.FileMode) (_ *AtomicFile, err error) {
	defer func() { err = t.checked(ctx, name, err) }()
	p, err := local(name)
	if err != nil {
		return nil, err
	}
	if err := t.gate.enter(ctx); err != nil {
		return nil, err
	}
	defer t.gate.leave()
	return t.createAtomic(ctx, p, perm)
}

func (t *Tree) createAtomic(ctx context.Context, target string, perm os.FileMode) (*AtomicFile, error) {
	fi, err := t.stat(target, false)
	switch {
	case err == nil && fi.IsDir():
		return nil, &os.PathError{Op: "open", Path: target, Err: syscall.EISDIR}
	case err == nil && fi.Mode().IsRegular():
		// Renaming over a file only needs write permission on its directory; replacing
		// it needs write permission on the file too, as writing it in place would
		f, err := openat(t.dir, target, os.O_WRONLY, 0)
		if err != nil {
			return nil, err
		}
		f.Close()
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return nil, err // e.g. a symbolic link
	}
	dirName, base := filepath.Split(target)
	dir, err := openat(t.dir, cmp.Or(dirName, "."), unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	for range 100 {
		tmp := TempPrefix + strconv.FormatUint(rand.Uint64(), 36)
		f, err := openat(int(dir.Fd()), tmp, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			dir.Close()
			return nil, err
		}
		if err := f.Chmod(perm &^ umask); err != nil {
			f.Close()
			unix.Unlinkat(int(dir.Fd()), tmp, 0)
			dir.Close()
			return nil, err
		}
		return &AtomicFile{File: t.file(ctx, f), dir: dir, tmp: tmp, target: base, path: target}, nil
	}
	dir.Close()
	return nil, &os.PathError{Op: "createtemp", Path: target, Err: fs.ErrExist}
}

// Commit flushes the data to stable storage and moves the file into place
func (a *AtomicFile) Commit() error { return a.commit(true) }

// CommitNoReplace is Commit, but fails with an error matching os.ErrExist if the
// target exists, even if it was created while the file was being written
func (a *AtomicFile) CommitNoReplace() error { return a.commit(false) }

// commit takes one slot for all its calls, however long they take, also once the
// request is cancelled: what was written is either in place or removed
func (a *AtomicFile) commit(replace bool) error {
	if a.done {
		return os.ErrClosed
	}
	a.done = true
	a.gate.enter(nil)
	defer a.gate.leave()
	defer a.dir.Close()
	dirfd := int(a.dir.Fd())
	f := a.File.f
	if err := f.Sync(); err != nil {
		f.Close()
		unix.Unlinkat(dirfd, a.tmp, 0)
		return err
	}
	if err := f.Close(); err != nil {
		unix.Unlinkat(dirfd, a.tmp, 0)
		return err
	}
	if replace {
		if err := unix.Renameat(dirfd, a.tmp, dirfd, a.target); err != nil {
			unix.Unlinkat(dirfd, a.tmp, 0)
			return &os.LinkError{Op: "renameat", Old: a.tmp, New: a.path, Err: err}
		}
	} else if err := a.linkNoReplace(dirfd); err != nil {
		unix.Unlinkat(dirfd, a.tmp, 0)
		return err
	}
	// Makes the rename durable; best effort, as the directory may not be readable
	if d, err := openat(dirfd, ".", os.O_RDONLY|unix.O_DIRECTORY, 0); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// linkNoReplace moves the file to its target unless that exists. A hard link is
// created atomically or not at all; on filesystems without hard links the check and
// the rename are separate steps.
func (a *AtomicFile) linkNoReplace(dirfd int) error {
	err := unix.Linkat(dirfd, a.tmp, dirfd, a.target, 0)
	if err == nil || err == unix.EEXIST {
		unix.Unlinkat(dirfd, a.tmp, 0)
		return pathError("linkat", a.path, err)
	}
	var st unix.Stat_t
	if unix.Fstatat(dirfd, a.target, &st, unix.AT_SYMLINK_NOFOLLOW) == nil {
		return &os.PathError{Op: "create", Path: a.path, Err: fs.ErrExist}
	}
	if err := unix.Renameat(dirfd, a.tmp, dirfd, a.target); err != nil {
		return &os.LinkError{Op: "renameat", Old: a.tmp, New: a.path, Err: err}
	}
	return nil
}

// Abort discards the upload. It is a no-op after Commit.
func (a *AtomicFile) Abort() {
	if a.done {
		return
	}
	a.done = true
	a.gate.enter(nil)
	defer a.gate.leave()
	a.File.f.Close()
	unix.Unlinkat(int(a.dir.Fd()), a.tmp, 0)
	a.dir.Close()
}

// pathError is err, unless nil, as an *os.PathError of op on p
func pathError(op, p string, err error) error {
	if err == nil {
		return nil
	}
	return &os.PathError{Op: op, Path: p, Err: err}
}

func ignoringEINTR(f func() error) error {
	for {
		if err := f(); err != unix.EINTR {
			return err
		}
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
