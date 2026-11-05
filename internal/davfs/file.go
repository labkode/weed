package davfs

import (
	"context"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// File is a file of a Tree. Each of its calls to the storage takes a slot of the
// tree's Gate for that call alone: a download holds one while it reads, not while it
// waits for its client. It does not embed *os.File, which would promote ReadFrom and
// WriteTo, letting io.Copy bypass Read and Write.
type File struct {
	f    *os.File
	gate *Gate
	ctx  context.Context // of the request that opened it
}

func (t *Tree) file(ctx context.Context, f *os.File) *File {
	return &File{f: f, gate: t.gate, ctx: ctx}
}

// Name is the file's name in the tree
func (f *File) Name() string { return f.f.Name() }

func (f *File) Read(p []byte) (int, error) {
	if err := f.gate.enter(f.ctx); err != nil {
		return 0, err
	}
	defer f.gate.leave()
	return f.f.Read(p)
}

func (f *File) ReadAt(p []byte, off int64) (int, error) {
	if err := f.gate.enter(f.ctx); err != nil {
		return 0, err
	}
	defer f.gate.leave()
	return f.f.ReadAt(p, off)
}

func (f *File) Write(p []byte) (int, error) {
	if err := f.gate.enter(f.ctx); err != nil {
		return 0, err
	}
	defer f.gate.leave()
	return f.f.Write(p)
}

func (f *File) WriteAt(p []byte, off int64) (int, error) {
	if err := f.gate.enter(f.ctx); err != nil {
		return 0, err
	}
	defer f.gate.leave()
	return f.f.WriteAt(p, off)
}

// Seek takes a slot too: on NFS, seeking from the end asks the server for the size
func (f *File) Seek(offset int64, whence int) (int64, error) {
	if err := f.gate.enter(f.ctx); err != nil {
		return 0, err
	}
	defer f.gate.leave()
	return f.f.Seek(offset, whence)
}

func (f *File) Stat() (os.FileInfo, error) {
	if err := f.gate.enter(f.ctx); err != nil {
		return nil, err
	}
	defer f.gate.leave()
	return f.f.Stat()
}

// Sync flushes the file to stable storage, also once its request is cancelled
func (f *File) Sync() error {
	f.gate.enter(nil)
	defer f.gate.leave()
	return f.f.Sync()
}

// Close closes the file, also once its request is cancelled (on NFS, closing a file
// asks the server)
func (f *File) Close() error {
	f.gate.enter(nil)
	defer f.gate.leave()
	return f.f.Close()
}

// Readdir implements webdav.File. It leaves out in-progress uploads and symbolic
// links, and the names removed since the directory was read. Tree.List lists without
// allocating for each entry.
//
// It stats each name relative to the directory (fstatat), rather than with
// os.File.Readdir: up to Go 1.26.0, that stats f.Name()+"/"+name, a path, which is
// the name in the tree, not in the process's file system, so that a listing missed
// every entry, or stated another file, following its symbolic links.
func (f *File) Readdir(count int) ([]os.FileInfo, error) {
	if err := f.gate.enter(f.ctx); err != nil {
		return nil, err
	}
	defer f.gate.leave()
	for {
		names, err := f.f.Readdirnames(count)
		fis := make([]os.FileInfo, 0, len(names))
		for _, name := range names {
			if strings.HasPrefix(name, TempPrefix) {
				continue
			}
			fi := &statInfo{name: name}
			serr := ignoringEINTR(func() error {
				return unix.Fstatat(int(f.f.Fd()), name, &fi.st, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT)
			})
			if serr == unix.ENOENT {
				continue
			}
			if serr != nil {
				return fis, pathError("fstatat", path.Join(f.f.Name(), name), serr)
			}
			if fi.Mode()&fs.ModeSymlink == 0 {
				fis = append(fis, fi)
			}
		}
		// With count > 0 an empty result must carry an error; keep reading instead
		if count <= 0 || len(fis) > 0 || err != nil {
			return fis, err
		}
	}
}

// statInfo is the os.FileInfo of a name in a directory, as fstatat(2) gives it; Sys
// is its *unix.Stat_t
type statInfo struct {
	name string
	st   unix.Stat_t
}

func (s *statInfo) Name() string       { return s.name }
func (s *statInfo) Size() int64        { return s.st.Size }
func (s *statInfo) ModTime() time.Time { return time.Unix(s.st.Mtim.Unix()) }
func (s *statInfo) IsDir() bool        { return s.Mode().IsDir() }
func (s *statInfo) Sys() any           { return &s.st }

// Mode is as os.Lstat makes it
func (s *statInfo) Mode() fs.FileMode {
	m := fs.FileMode(s.st.Mode & 0o777)
	switch s.st.Mode & unix.S_IFMT {
	case unix.S_IFBLK:
		m |= fs.ModeDevice
	case unix.S_IFCHR:
		m |= fs.ModeDevice | fs.ModeCharDevice
	case unix.S_IFDIR:
		m |= fs.ModeDir
	case unix.S_IFIFO:
		m |= fs.ModeNamedPipe
	case unix.S_IFLNK:
		m |= fs.ModeSymlink
	case unix.S_IFSOCK:
		m |= fs.ModeSocket
	}
	if s.st.Mode&unix.S_ISGID != 0 {
		m |= fs.ModeSetgid
	}
	if s.st.Mode&unix.S_ISUID != 0 {
		m |= fs.ModeSetuid
	}
	if s.st.Mode&unix.S_ISVTX != 0 {
		m |= fs.ModeSticky
	}
	return m
}

// Getxattr reads the extended attribute attr into dest
func (f *File) Getxattr(attr string, dest []byte) (int, error) {
	if err := f.gate.enter(f.ctx); err != nil {
		return 0, err
	}
	defer f.gate.leave()
	return unix.Fgetxattr(int(f.f.Fd()), attr, dest)
}

// Setxattr sets the extended attribute attr to data
func (f *File) Setxattr(attr string, data []byte) error {
	if err := f.gate.enter(f.ctx); err != nil {
		return err
	}
	defer f.gate.leave()
	return unix.Fsetxattr(int(f.f.Fd()), attr, data, 0)
}
