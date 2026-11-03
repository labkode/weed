package davfs

import (
	"context"
	"io/fs"
	"os"
	"strings"

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
// links. Tree.List lists without allocating for each entry.
func (f *File) Readdir(count int) ([]os.FileInfo, error) {
	if err := f.gate.enter(f.ctx); err != nil {
		return nil, err
	}
	defer f.gate.leave()
	for {
		fis, err := f.f.Readdir(count)
		kept := fis[:0]
		for _, fi := range fis {
			if !strings.HasPrefix(fi.Name(), TempPrefix) && fi.Mode()&fs.ModeSymlink == 0 {
				kept = append(kept, fi)
			}
		}
		// With count > 0 an empty result must carry an error; keep reading instead
		if count <= 0 || len(kept) > 0 || err != nil {
			return kept, err
		}
	}
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
