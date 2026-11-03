package davfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"path"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Entry is an entry of a directory, with the metadata of its file
type Entry struct {
	Name []byte // valid until the next batch of its Lister
	Dir  bool
	Size int64
	// The modification time, since the epoch
	MtimeSec, MtimeNsec int64
}

// Lister lists a directory a batch at a time (Tree.List): a getdents64 of the
// directory, then a statx of each name in it, relative to the directory. Its batches
// reuse the same memory, and take the names from what getdents64 read: listing
// allocates nothing for each entry.
type Lister struct {
	fd   int
	path string // in the tree, for errors
	gate *Gate
	ctx  context.Context
	b    *listBuffers
	eof  bool
}

type listBuffers struct {
	dirents [32 << 10]byte
	stx     unix.Statx_t
	entries []Entry
}

var listBuffersPool = sync.Pool{New: func() any { return new(listBuffers) }}

var tempPrefix = []byte(TempPrefix)

// statxMask is what a listing needs of each entry
const statxMask = unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_SIZE | unix.STATX_MTIME

// List opens the directory name to list it; close the Lister after
func (t *Tree) List(ctx context.Context, name string) (_ *Lister, err error) {
	defer func() { err = t.checked(ctx, name, err) }()
	p, err := local(name)
	if err != nil {
		return nil, err
	}
	if err := t.gate.enter(ctx); err != nil {
		return nil, err
	}
	defer t.gate.leave()
	fd, err := openat2fd(t.dir, p, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	return &Lister{fd: fd, path: p, gate: t.gate, ctx: ctx, b: listBuffersPool.Get().(*listBuffers)}, nil
}

// Next returns the next entries of the directory, at least one, or io.EOF once there
// are no more. It leaves out in-progress uploads and symbolic links, and the entries
// removed since the directory was read. The entries, and their names, are valid until
// the next call, or Close. An error ends the listing; it comes with the entries read
// before it.
func (l *Lister) Next() ([]Entry, error) {
	if l.eof {
		return nil, io.EOF
	}
	if err := l.gate.enter(l.ctx); err != nil {
		return nil, err
	}
	defer l.gate.leave()
	b := l.b
	entries := b.entries[:0] // kept, grown, in b.entries for the next batches
	for len(entries) == 0 {
		n, err := getdents(l.fd, b.dirents[:])
		if err != nil {
			l.eof = true
			return nil, pathError("getdents64", l.path, err)
		}
		if n == 0 {
			l.eof = true
			return nil, io.EOF
		}
		for buf := b.dirents[:n]; len(buf) >= direntName; {
			reclen := int(binary.NativeEndian.Uint16(buf[direntReclen:]))
			if reclen <= direntName || reclen > len(buf) {
				break // never from the kernel
			}
			rec := buf[:reclen]
			buf = buf[reclen:]
			name := rec[direntName:]
			if i := bytes.IndexByte(name, 0); i >= 0 {
				name = name[:i]
			}
			if len(name) == 0 || rec[direntType] == unix.DT_LNK || isDot(name) || bytes.HasPrefix(name, tempPrefix) {
				continue
			}
			// The name is followed by a NUL in rec: statx reads it there
			err := statx(l.fd, &rec[direntName], &b.stx)
			if err == unix.ENOENT {
				continue
			}
			if err != nil {
				l.eof = true
				b.entries = entries[:0]
				return entries, pathError("statx", path.Join(l.path, string(name)), err)
			}
			mode := uint32(b.stx.Mode) & unix.S_IFMT
			if mode == unix.S_IFLNK {
				continue // on filesystems whose getdents64 does not say
			}
			entries = append(entries, Entry{Name: name, Dir: mode == unix.S_IFDIR, Size: int64(b.stx.Size),
				MtimeSec: b.stx.Mtime.Sec, MtimeNsec: int64(b.stx.Mtime.Nsec)})
		}
	}
	b.entries = entries[:0]
	return entries, nil
}

// Close closes the directory; the entries of the last batch are no longer valid
func (l *Lister) Close() error {
	if l.b == nil {
		return nil
	}
	err := unix.Close(l.fd)
	listBuffersPool.Put(l.b)
	l.b = nil
	return err
}

// The fields of a struct linux_dirent64: d_ino, d_off (8 bytes each), d_reclen (2),
// d_type (1), then d_name, ended by a NUL
const (
	direntReclen = 16
	direntType   = 18
	direntName   = 19
)

func isDot(name []byte) bool {
	return len(name) == 1 && name[0] == '.' || len(name) == 2 && name[0] == '.' && name[1] == '.'
}

func getdents(fd int, buf []byte) (int, error) {
	for {
		n, err := unix.Getdents(fd, buf)
		if err != unix.EINTR {
			return n, err
		}
	}
}

// statx is statx(2) of the NUL-terminated name at name, in the directory dirfd,
// following no symbolic link nor automount. It takes the name where it is, rather
// than a string that unix.Statx would copy.
func statx(dirfd int, name *byte, stx *unix.Statx_t) error {
	for {
		_, _, errno := unix.Syscall6(unix.SYS_STATX, uintptr(dirfd), uintptr(unsafe.Pointer(name)),
			unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT, statxMask, uintptr(unsafe.Pointer(stx)), 0)
		switch errno {
		case 0:
			return nil
		case unix.EINTR:
			continue
		}
		return errno
	}
}
