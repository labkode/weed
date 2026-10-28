package version

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
)

// ExecutableBuild identifies the build of the running executable (see Build). On
// Linux it is read from /proc/self/exe, the running binary even if it has been
// replaced on disk since.
func ExecutableBuild() (string, error) {
	path := "/proc/self/exe"
	if runtime.GOOS != "linux" {
		p, err := os.Executable()
		if err != nil {
			return "", err
		}
		path = p
	}
	return Build(path)
}

// Build identifies the executable at path: by its Go build ID ("go:<id>"), which the
// linker derives from the binary's content, or, for binaries linked without one
// (-ldflags=-buildid=), by the SHA-256 of the file ("sha256:<hex>"). Two executables
// with the same build are the same binary.
func Build(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if id := goBuildID(f); id != "" {
		return "go:" + id, nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// goBuildID returns the Go build ID of an executable, or "" if it has none. ELF
// executables have it in a note; Mach-O and PE ones at the start of their text.
func goBuildID(f io.ReaderAt) string {
	if ef, err := elf.NewFile(f); err == nil {
		sec := ef.Section(".note.go.buildid")
		if sec == nil {
			return ""
		}
		data, err := sec.Data()
		if err != nil {
			return ""
		}
		id, _ := parseGoNote(data, ef.ByteOrder)
		return id
	}
	if mf, err := macho.NewFile(f); err == nil {
		if sec := mf.Section("__text"); sec != nil {
			return markedBuildID(sec)
		}
		return ""
	}
	if pf, err := pe.NewFile(f); err == nil {
		if sec := pf.Section(".text"); sec != nil {
			return markedBuildID(sec)
		}
	}
	return ""
}

// parseGoNote decodes an ELF note holding a Go build ID: the sizes of its name and
// description and its type, then the name and the description, each padded to 4 bytes
func parseGoNote(data []byte, order interface{ Uint32([]byte) uint32 }) (string, error) {
	if len(data) < 12 {
		return "", errors.New("short note")
	}
	nameSize, descSize, typ := uint64(order.Uint32(data)), uint64(order.Uint32(data[4:])), order.Uint32(data[8:])
	desc := 12 + (nameSize+3)&^3
	if typ != 4 || desc+descSize > uint64(len(data)) || strings.TrimRight(string(data[12:12+nameSize]), "\x00") != "Go" {
		return "", errors.New("not a Go build ID note")
	}
	return string(data[desc : desc+descSize]), nil
}

// markedBuildID reads the build ID that the Go linker puts at the start of text:
// \xff Go build ID: "<id>"\n \xff
func markedBuildID(r io.ReaderAt) string {
	const prefix, suffix = "\xff Go build ID: \"", "\"\n \xff"
	b := make([]byte, 1024)
	n, _ := r.ReadAt(b, 0)
	b, ok := bytes.CutPrefix(b[:n], []byte(prefix))
	if !ok {
		return ""
	}
	id, _, ok := bytes.Cut(b, []byte(suffix))
	if !ok {
		return ""
	}
	return string(id)
}
