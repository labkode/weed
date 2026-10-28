package worker

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
)

// executableBuild identifies the build of the running executable, so that the front
// process only lets workers serve if they run the same build as itself. Workers are
// started from /proc/self/exe, the front process's own executable even if it has
// been replaced on disk since, but an executable overwritten in place is a different
// build in the same file.
//
// The identity is the Go build ID, which the linker derives from the binary's
// content, or, for binaries linked without one (-ldflags=-buildid=), the SHA-256 of
// the file.
func executableBuild() (string, error) {
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if ef, err := elf.NewFile(f); err == nil {
		if id := goBuildID(ef); id != "" {
			return "go:" + id, nil
		}
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

// goBuildID returns the Go build ID of an executable, or "" if it has none. It is in
// an ELF note named "Go" of type 4, in section .note.go.buildid.
func goBuildID(f *elf.File) string {
	sec := f.Section(".note.go.buildid")
	if sec == nil {
		return ""
	}
	data, err := sec.Data()
	if err != nil {
		return ""
	}
	id, err := parseGoNote(data, f.ByteOrder)
	if err != nil {
		return ""
	}
	return id
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
