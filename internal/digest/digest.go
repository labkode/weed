// Package digest implements the HTTP digest fields used for data integrity: RFC 9530
// (Repr-Digest / Want-Repr-Digest) and the legacy RFC 3230 fields (Digest / Want-Digest)
// that WLCG clients still send.
package digest

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Algorithm names as registered for RFC 9530
const (
	Adler  = "adler"
	CRC32C = "crc32c"
	MD5    = "md5"
	SHA    = "sha"
	SHA256 = "sha-256"
	SHA512 = "sha-512"
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

var algorithms = map[string]struct {
	new  func() hash.Hash
	size int
}{
	Adler:  {func() hash.Hash { return adler32.New() }, adler32.Size},
	CRC32C: {func() hash.Hash { return crc32.New(castagnoli) }, crc32.Size},
	MD5:    {md5.New, md5.Size},
	SHA:    {sha1.New, sha1.Size},
	SHA256: {sha256.New, sha256.Size},
	SHA512: {sha512.New, sha512.Size},
}

// Canonical returns the RFC 9530 name of alg and whether it is supported.
// "adler32" is accepted as an alias of "adler", as WLCG has always used that name.
func Canonical(alg string) (string, bool) {
	a := strings.ToLower(strings.TrimSpace(alg))
	if a == "adler32" {
		a = Adler
	}
	_, ok := algorithms[a]
	return a, ok
}

// Set maps algorithm names to raw digest values
type Set map[string][]byte

// Algorithms returns the algorithms in s, sorted
func (s Set) Algorithms() []string {
	algs := make([]string, 0, len(s))
	for a := range s {
		algs = append(algs, a)
	}
	sort.Strings(algs)
	return algs
}

// ParseReprDigest parses a Repr-Digest field value (an RFC 8941 dictionary of byte
// sequences). Unsupported algorithms are returned separately so callers can ignore them.
func ParseReprDigest(v string) (supported Set, unsupported []string, err error) {
	supported = Set{}
	if strings.TrimSpace(v) == "" {
		return supported, nil, nil
	}
	for _, member := range strings.Split(v, ",") {
		member = strings.TrimSpace(member)
		if i := strings.IndexByte(member, ';'); i >= 0 {
			member = member[:i] // parameters carry no meaning for digests
		}
		key, val, ok := strings.Cut(member, "=")
		if !ok || key == "" {
			return nil, nil, fmt.Errorf("malformed digest member %q", member)
		}
		if len(val) < 2 || val[0] != ':' || val[len(val)-1] != ':' {
			return nil, nil, fmt.Errorf("digest for %q is not a byte sequence (:base64:)", key)
		}
		raw, err := base64.StdEncoding.DecodeString(val[1 : len(val)-1])
		if err != nil {
			return nil, nil, fmt.Errorf("digest for %q is not valid base64: %v", key, err)
		}
		alg, ok := Canonical(key)
		if !ok {
			unsupported = append(unsupported, key)
			continue
		}
		if len(raw) != algorithms[alg].size {
			return nil, nil, fmt.Errorf("digest for %q has %d bytes, want %d", key, len(raw), algorithms[alg].size)
		}
		if prev, dup := supported[alg]; dup && !bytes.Equal(prev, raw) {
			return nil, nil, fmt.Errorf("conflicting values for %q", alg)
		}
		supported[alg] = raw
	}
	return supported, unsupported, nil
}

// FormatReprDigest formats s as a Repr-Digest field value
func FormatReprDigest(s Set) string {
	parts := make([]string, 0, len(s))
	for _, alg := range s.Algorithms() {
		parts = append(parts, alg+"=:"+base64.StdEncoding.EncodeToString(s[alg])+":")
	}
	return strings.Join(parts, ", ")
}

// FormatWant formats a Want-Repr-Digest field value asking for algs
func FormatWant(algs []string) string {
	parts := make([]string, 0, len(algs))
	for _, alg := range algs {
		parts = append(parts, alg+"=9")
	}
	return strings.Join(parts, ", ")
}

// ParseWant parses a Want-Repr-Digest field value and returns the supported algorithms
// the client accepts, most preferred first. Malformed members are ignored.
func ParseWant(v string) []string {
	type pref struct {
		alg    string
		weight int
	}
	var prefs []pref
	for _, member := range strings.Split(v, ",") {
		key, val, _ := strings.Cut(strings.TrimSpace(member), "=")
		alg, ok := Canonical(key)
		if !ok {
			continue
		}
		weight := 1
		if val != "" {
			w, err := strconv.Atoi(strings.TrimSpace(val))
			if err != nil || w < 0 || w > 10 {
				continue
			}
			weight = w
		}
		if weight > 0 {
			prefs = append(prefs, pref{alg, weight})
		}
	}
	sort.SliceStable(prefs, func(i, j int) bool { return prefs[i].weight > prefs[j].weight })
	algs := make([]string, len(prefs))
	for i, p := range prefs {
		algs[i] = p.alg
	}
	return algs
}

// ParseWantLegacy parses an RFC 3230 Want-Digest field value (e.g. "adler32;q=0.5, md5")
// and returns the supported algorithms, most preferred first
func ParseWantLegacy(v string) []string {
	type pref struct {
		alg string
		q   float64
	}
	var prefs []pref
	for _, member := range strings.Split(v, ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(member), ";")
		alg, ok := Canonical(name)
		if !ok {
			continue
		}
		q := 1.0
		if k, val, ok := strings.Cut(strings.TrimSpace(params), "="); ok && strings.TrimSpace(k) == "q" {
			f, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
			if err != nil {
				continue
			}
			q = f
		}
		if q > 0 {
			prefs = append(prefs, pref{alg, q})
		}
	}
	sort.SliceStable(prefs, func(i, j int) bool { return prefs[i].q > prefs[j].q })
	algs := make([]string, len(prefs))
	for i, p := range prefs {
		algs[i] = p.alg
	}
	return algs
}

// FormatLegacy formats one RFC 3230 Digest field member. Checksums (adler32, crc32c) are
// hex encoded as WLCG clients expect; cryptographic hashes are base64 encoded.
func FormatLegacy(alg string, sum []byte) string {
	switch alg {
	case Adler:
		return "adler32=" + hex.EncodeToString(sum)
	case CRC32C:
		return "crc32c=" + hex.EncodeToString(sum)
	default:
		return alg + "=" + base64.StdEncoding.EncodeToString(sum)
	}
}

// Mismatch compares two sets on the algorithms they share and returns the first
// algorithm whose values differ
func Mismatch(expected, actual Set) (string, bool) {
	for _, alg := range expected.Algorithms() {
		if got, ok := actual[alg]; ok && !bytes.Equal(got, expected[alg]) {
			return alg, true
		}
	}
	return "", false
}

// Hasher computes several digests in a single pass
type Hasher struct {
	algs   []string
	hashes []hash.Hash
}

// NewHasher returns a Hasher for the given (canonical, supported) algorithms
func NewHasher(algs ...string) *Hasher {
	h := &Hasher{}
	seen := map[string]bool{}
	for _, alg := range algs {
		if a, ok := algorithms[alg]; ok && !seen[alg] {
			seen[alg] = true
			h.algs = append(h.algs, alg)
			h.hashes = append(h.hashes, a.new())
		}
	}
	return h
}

// parallelMin is the size from which several digests are computed in parallel
const parallelMin = 64 << 10

// Write feeds p to every digest
func (h *Hasher) Write(p []byte) (int, error) {
	if len(h.hashes) < 2 || len(p) < parallelMin {
		for _, hh := range h.hashes {
			hh.Write(p)
		}
		return len(p), nil
	}
	var wg sync.WaitGroup
	for _, hh := range h.hashes[1:] {
		wg.Go(func() { hh.Write(p) })
	}
	h.hashes[0].Write(p)
	wg.Wait()
	return len(p), nil
}

// Sums returns the digests of everything written so far
func (h *Hasher) Sums() Set {
	s := make(Set, len(h.algs))
	for i, alg := range h.algs {
		s[alg] = h.hashes[i].Sum(nil)
	}
	return s
}

// File returns the digests of the file at path, reusing values cached in extended
// attributes when the file has not changed since they were computed
func File(path string, algs []string) (Set, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}

	out := Set{}
	var missing []string
	for _, alg := range algs {
		if sum, ok := readCache(f, alg, fi); ok {
			out[alg] = sum
		} else {
			missing = append(missing, alg)
		}
	}
	if len(missing) == 0 {
		return out, nil
	}

	h := NewHasher(missing...)
	// Hide os.File's WriteTo so CopyBuffer uses our (larger) buffer
	if _, err := io.CopyBuffer(h, struct{ io.Reader }{f}, make([]byte, 1<<20)); err != nil {
		return nil, err
	}
	sums := h.Sums()
	// Only cache digests if the file did not change while it was being read
	if after, err := f.Stat(); err == nil && after.Size() == fi.Size() && after.ModTime().Equal(fi.ModTime()) {
		writeCache(f, sums, fi)
	}
	for alg, sum := range sums {
		out[alg] = sum
	}
	return out, nil
}

// StoreCache records digests computed while writing f so later reads are free.
// Call it after the last write; failures are ignored (the cache is best effort).
func StoreCache(f *os.File, sums Set) {
	if fi, err := f.Stat(); err == nil {
		writeCache(f, sums, fi)
	}
}

// cacheValue binds a cached digest to the file size and modification time it was computed for
func cacheValue(sum []byte, fi os.FileInfo) string {
	return fmt.Sprintf("%d:%d:%s", fi.Size(), fi.ModTime().UnixNano(), hex.EncodeToString(sum))
}

func parseCacheValue(v string, fi os.FileInfo) ([]byte, bool) {
	parts := strings.Split(v, ":")
	if len(parts) != 3 || parts[0] != strconv.FormatInt(fi.Size(), 10) || parts[1] != strconv.FormatInt(fi.ModTime().UnixNano(), 10) {
		return nil, false
	}
	sum, err := hex.DecodeString(parts[2])
	return sum, err == nil
}
