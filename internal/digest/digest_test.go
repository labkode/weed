package digest

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"hash/adler32"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

var data = []byte("hello, world\n")

func adlerOf(b []byte) []byte {
	h := adler32.New()
	h.Write(b)
	return h.Sum(nil)
}

func md5Of(b []byte) []byte {
	s := md5.Sum(b)
	return s[:]
}

func TestParseReprDigest(t *testing.T) {
	a := base64.StdEncoding.EncodeToString(adlerOf(data))
	m := base64.StdEncoding.EncodeToString(md5Of(data))

	set, unsupported, err := ParseReprDigest("adler32=:" + a + ":, MD5=:" + m + ":;param=1, unixsum=:AAAA:")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(set[Adler], adlerOf(data)) || !bytes.Equal(set[MD5], md5Of(data)) {
		t.Fatalf("parsed %v", set)
	}
	if !reflect.DeepEqual(unsupported, []string{"unixsum"}) {
		t.Fatalf("unsupported = %v", unsupported)
	}

	// Round trip
	again, _, err := ParseReprDigest(FormatReprDigest(set))
	if err != nil || !reflect.DeepEqual(again, set) {
		t.Fatalf("round trip: %v %v", again, err)
	}
}

func TestParseReprDigestRejectsMalformed(t *testing.T) {
	for _, v := range []string{
		"adler",                                // no value
		"adler=1234",                           // not a byte sequence
		"adler=:!!!:",                          // not base64
		"adler=:1234:",                         // 3 bytes, adler32 has 4
		"adler=:AAAAAA==:, adler32=:AQEBAQ==:", // conflicting values for the same algorithm
	} {
		if _, _, err := ParseReprDigest(v); err == nil {
			t.Errorf("ParseReprDigest(%q) succeeded", v)
		}
	}
}

func TestParseWant(t *testing.T) {
	if got := ParseWant("sha-256=3, adler=9, md5=0, bogus=10, sha-512=x"); !reflect.DeepEqual(got, []string{Adler, SHA256}) {
		t.Fatalf("ParseWant = %v", got)
	}
	if got := ParseWantLegacy("md5;q=0.3, ADLER32, sha-256;q=0"); !reflect.DeepEqual(got, []string{Adler, MD5}) {
		t.Fatalf("ParseWantLegacy = %v", got)
	}
}

func TestFormatLegacy(t *testing.T) {
	if got := FormatLegacy(Adler, []byte{0x0a, 0x1b, 0x2c, 0x3d}); got != "adler32=0a1b2c3d" {
		t.Fatalf("adler32: %s", got)
	}
	if got := FormatLegacy(MD5, md5Of(data)); got != "md5="+base64.StdEncoding.EncodeToString(md5Of(data)) {
		t.Fatalf("md5: %s", got)
	}
}

func TestMismatch(t *testing.T) {
	exp := Set{Adler: adlerOf(data), MD5: md5Of(data)}
	if _, bad := Mismatch(exp, Set{Adler: adlerOf(data)}); bad {
		t.Fatal("matching digest reported as mismatch")
	}
	if alg, bad := Mismatch(exp, Set{MD5: md5Of([]byte("other"))}); !bad || alg != MD5 {
		t.Fatalf("mismatch not detected: %s %v", alg, bad)
	}
}

func TestHasher(t *testing.T) {
	h := NewHasher(Adler, MD5, Adler, "bogus")
	h.Write(data[:5])
	h.Write(data[5:])
	sums := h.Sums()
	if len(sums) != 2 || !bytes.Equal(sums[Adler], adlerOf(data)) || !bytes.Equal(sums[MD5], md5Of(data)) {
		t.Fatalf("sums = %v", sums)
	}
}

func TestStored(t *testing.T) {
	stored := func(p string, algs ...string) (Set, error) {
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return Stored(f, algs)
	}
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, data, 0644); err != nil {
		t.Fatal(err)
	}
	// Digests are not computed on reads
	if sums, err := stored(p, Adler); err != nil || len(sums) != 0 {
		t.Fatalf("Stored before Store = %x, %v", sums, err)
	}

	f, _ := os.OpenFile(p, os.O_WRONLY, 0)
	Store(f, Set{Adler: adlerOf(data), MD5: md5Of(data)})
	f.Close()
	sums, err := stored(p, MD5, SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if len(sums) == 0 {
		t.Skip("extended attributes not supported on this filesystem")
	}
	if !reflect.DeepEqual(sums, Set{MD5: md5Of(data)}) {
		t.Fatalf("Stored = %x, want only md5", sums)
	}

	// Rewritten behind weed's back, keeping size and mtime, the file keeps its digests
	fi, _ := os.Stat(p)
	os.WriteFile(p, bytes.ToUpper(data), 0644)
	os.Chtimes(p, fi.ModTime(), fi.ModTime())
	if sums, _ := stored(p, Adler); !bytes.Equal(sums[Adler], adlerOf(data)) {
		t.Errorf("Stored with the same size and mtime = %x", sums)
	}
	// Any change to them makes them stale
	os.Chtimes(p, fi.ModTime().Add(time.Second), fi.ModTime().Add(time.Second))
	if sums, _ := stored(p, Adler, MD5); len(sums) != 0 {
		t.Errorf("stale digests returned after the file changed: %x", sums)
	}
	if _, err := stored(filepath.Dir(p), Adler); err == nil {
		t.Error("digests of a directory")
	}
}
