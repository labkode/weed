package digest

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"hash/adler32"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
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

func TestFileUsesCacheOnlyWhileFileIsUnchanged(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, data, 0644); err != nil {
		t.Fatal(err)
	}
	sums, err := File(p, []string{Adler})
	if err != nil || !bytes.Equal(sums[Adler], adlerOf(data)) {
		t.Fatalf("File = %x, %v", sums[Adler], err)
	}

	// Rewrite the content behind the cache's back, keeping size and mtime
	fi, _ := os.Stat(p)
	other := bytes.ToUpper(data)
	os.WriteFile(p, other, 0644)
	os.Chtimes(p, fi.ModTime(), fi.ModTime())
	sums, _ = File(p, []string{Adler})
	cached := bytes.Equal(sums[Adler], adlerOf(data))
	if (runtime.GOOS == "linux" || runtime.GOOS == "darwin") && !cached {
		t.Log("extended attributes not supported on this filesystem; cache not exercised")
	}

	// Any change to the modification time invalidates the cache
	os.Chtimes(p, fi.ModTime().Add(time.Second), fi.ModTime().Add(time.Second))
	sums, _ = File(p, []string{Adler})
	if !bytes.Equal(sums[Adler], adlerOf(other)) {
		t.Fatalf("stale cached digest returned after the file changed")
	}
}
