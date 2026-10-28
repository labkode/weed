package digest

import (
	"reflect"
	"testing"
)

func FuzzParseReprDigest(f *testing.F) {
	for _, s := range []string{
		"adler=:AAAAAQ==:", "adler32=:AAAAAQ==:, md5=:1B2M2Y8AsgTpgAmY7PhCfg==:", "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpZWZG3hSuFU=:;p=1",
		"unixsum=:AAAA:", "adler=1234", "adler=:AAAAAQ==:, adler32=:AAAAAg==:", "", ",", "a=:",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		set, _, err := ParseReprDigest(s)
		if err != nil || len(set) == 0 {
			return
		}
		for alg, sum := range set {
			if c, ok := Canonical(alg); !ok || c != alg {
				t.Fatalf("%q: non-canonical algorithm %q in result", s, alg)
			}
			if len(sum) == 0 {
				t.Fatalf("%q: empty digest for %s", s, alg)
			}
		}
		formatted := FormatReprDigest(set)
		again, unsupported, err := ParseReprDigest(formatted)
		if err != nil || len(unsupported) > 0 || !reflect.DeepEqual(set, again) {
			t.Fatalf("%q -> %q does not round trip: %v %v %v", s, formatted, again, unsupported, err)
		}
	})
}

func FuzzParseWant(f *testing.F) {
	for _, s := range []string{"adler=9", "sha-256=1, md5=9", "md5=0", "adler32;q=0.5, md5", "md5;q=0", "x=99, adler=-1", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, algs := range [][]string{ParseWant(s), ParseWantLegacy(s)} {
			for _, alg := range algs {
				if c, ok := Canonical(alg); !ok || c != alg {
					t.Fatalf("%q: returned %q", s, alg)
				}
			}
		}
	})
}
