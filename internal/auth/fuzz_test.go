package auth

import (
	"path"
	"strings"
	"testing"
	"unicode"
)

func FuzzParseGridmapLine(f *testing.F) {
	for _, s := range []string{
		`"/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=jdoe" jdoe`, `"/CN=a b" alice,bob`, "/CN=x alice", `"/CN=x"alice`,
		`"unterminated alice`, `"" alice`, "/CN=x", `"/CN=x" alice bob`, "\"/CN=x\"\t alice , bob",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		dn, user, ok := parseGridmapLine(line)
		if !ok {
			return
		}
		if dn == "" || user == "" || strings.ContainsFunc(user, unicode.IsSpace) || strings.Contains(user, ",") {
			t.Fatalf("%q: dn=%q user=%q", line, dn, user)
		}
	})
}

func FuzzPathMatches(f *testing.F) {
	for _, s := range [][2]string{
		{"/webdav/a/b", "/webdav/a"}, {"/webdav/a/../b", "/webdav/a"}, {"/webdav/ab", "/webdav/a"},
		{"/webdav/a/", "/webdav/a/"}, {"/webdav//a", "/webdav/a"}, {"/x", "/"}, {"/webdav/a/./b", "/webdav/a/"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, req, caveat string) {
		if !pathMatches(req, caveat) {
			return
		}
		// Whatever the request path, what it refers to must be inside the caveat path
		got, scope := path.Clean("/"+req), path.Clean("/"+caveat)
		if scope != "/" && got != scope && !strings.HasPrefix(got, scope+"/") {
			t.Fatalf("pathMatches(%q, %q) but %q is outside %q", req, caveat, got, scope)
		}
	})
}

// FuzzVerifyMacaroon checks that no token, however malformed, panics the verifier or
// authenticates as anything other than what the server signed
func FuzzVerifyMacaroon(f *testing.F) {
	as := NewAuthStore()
	as.MacaroonEnabled = true
	if err := as.InitializeMacaroon("0123456789abcdef0123456789abcdef", "weed"); err != nil {
		f.Fatal(err)
	}
	valid, err := as.CreateMacaroon([]string{"id:alice", "path:/webdav/a", "activity:DOWNLOAD"})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add(valid[:len(valid)/2])
	f.Add("")
	f.Add("AgEEd2VlZAI")
	f.Fuzz(func(t *testing.T, token string) {
		access := AccessRequest{Paths: []string{"/webdav/a/f"}, Activities: [][]string{{ActivityDownload}}}
		info, err := as.VerifyMacaroon(token, access)
		if err != nil {
			return
		}
		if info.Username != "alice" {
			t.Fatalf("token authenticated as %q", info.Username)
		}
		access.Paths = []string{"/webdav/b"}
		if _, err := as.VerifyMacaroon(token, access); err == nil {
			t.Fatal("token valid outside its path")
		}
	})
}
