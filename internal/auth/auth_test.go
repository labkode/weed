package auth

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/macaroon.v2"
)

const testKey = "0123456789abcdef0123456789abcdef"

func macaroonStore(t *testing.T) *AuthStore {
	t.Helper()
	as := NewAuthStore()
	if err := as.InitializeMacaroon(testKey, "weed"); err != nil {
		t.Fatal(err)
	}
	as.MacaroonEnabled = true
	return as
}

func mint(t *testing.T, as *AuthStore, caveats ...string) string {
	t.Helper()
	tok, err := as.CreateMacaroon(caveats)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// attenuate appends caveats the way any token holder can, without the root key
func attenuate(t *testing.T, tok string, caveats ...string) string {
	t.Helper()
	b, _ := base64.StdEncoding.DecodeString(tok)
	m := &macaroon.Macaroon{}
	if err := m.UnmarshalBinary(b); err != nil {
		t.Fatal(err)
	}
	for _, c := range caveats {
		m.AddFirstPartyCaveat([]byte(c))
	}
	b, _ = m.MarshalBinary()
	return base64.StdEncoding.EncodeToString(b)
}

func request(method, target string, headers ...string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	return r
}

func verify(t *testing.T, as *AuthStore, tok string, r *http.Request) (*AuthInfo, error) {
	t.Helper()
	access, err := RequestAccess(r)
	if err != nil {
		return nil, err
	}
	return as.VerifyMacaroon(tok, access)
}

func TestMacaroonIdentityCannotBeChanged(t *testing.T) {
	as := macaroonStore(t)
	tok := mint(t, as, "id:alice", "path:/webdav/")

	info, err := verify(t, as, tok, request("GET", "/webdav/f"))
	if err != nil || info.Username != "alice" {
		t.Fatalf("verify = %v, %v", info, err)
	}
	if _, err := verify(t, as, attenuate(t, tok, "id:admin"), request("GET", "/webdav/f")); err == nil {
		t.Fatal("holder-added id caveat changed the identity")
	}
	// Restating the same identity is harmless
	if info, err := verify(t, as, attenuate(t, tok, "id:alice"), request("GET", "/webdav/f")); err != nil || info.Username != "alice" {
		t.Fatalf("restated id: %v, %v", info, err)
	}
}

func TestMacaroonForgeryWithEmptyKey(t *testing.T) {
	// A server without macaroon support has no key; a macaroon "signed" with the
	// empty key must not authenticate anyone
	forged, err := macaroon.New(nil, []byte("x"), "weed", macaroon.LatestVersion)
	if err != nil {
		t.Fatal(err)
	}
	forged.AddFirstPartyCaveat([]byte("id:root"))
	b, _ := forged.MarshalBinary()
	tok := base64.StdEncoding.EncodeToString(b)

	as := NewAuthStore()
	as.BasicEnabled = true
	if _, err := as.VerifyMacaroon(tok, AccessRequest{}); err == nil {
		t.Fatal("forged macaroon verified without a key")
	}
	r := request("GET", "/webdav/f", "Authorization", "Bearer "+tok)
	if info, err := as.authenticateMacaroon(r); info != nil || err != nil {
		t.Fatalf("macaroon auth attempted while disabled: %v %v", info, err)
	}

	// And with macaroons enabled, a token signed with another key fails
	as = macaroonStore(t)
	if _, err := as.VerifyMacaroon(tok, AccessRequest{}); err == nil {
		t.Fatal("macaroon signed with the wrong key verified")
	}
}

func TestMacaroonCaveats(t *testing.T) {
	as := macaroonStore(t)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)

	cases := []struct {
		name    string
		caveats []string
		req     *http.Request
		ok      bool
	}{
		{"download allowed", []string{"activity:DOWNLOAD"}, request("GET", "/webdav/a"), true},
		{"download does not allow upload", []string{"activity:DOWNLOAD"}, request("PUT", "/webdav/a"), false},
		{"list allows HEAD", []string{"activity:LIST"}, request("HEAD", "/webdav/a"), true},
		{"list allows PROPFIND", []string{"activity:list"}, request("PROPFIND", "/webdav/a"), true},
		{"download does not allow PROPFIND", []string{"activity:DOWNLOAD"}, request("PROPFIND", "/webdav/a"), false},
		{"manage allows MKCOL", []string{"activity:MANAGE"}, request("MKCOL", "/webdav/d"), true},
		{"delete", []string{"activity:DELETE"}, request("DELETE", "/webdav/a"), true},
		{"unknown activity", []string{"activity:EVERYTHING"}, request("GET", "/webdav/a"), false},
		{"two activity caveats intersect", []string{"activity:DOWNLOAD,UPLOAD", "activity:DOWNLOAD"}, request("PUT", "/webdav/a"), false},
		{"pull needs upload", []string{"activity:UPLOAD"}, request("COPY", "/webdav/a", "Source", "https://remote/f"), true},
		{"pull with download only", []string{"activity:DOWNLOAD"}, request("COPY", "/webdav/a", "Source", "https://remote/f"), false},
		{"push needs download", []string{"activity:DOWNLOAD"}, request("COPY", "/webdav/a", "Destination", "https://remote/f"), true},
		{"local copy needs download and upload", []string{"activity:DOWNLOAD"}, request("COPY", "/webdav/a", "Destination", "/webdav/b"), false},
		{"local copy with both", []string{"activity:DOWNLOAD,UPLOAD"}, request("COPY", "/webdav/a", "Destination", "/webdav/b"), true},
		{"move needs manage", []string{"activity:MANAGE"}, request("MOVE", "/webdav/a", "Destination", "/webdav/b"), true},
		{"minting needs no activity", []string{"activity:DOWNLOAD"}, request("POST", "/webdav/a", "Content-Type", "application/macaroon-request"), true},
		{"other POST is a download", []string{"activity:UPLOAD"}, request("POST", "/webdav/a"), false},
		{"path below caveat", []string{"path:/webdav/dir"}, request("GET", "/webdav/dir/f"), true},
		{"path caveat with slash allows the collection", []string{"path:/webdav/dir/"}, request("PROPFIND", "/webdav/dir"), true},
		{"sibling with common prefix", []string{"path:/webdav/dir"}, request("GET", "/webdav/dirx/f"), false},
		{"move destination outside path", []string{"path:/webdav/a/"}, request("MOVE", "/webdav/a/f", "Destination", "/webdav/b/f"), false},
		{"copy destination escaping with dots", []string{"path:/webdav/a/"}, request("COPY", "/webdav/a/f", "Destination", "/webdav/a/../b/f"), false},
		{"move inside path", []string{"path:/webdav/a/"}, request("MOVE", "/webdav/a/f", "Destination", "http://example.com/webdav/a/g"), true},
		{"not expired", []string{"before:" + future}, request("GET", "/webdav/a"), true},
		{"expired", []string{"before:" + past}, request("GET", "/webdav/a"), false},
		{"ip allowed", []string{"ip:192.0.2.0/24"}, request("GET", "/webdav/a"), true},
		{"ip not allowed", []string{"ip:198.51.100.7"}, request("GET", "/webdav/a"), false},
		{"unknown caveat fails closed", []string{"color:blue"}, request("GET", "/webdav/a"), false},
		{"whoami only needs identity", []string{"path:/webdav/a", "activity:UPLOAD"}, request("GET", "/proc/whoami"), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tok := mint(t, as, append([]string{"id:alice"}, c.caveats...)...)
			_, err := verify(t, as, tok, c.req)
			if (err == nil) != c.ok {
				t.Fatalf("verify ok=%v err=%v, want ok=%v", err == nil, err, c.ok)
			}
		})
	}
}

func TestMacaroonErrorsDistinguishForbidden(t *testing.T) {
	as := macaroonStore(t)
	tok := mint(t, as, "id:alice", "activity:DOWNLOAD")
	_, err := verify(t, as, tok, request("PUT", "/webdav/a"))
	if !errors.Is(err, errForbidden) {
		t.Fatalf("restricted token: want forbidden, got %v", err)
	}
	_, err = as.VerifyMacaroon(tok[:len(tok)-8]+"AAAAAAA=", AccessRequest{})
	if err == nil || errors.Is(err, errForbidden) {
		t.Fatalf("corrupted token: want unauthorized, got %v", err)
	}
}

func TestValidateCaveat(t *testing.T) {
	for _, ok := range []string{"activity:DOWNLOAD,LIST", "path:/webdav/a", "before:2030-01-01T00:00:00Z", "ip:10.0.0.0/8,::1"} {
		if err := ValidateCaveat(ok); err != nil {
			t.Errorf("ValidateCaveat(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"id:admin", "activity:ROOT", "path:relative", "before:tomorrow", "ip:nowhere", "color:blue", "nocolon"} {
		if err := ValidateCaveat(bad); err == nil {
			t.Errorf("ValidateCaveat(%q) accepted", bad)
		}
	}
}

func TestUnifiedAuthStatusCodes(t *testing.T) {
	as := macaroonStore(t)
	as.BasicEnabled = true
	as.PrepareBasicAuth()
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	as.Htpasswd["alice"] = string(hash)

	h := as.UnifiedAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, _ := GetAuthInfoFromContext(r.Context())
		w.Write([]byte(info.Username))
	}))
	serve := func(r *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	r := request("GET", "/webdav/a")
	r.SetBasicAuth("alice", "pw")
	if w := serve(r); w.Code != 200 || w.Body.String() != "alice" {
		t.Fatalf("basic: %d %s", w.Code, w.Body)
	}

	r = request("GET", "/webdav/a")
	r.SetBasicAuth("alice", "wrong")
	if w := serve(r); w.Code != 401 || len(w.Header().Values("WWW-Authenticate")) != 2 {
		t.Fatalf("bad password: %d %v", w.Code, w.Header())
	}

	ro := mint(t, as, "id:alice", "activity:DOWNLOAD")
	if w := serve(request("PUT", "/webdav/a", "Authorization", "Bearer "+ro)); w.Code != 403 {
		t.Fatalf("restricted macaroon: %d", w.Code)
	}
	if w := serve(request("GET", "/webdav/a", "Authorization", "bearer "+ro)); w.Code != 200 {
		t.Fatalf("lower-case bearer scheme: %d", w.Code)
	}
}

func TestBasicCredentials(t *testing.T) {
	as := NewAuthStore()
	as.PrepareBasicAuth()
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	as.Htpasswd["bob"] = string(hash)
	token := strings.Repeat("ab", 32)
	as.AppTokens[token] = "bob"

	if ok, method, _ := as.VerifyCredentialsWithMethod("bob", "secret"); !ok || method != "password" {
		t.Fatal("password rejected")
	}
	if ok, method, _ := as.VerifyCredentialsWithMethod("bob", token); !ok || method != "app-token" {
		t.Fatal("app token rejected")
	}
	if ok, _, _ := as.VerifyCredentialsWithMethod("eve", token); ok {
		t.Fatal("app token accepted for another user")
	}
	if ok, _, _ := as.VerifyCredentialsWithMethod("nobody", "secret"); ok {
		t.Fatal("unknown user accepted")
	}
}

func TestLoadGridmap(t *testing.T) {
	p := filepath.Join(t.TempDir(), "grid-mapfile")
	os.WriteFile(p, []byte(`# comment
"/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=gonzalhu/CN=756361/CN=Hugo Gonzalez Labrador" gonzalhu
"/C=US/O=Test Org/CN=Test Client"   testuser,other
/CN=unquoted plain
"/CN=broken
`), 0600)
	as := NewAuthStore()
	if err := as.LoadGridmap(p); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=gonzalhu/CN=756361/CN=Hugo Gonzalez Labrador": "gonzalhu",
		"/C=US/O=Test Org/CN=Test Client": "testuser",
		"/CN=unquoted":                    "plain",
	}
	if len(as.Gridmap) != len(want) {
		t.Fatalf("gridmap = %v", as.Gridmap)
	}
	for dn, u := range want {
		if as.Gridmap[dn] != u {
			t.Errorf("gridmap[%q] = %q, want %q", dn, as.Gridmap[dn], u)
		}
	}
}

func TestOIDCLoginsAndSessions(t *testing.T) {
	as := NewAuthStore()
	state, nonce, err := as.StartOIDCLogin()
	if err != nil {
		t.Fatal(err)
	}
	if n, ok := as.FinishOIDCLogin(state); !ok || n != nonce {
		t.Fatal("login not found")
	}
	if _, ok := as.FinishOIDCLogin(state); ok {
		t.Fatal("state accepted twice")
	}

	id, err := as.CreateOIDCSession("carol", time.Hour)
	if err != nil || id == state {
		t.Fatalf("session id %q, %v", id, err)
	}
	if s, ok := as.GetOIDCSession(id); !ok || s.Username != "carol" {
		t.Fatal("session not found")
	}
	expired, _ := as.CreateOIDCSession("dave", -time.Second)
	if _, ok := as.GetOIDCSession(expired); ok {
		t.Fatal("expired session accepted")
	}
}

func TestOIDCStoreIsConcurrencySafe(t *testing.T) {
	as := NewAuthStore()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			state, _, _ := as.StartOIDCLogin()
			as.FinishOIDCLogin(state)
			id, _ := as.CreateOIDCSession("u", time.Hour)
			as.GetOIDCSession(id)
		}()
	}
	wg.Wait()
}
