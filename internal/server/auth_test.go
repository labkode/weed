package server

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/testutil"
	"gopkg.in/macaroon.v2"
)

func TestMacaroonMintAndUse(t *testing.T) {
	n := newNode(t, nil)
	n.write("/data/f", "secret")

	tok, expiresIn := n.mint("/data/", `{"caveats":["activity:DOWNLOAD,LIST"],"validity":"PT2H"}`)
	if expiresIn <= 0 || expiresIn > 3600 {
		t.Fatalf("validity not capped at the 1h maximum: expires_in=%d", expiresIn)
	}
	bearer := "Bearer " + tok
	if resp, body := n.do("GET", "/data/f", "", "Authorization", bearer); resp.StatusCode != 200 || body != "secret" {
		t.Fatalf("GET with macaroon: %d %q", resp.StatusCode, body)
	}
	if code := n.status("PUT", "/data/f", "x", "Authorization", bearer); code != 403 {
		t.Fatalf("PUT with read-only macaroon: %d", code)
	}
	n.write("/other", "x")
	if code := n.status("GET", "/other", "", "Authorization", bearer); code != 403 {
		t.Fatalf("GET outside the path caveat: %d", code)
	}

	// Re-minting with the macaroon keeps all its restrictions
	again, againExpires := n.mint("/data/f", `{"caveats":[]}`, "Authorization", bearer)
	if againExpires > expiresIn {
		t.Fatalf("re-minted macaroon outlives the original: %d > %d", againExpires, expiresIn)
	}
	if code := n.status("DELETE", "/data/f", "", "Authorization", "Bearer "+again); code != 403 {
		t.Fatalf("DELETE with re-minted macaroon: %d", code)
	}
	if code := n.status("GET", "/data/f", "", "Authorization", "Bearer "+again); code != 200 {
		t.Fatalf("GET with re-minted macaroon: %d", code)
	}

	// whoami works with any valid macaroon and shows its identity
	if _, body := n.do("GET", n.ts.URL+"/proc/whoami", "", "Authorization", bearer); !strings.Contains(body, "Username: alice") {
		t.Fatalf("whoami: %s", body)
	}
}

func TestMacaroonMintRejections(t *testing.T) {
	n := newNode(t, nil)
	for _, req := range []string{
		`{"caveats":["id:root"]}`,
		`{"caveats":["activity:EVERYTHING"]}`,
		`{"caveats":["color:blue"]}`,
		`{"validity":"forever"}`,
		`not json`,
	} {
		resp, _ := n.do("POST", "/", req, "Content-Type", "application/macaroon-request")
		if resp.StatusCode != 400 {
			t.Errorf("mint %s: %d", req, resp.StatusCode)
		}
	}
	// Unauthenticated
	resp, _ := n.do("POST", "/", `{}`, "Content-Type", "application/macaroon-request", "Authorization", "none")
	if resp.StatusCode != 401 {
		t.Fatalf("anonymous mint: %d", resp.StatusCode)
	}
}

func TestMacaroonMoveCannotEscapePath(t *testing.T) {
	n := newNode(t, nil)
	n.write("/a/f", "x")
	os.Mkdir(filepath.Join(n.dir, "b"), 0755)
	tok, _ := n.mint("/a/", `{"caveats":[]}`)
	for _, dst := range []string{n.url("/b/escaped"), "/webdav/a/../b/escaped"} {
		if code := n.status("MOVE", "/a/f", "", "Authorization", "Bearer "+tok, "Destination", dst); code != 403 {
			t.Fatalf("MOVE to %s: %d", dst, code)
		}
	}
	if _, ok := n.read("/b/escaped"); ok {
		t.Fatal("file moved outside the macaroon path")
	}
	if code := n.status("MOVE", "/a/f", "", "Authorization", "Bearer "+tok, "Destination", n.url("/a/g")); code != 201 {
		t.Fatalf("MOVE inside the path: %d", code)
	}
}

func TestMacaroonsDisabled(t *testing.T) {
	n := newNode(t, func(cfg *config.Config, _ string) { cfg.MacaroonAuth = false })
	n.write("/f", "x")

	// With macaroons disabled there is no key; a token "signed" with the empty key
	// must not authenticate
	m, _ := macaroon.New(nil, []byte("x"), "weed", macaroon.LatestVersion)
	m.AddFirstPartyCaveat([]byte("id:root"))
	b, _ := m.MarshalBinary()
	if code := n.status("GET", "/f", "", "Authorization", "Bearer "+base64.StdEncoding.EncodeToString(b)); code != 401 {
		t.Fatalf("forged macaroon: %d", code)
	}
	resp, _ := n.do("POST", "/", `{}`, "Content-Type", "application/macaroon-request")
	if resp.StatusCode != 501 {
		t.Fatalf("mint with macaroons disabled: %d", resp.StatusCode)
	}
}

// Without a configuration file weed serves local clients without credentials
func TestAnonymous(t *testing.T) {
	n := newNode(t, func(cfg *config.Config, _ string) { cfg.Anonymous, cfg.Address = true, "127.0.0.1" })
	anonymous := []string{"Authorization", "none"}

	if code := n.status("PUT", "/f", "data", anonymous...); code != 201 {
		t.Fatalf("anonymous PUT: %d", code)
	}
	if code := n.status("MKCOL", "/d", "", anonymous...); code != 201 {
		t.Fatalf("anonymous MKCOL: %d", code)
	}
	if resp, body := n.do("GET", "/f", "", anonymous...); resp.StatusCode != 200 || body != "data" {
		t.Fatalf("anonymous GET: %d %q", resp.StatusCode, body)
	}
	if _, body := n.do("GET", n.ts.URL+"/proc/whoami", "", anonymous...); !strings.Contains(body, "Username: anonymous") {
		t.Fatalf("whoami: %s", body)
	}
	// Credentials that an enabled method rejects are refused, not served anonymously
	if code := n.status("GET", "/f", "", "Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:wrong"))); code != 401 {
		t.Fatalf("wrong password: %d", code)
	}
	if code := n.status("GET", "/f", "", "Authorization", "Bearer not-a-token"); code != 401 {
		t.Fatalf("invalid bearer token: %d", code)
	}
	if _, body := n.do("GET", n.ts.URL+"/proc/whoami", ""); !strings.Contains(body, "Username: alice") {
		t.Fatalf("whoami with a password: %s", body)
	}

	// Not without it
	n = newNode(t, nil)
	if code := n.status("GET", "/", "", anonymous...); code != 401 {
		t.Fatalf("without anonymous: %d", code)
	}
}

func TestX509WithProxiesAndGridmap(t *testing.T) {
	ca := testutil.NewCA(t, testutil.Name(t, "DC=ch", "DC=cern", "CN=Test CA"))
	subject := testutil.Name(t, "DC=ch", "DC=cern", "OU=Organic Units", "OU=Users", "CN=gonzalhu")
	user := testutil.NewUser(t, ca, subject, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	proxy := testutil.NewProxy(t, user, true, time.Now().Add(time.Hour))

	gridmap := filepath.Join(t.TempDir(), "grid-mapfile")
	os.WriteFile(gridmap, []byte(`"/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=gonzalhu" gonzalhu`+"\n"), 0600)

	n := newNode(t, func(cfg *config.Config, _ string) {
		cfg.TLS = true
		cfg.X509Auth = true
		cfg.CACert = writePEM(t, ca.Cert.Raw)
		cfg.GridmapFile = gridmap
	})

	get := func(c *http.Client, p string) (int, string) {
		resp, err := c.Get(n.ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	for name, cert := range map[string]*http.Client{
		"user certificate": clientWithCert(n, testutil.TLS(user)),
		"proxy chain":      clientWithCert(n, testutil.TLS(proxy, user)),
	} {
		code, body := get(cert, "/proc/whoami")
		if code != 200 || !strings.Contains(body, "Username: gonzalhu") {
			t.Fatalf("%s: %d %s", name, code, body)
		}
		if code, _ := get(cert, "/auth/x509"); code != 200 {
			t.Fatalf("%s: /auth/x509 = %d", name, code)
		}
	}

	rogueCA := testutil.NewCA(t, testutil.Name(t, "CN=Rogue"))
	rogue := clientWithCert(n, testutil.TLS(testutil.NewUser(t, rogueCA, subject, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))))
	if code, _ := get(rogue, "/auth/x509"); code != 401 {
		t.Fatalf("untrusted certificate on /auth/x509: %d", code)
	}
	if code, _ := get(rogue, "/webdav/"); code != 401 {
		t.Fatalf("untrusted certificate on /webdav/: %d", code)
	}

	// A certificate from a trusted CA is refused unless the grid-mapfile lists its DN
	other := testutil.NewUser(t, ca, testutil.Name(t, "DC=ch", "DC=cern", "CN=someone"), time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	unmapped := clientWithCert(n, testutil.TLS(testutil.NewProxy(t, other, true, time.Now().Add(time.Hour)), other))
	for _, p := range []string{"/webdav/", "/auth/x509"} {
		if code, _ := get(unmapped, p); code != 403 {
			t.Fatalf("unmapped certificate on %s: %d", p, code)
		}
	}
	if _, body := get(unmapped, "/proc/x509"); !strings.Contains(body, "Would FAIL (not in the grid-mapfile)") {
		t.Fatalf("/proc/x509 for an unmapped certificate: %s", body)
	}
	// Other credentials sent along still apply
	n.write("/f", "data")
	req, _ := http.NewRequest("GET", n.ts.URL+"/webdav/f", nil)
	req.SetBasicAuth(basicUser, basicPass)
	if resp, err := unmapped.Do(req); err != nil || resp.StatusCode != 200 {
		t.Fatalf("unmapped certificate with a password: %v %v", resp, err)
	} else {
		resp.Body.Close()
	}

	// Removing the DN from the grid-mapfile revokes access on reload
	os.WriteFile(gridmap, []byte("# nobody\n"), 0600)
	n.srv.Reload()
	if code, _ := get(clientWithCert(n, testutil.TLS(user)), "/webdav/"); code != 403 {
		t.Fatalf("certificate removed from the grid-mapfile: %d", code)
	}
}

// fakeIdP is a minimal OpenID provider
type fakeIdP struct {
	*httptest.Server
	key   *rsa.PrivateKey
	mu    sync.Mutex
	nonce string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &fakeIdP{key: key}
	mux := http.NewServeMux()
	idp.Server = httptest.NewServer(mux)
	t.Cleanup(idp.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                                idp.URL,
			"authorization_endpoint":                idp.URL + "/authorize",
			"token_endpoint":                        idp.URL + "/token",
			"jwks_uri":                              idp.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		idp.mu.Lock()
		nonce := idp.nonce
		idp.mu.Unlock()
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
		claims, _ := json.Marshal(map[string]interface{}{
			"iss": idp.URL, "sub": "1234", "aud": "weed", "nonce": nonce,
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
			"preferred_username": "carol",
		})
		jws, _ := signer.Sign(claims)
		idToken, _ := jws.CompactSerialize()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "at", "token_type": "Bearer", "id_token": idToken})
	})
	return idp
}

func TestOIDCLogin(t *testing.T) {
	idp := newFakeIdP(t)
	n := newNode(t, func(cfg *config.Config, base string) {
		cfg.OIDCAuth = true
		cfg.OIDCIssuer = idp.URL
		cfg.OIDCClientID = "weed"
		cfg.OIDCClientSecret = "secret"
		cfg.OIDCRedirectURL = base + "/oidc_redirect"
	})

	browser := func() *http.Client {
		jar, _ := cookiejar.New(nil)
		return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	get := func(c *http.Client, p string) *http.Response {
		resp, err := c.Get(n.ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp
	}
	startLogin := func(c *http.Client) (state, nonce string) {
		resp := get(c, "/auth/oidc")
		loc, err := url.Parse(resp.Header.Get("Location"))
		if resp.StatusCode != 302 || err != nil || !strings.HasPrefix(loc.String(), idp.URL+"/authorize") {
			t.Fatalf("login redirect: %d %s", resp.StatusCode, resp.Header.Get("Location"))
		}
		return loc.Query().Get("state"), loc.Query().Get("nonce")
	}
	setNonce := func(nonce string) {
		idp.mu.Lock()
		idp.nonce = nonce
		idp.mu.Unlock()
	}

	b := browser()
	state, nonce := startLogin(b)
	setNonce(nonce)
	if resp := get(b, "/oidc_redirect?code=c&state="+state); resp.StatusCode != 302 {
		t.Fatalf("callback: %d", resp.StatusCode)
	}
	u, _ := url.Parse(n.ts.URL)
	for _, c := range b.Jar.Cookies(u) {
		if c.Name == "oidc_session" && c.Value == state {
			t.Fatal("session cookie is the OAuth state, which appears in URLs and logs")
		}
	}
	resp, err := b.Get(n.ts.URL + "/proc/whoami")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "Username: carol") {
		t.Fatalf("whoami after login: %s", body)
	}

	// The state is single use
	if resp := get(b, "/oidc_redirect?code=c&state="+state); resp.StatusCode != 400 {
		t.Fatalf("replayed callback: %d", resp.StatusCode)
	}

	// Login CSRF: a login started by an attacker cannot be completed in a victim's browser
	attacker := browser()
	state, nonce = startLogin(attacker)
	setNonce(nonce)
	if resp := get(browser(), "/oidc_redirect?code=c&state="+state); resp.StatusCode != 400 {
		t.Fatalf("callback without the state cookie: %d", resp.StatusCode)
	}

	// An ID token that does not carry this login's nonce is rejected
	b = browser()
	state, _ = startLogin(b)
	setNonce("someone-else")
	if resp := get(b, "/oidc_redirect?code=c&state="+state); resp.StatusCode != 401 {
		t.Fatalf("callback with wrong nonce: %d", resp.StatusCode)
	}
}

func TestMacaroonPathCannotBeEscapedWithEncodedDots(t *testing.T) {
	n := newNode(t, nil)
	n.write("/a/f", "mine")
	n.write("/b/secret", "not yours")
	tok, _ := n.mint("/a/", `{"caveats":[]}`)
	bearer := "Bearer " + tok

	for _, p := range []string{"/a/%2e%2e/b/secret", "/a/%2E%2E/b/secret", "/a/.%2e/b/secret", "/a/%2e%2e%2fb/secret"} {
		if resp, body := n.do("GET", n.url(p), "", "Authorization", bearer); resp.StatusCode < 400 || strings.Contains(body, "not yours") {
			t.Errorf("GET %s with a macaroon for /webdav/a/: %d %q", p, resp.StatusCode, body)
		}
	}
	// Unencoded dot segments are cleaned (and redirected) by ServeMux, so they stay in scope
	if resp, body := n.do("GET", n.url("/a/./f"), "", "Authorization", bearer); resp.StatusCode != 200 || body != "mine" {
		t.Errorf("GET /a/./f: %d %q", resp.StatusCode, body)
	}
	if code := n.status("PUT", n.url("/a/%2e%2e/b/planted"), "x", "Authorization", bearer); code < 400 {
		t.Errorf("PUT through encoded dots: %d", code)
	}
	if _, ok := n.read("/b/planted"); ok {
		t.Error("file planted outside the macaroon path")
	}
}
