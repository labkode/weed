package server

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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

// The OIDC login page gives out the access tokens of a token issuer that weed accepts,
// and keeps nothing: a login in progress is in a cookie of the browser
func TestOIDCLogin(t *testing.T) {
	iss := testutil.NewIssuer(t)
	issuers := iss.WriteIssuers(tokenAudience, "/")
	var redirectURL string
	oidcConfig := func(cfg *config.Config, base string) {
		cfg.TLS = true
		cfg.TokenIssuers, cfg.TokenCAPath = issuers, iss.CAFile
		cfg.OIDCAuth, cfg.OIDCIssuer, cfg.OIDCClientID, cfg.OIDCClientSecret = true, iss.URL, "weed", "secret"
		cfg.OIDCScopes = []string{"openid", "storage.read:/", "storage.create:/up"}
		cfg.OIDCAudience = tokenAudience
		if redirectURL == "" && base != "" {
			redirectURL = base + "/oidc_redirect"
		}
		cfg.OIDCRedirectURL = redirectURL
	}
	n := newNode(t, oidcConfig)
	n.write("/f", "data")

	// The issuer gives out token for the code "c", if the client is weed and the PKCE
	// verifier matches the challenge of the login
	var mu sync.Mutex
	var challenge, token string
	iss.HandleToken(func(form url.Values) (int, any) {
		mu.Lock()
		defer mu.Unlock()
		sum := sha256.Sum256([]byte(form.Get("code_verifier")))
		if form.Get("grant_type") != "authorization_code" || form.Get("code") != "c" || form.Get("redirect_uri") != redirectURL ||
			form.Get("client_id") != "weed" || form.Get("client_secret") != "secret" || form.Get("audience") != tokenAudience ||
			base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			return 400, map[string]string{"error": "invalid_grant"}
		}
		return 200, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 3600}
	})

	browser := func() *http.Client {
		jar, _ := cookiejar.New(nil)
		return &http.Client{Jar: jar, Transport: n.ts.Client().Transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	get := func(c *http.Client, u string) (*http.Response, string) {
		t.Helper()
		resp, err := c.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
	// login starts a login in browser b, for which the issuer will give out tok
	login := func(b *http.Client, tok string) (state string) {
		t.Helper()
		resp, _ := get(b, n.ts.URL+"/auth/oidc")
		loc, err := url.Parse(resp.Header.Get("Location"))
		if resp.StatusCode != 302 || err != nil || loc.Scheme+"://"+loc.Host+loc.Path != iss.URL+"/authorize" {
			t.Fatalf("login redirect: %d %s", resp.StatusCode, resp.Header.Get("Location"))
		}
		q := loc.Query()
		if q.Get("scope") != "openid storage.read:/ storage.create:/up" || q.Get("audience") != tokenAudience ||
			q.Get("code_challenge_method") != "S256" || q.Get("client_id") != "weed" || q.Get("redirect_uri") != redirectURL {
			t.Fatalf("authorization request %v", q)
		}
		cookies := resp.Cookies()
		if len(cookies) != 1 || cookies[0].Name != "__Host-weed_oidc_login" || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Path != "/" {
			t.Fatalf("login cookie %v", cookies)
		}
		mu.Lock()
		challenge, token = q.Get("code_challenge"), tok
		mu.Unlock()
		return q.Get("state")
	}
	callback := n.ts.URL + "/oidc_redirect?code=c&state="

	// The page shows the token, which weed accepts
	tok := iss.Token(tokenAudience, "storage.read:/ storage.create:/up", map[string]interface{}{"sub": "carol"})
	b := browser()
	state := login(b, tok)
	resp, body := get(b, callback+state)
	if resp.StatusCode != 200 || !strings.Contains(body, tok) || !strings.Contains(body, "as user <strong>carol</strong>") ||
		!strings.Contains(body, "storage.create:/up") {
		t.Fatalf("callback: %d %s", resp.StatusCode, body)
	}
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("token page headers %v", resp.Header)
	}
	if resp, body := n.do("GET", "/f", "", bearer(tok)...); resp.StatusCode != 200 || body != "data" {
		t.Errorf("GET with the token: %d %q", resp.StatusCode, body)
	}

	// The login cookie is used once
	if u, _ := url.Parse(n.ts.URL); len(b.Jar.Cookies(u)) != 0 {
		t.Errorf("cookies left: %v", b.Jar.Cookies(u))
	}
	if resp, _ := get(b, callback+state); resp.StatusCode != 400 {
		t.Errorf("replayed callback: %d", resp.StatusCode)
	}

	// Login CSRF: a login started by someone else cannot be completed in this browser
	state = login(browser(), tok)
	if resp, _ := get(browser(), callback+state); resp.StatusCode != 400 {
		t.Errorf("callback without the login cookie: %d", resp.StatusCode)
	}
	b = browser()
	login(b, tok)
	if resp, _ := get(b, callback+state); resp.StatusCode != 400 {
		t.Errorf("callback with the state of another login: %d", resp.StatusCode)
	}

	// The provider's errors are only shown to the browser whose login it is, so that
	// nobody can make weed show their own text
	b = browser()
	state = login(b, tok)
	if resp, body := get(b, n.ts.URL+"/oidc_redirect?error=access_denied&error_description=No+consent&state="+state); resp.StatusCode != 401 ||
		!strings.Contains(body, "No consent") {
		t.Errorf("refused login: %d %s", resp.StatusCode, body)
	}
	if resp, body := get(browser(), n.ts.URL+"/oidc_redirect?error=x&error_description=Call+us&state=s"); resp.StatusCode != 400 ||
		strings.Contains(body, "Call us") {
		t.Errorf("forged error: %d %s", resp.StatusCode, body)
	}

	// Tokens that weed would not accept are not given out
	for _, c := range []struct {
		name, token, code string
		status            int
		reason            string
	}{
		{"wrong audience", iss.Token("https://other.test", "storage.read:/", nil), "c", 502, "audience"},
		{"no storage scopes", iss.Token(tokenAudience, "openid", nil), "c", 403, "no storage scopes"},
		{"not a JWT", "opaque-token", "c", 502, "not a JWT"},
		{"code refused", tok, "stolen", 502, "invalid_grant"},
	} {
		b := browser()
		state := login(b, c.token)
		if resp, body := get(b, n.ts.URL+"/oidc_redirect?code="+c.code+"&state="+state); resp.StatusCode != c.status ||
			!strings.Contains(body, c.reason) || strings.Contains(body, c.token) {
			t.Errorf("%s: %d %s", c.name, resp.StatusCode, body)
		}
	}

	// weed keeps nothing: behind a load balancer, another node completes the login
	other := newNode(t, oidcConfig)
	b = browser()
	state = login(b, tok)
	if resp, body := get(b, other.ts.URL+"/oidc_redirect?code=c&state="+state); resp.StatusCode != 200 || !strings.Contains(body, tok) {
		t.Errorf("login completed on another node: %d %s", resp.StatusCode, body)
	}

	// weed does not start with a provider whose tokens it would not accept
	s := New(&config.Config{Directory: t.TempDir(), TokenIssuers: testutil.NewIssuer(t).WriteIssuers(tokenAudience, "/"),
		OIDCAuth: true, OIDCIssuer: iss.URL, OIDCClientID: "weed", OIDCClientSecret: "secret", OIDCRedirectURL: redirectURL})
	t.Cleanup(s.Close)
	if err := s.Initialize(); err == nil || !strings.Contains(err.Error(), "not in tokens.issuers") {
		t.Errorf("provider that is not a token issuer: %v", err)
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
