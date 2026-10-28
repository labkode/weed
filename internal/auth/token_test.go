package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/labkode/weed/internal/testutil"
)

const testAudience = "https://weed.example.org"

func tokenStore(t *testing.T, iss *testutil.Issuer, basePath string) *AuthStore {
	t.Helper()
	as := NewAuthStore()
	as.TokenEnabled = true
	pool := x509.NewCertPool()
	pool.AddCert(iss.Certificate())
	as.SetTokenRootCAs(pool)
	issuers, err := LoadTokenIssuers(iss.WriteIssuers(testAudience, basePath))
	if err != nil {
		t.Fatal(err)
	}
	as.SetCredentials(&Credentials{TokenIssuers: issuers})
	return as
}

func TestVerifyToken(t *testing.T) {
	iss := testutil.NewIssuer(t)
	as := tokenStore(t, iss, "/")
	now := time.Now()
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	claims := func(extra map[string]interface{}) map[string]interface{} {
		c := map[string]interface{}{"iss": iss.URL, "sub": "u", "aud": testAudience, "scope": "storage.read:/",
			"exp": now.Add(time.Hour).Unix()}
		for k, v := range extra {
			c[k] = v
		}
		return c
	}
	noneToken := func() string {
		enc := base64.RawURLEncoding.EncodeToString
		payload, _ := json.Marshal(claims(nil))
		return enc([]byte(`{"alg":"none"}`)) + "." + enc(payload) + "."
	}

	for _, c := range []struct {
		name, token, err string
		forbidden        bool
	}{
		{"valid", iss.Token(testAudience, "storage.read:/", nil), "", false},
		{"EC key", iss.Sign("ec1", jose.ES256, claims(nil)), "", false},
		{"no kid tries every key", testutil.SignJWT(t, iss.Key("rsa1"), "", jose.RS256, claims(nil)), "", false},
		{"any audience", iss.Token(AudienceAny, "storage.read:/", nil), "", false},
		{"audience list", iss.Token("", "storage.read:/", map[string]interface{}{"aud": []string{"x", testAudience}}), "", false},
		{"scope as a list", iss.Token(testAudience, "", map[string]interface{}{"scope": []string{"openid", "storage.read:/"}}), "", false},
		{"other audience", iss.Token("https://other.example.org", "storage.read:/", nil), "audience", false},
		{"no audience", iss.Token("", "storage.read:/", map[string]interface{}{"aud": nil}), "audience", false},
		{"expired", iss.Token(testAudience, "storage.read:/", map[string]interface{}{"exp": now.Add(-2 * time.Minute).Unix()}), "expired", false},
		{"expiry within clock skew", iss.Token(testAudience, "storage.read:/", map[string]interface{}{"exp": now.Add(-30 * time.Second).Unix()}), "", false},
		{"no expiry", iss.Token(testAudience, "storage.read:/", map[string]interface{}{"exp": nil}), "no expiry", false},
		{"not yet valid", iss.Token(testAudience, "storage.read:/", map[string]interface{}{"nbf": now.Add(time.Hour).Unix()}), "not valid yet", false},
		{"untrusted issuer", iss.Token(testAudience, "storage.read:/", map[string]interface{}{"iss": "https://evil.example.org"}), "not trusted", false},
		{"forged with the kid of a real key", testutil.SignJWT(t, otherKey, "rsa1", jose.RS256, claims(nil)), "signature", false},
		{"unknown kid", testutil.SignJWT(t, otherKey, "rsa9", jose.RS256, claims(nil)), "no signing key", false},
		{"symmetric algorithm", testutil.SignJWT(t, []byte("0123456789abcdef0123456789abcdef"), "rsa1", jose.HS256, claims(nil)), "malformed", false},
		{"alg none", noneToken(), "malformed", false},
		{"garbage", "a.b.c", "malformed", false},
		{"no storage scopes", iss.Token(testAudience, "openid wlcg.groups", nil), "no storage scopes", true},
	} {
		v, err := as.verifyToken(c.token, now)
		switch {
		case c.err == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%s: error %v, want %q", c.name, err, c.err)
		case c.err != "" && errors.Is(err, errForbidden) != c.forbidden:
			t.Errorf("%s: forbidden = %t", c.name, errors.Is(err, errForbidden))
		case c.err == "" && len(v.grants) != 1:
			t.Errorf("%s: grants %v", c.name, v.grants)
		}
	}
}

func TestTokenKeyRefresh(t *testing.T) {
	iss := testutil.NewIssuer(t)
	as := tokenStore(t, iss, "/")
	now := time.Now()
	valid := func(kid string, at time.Time) error {
		_, err := as.verifyToken(iss.Sign(kid, jose.RS256, map[string]interface{}{
			"iss": iss.URL, "aud": testAudience, "scope": "storage.read:/", "exp": at.Add(time.Hour).Unix()}), at)
		return err
	}

	if err := valid("rsa1", now); err != nil {
		t.Fatal(err)
	}
	// Forged tokens with unknown key IDs do not make weed fetch the keys again and again
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	for i := 0; i < 20; i++ {
		tok := testutil.SignJWT(t, otherKey, "kid"+strings.Repeat("x", i), jose.RS256, map[string]interface{}{
			"iss": iss.URL, "aud": testAudience, "scope": "storage.read:/", "exp": now.Add(time.Hour).Unix()})
		if _, err := as.verifyToken(tok, now.Add(time.Duration(i)*time.Second)); err == nil {
			t.Fatal("forged token accepted")
		}
	}
	if n := iss.JWKSFetches.Load(); n != 1 {
		t.Fatalf("%d key fetches, want 1", n)
	}

	// A key added by the issuer is picked up once the refresh interval has passed
	newKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	iss.AddKey("rsa2", newKey, jose.RS256)
	if err := valid("rsa2", now.Add(30*time.Second)); err == nil {
		t.Fatal("new key used before the refresh interval")
	}
	if err := valid("rsa2", now.Add(tokenKeysMinRefresh)); err != nil {
		t.Fatalf("new key: %v", err)
	}

	// A withdrawn key stops working once the cached keys are too old
	iss.RemoveKey("rsa1")
	if err := valid("rsa1", now.Add(tokenKeysMinRefresh+time.Minute)); err != nil {
		t.Fatalf("withdrawn key, cache still fresh: %v", err)
	}
	if err := valid("rsa1", now.Add(tokenKeysMinRefresh+tokenKeysMaxAge)); err == nil {
		t.Fatal("withdrawn key accepted after the cache expired")
	}

	// If the issuer is down, the known keys keep working
	iss.Close()
	if err := valid("rsa2", now.Add(tokenKeysMinRefresh+2*tokenKeysMaxAge)); err != nil {
		t.Fatalf("issuer down: %v", err)
	}
}

func TestIssuerDiscovery(t *testing.T) {
	var issuerURL, jwksURI string
	var openIDStatus int
	mux := http.NewServeMux()
	meta := func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": issuerURL, "jwks_uri": jwksURI})
	}
	mux.HandleFunc("/vo/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if openIDStatus != 200 {
			w.WriteHeader(openIDStatus)
			return
		}
		meta(w, r)
	})
	mux.HandleFunc("/vo/.well-known/oauth-authorization-server", meta)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"keys":[{"kty":"unknown"},{"kty":"oct","k":"c2VjcmV0"},`))
		b, _ := json.Marshal(jose.JSONWebKey{Key: &key.PublicKey, KeyID: "k1", Use: "sig"})
		w.Write(b)
		b, _ = json.Marshal(jose.JSONWebKey{Key: &key.PublicKey, KeyID: "k2", Use: "enc"})
		w.Write([]byte("," + string(b) + "]}"))
	})
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	for _, c := range []struct {
		name         string
		openID       int
		issuer, jwks string
		err          string
	}{
		{"openid-configuration", 200, ts.URL + "/vo", ts.URL + "/keys", ""},
		{"oauth-authorization-server fallback", 404, ts.URL + "/vo", ts.URL + "/keys", ""},
		{"discovery error", 500, ts.URL + "/vo", ts.URL + "/keys", "500"},
		{"issuer mismatch", 200, "https://evil.example.org", ts.URL + "/keys", "discovery document is for issuer"},
		{"jwks over http", 200, ts.URL + "/vo", "http://" + ts.Listener.Addr().String() + "/keys", "invalid jwks_uri"},
	} {
		openIDStatus, issuerURL, jwksURI = c.openID, c.issuer, c.jwks
		keys, err := fetchIssuerKeys(t.Context(), ts.Client(), ts.URL+"/vo")
		switch {
		case c.err == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%s: error %v, want %q", c.name, err, c.err)
		case c.err == "" && (len(keys) != 1 || keys[0].KeyID != "k1"):
			t.Errorf("%s: keys %v (only the RSA signing key is usable)", c.name, keys)
		}
	}
}

func TestLoadTokenIssuers(t *testing.T) {
	write := func(s string) string {
		p := filepath.Join(t.TempDir(), "issuers.json")
		os.WriteFile(p, []byte(s), 0600)
		return p
	}
	issuers, err := LoadTokenIssuers(write(`[{"issuer":"https://a.example/","audiences":["x"],"base_path":"vo/../../cms/"},{"issuer":"https://b.example"}]`))
	if err != nil {
		t.Fatal(err)
	}
	if got := issuers["https://a.example/"].BasePath; got != "/cms" {
		t.Errorf("base path %q", got)
	}
	if got := issuers["https://b.example"].BasePath; got != "/" {
		t.Errorf("default base path %q", got)
	}
	for _, bad := range []string{
		`[{"issuer":"http://a.example"}]`,
		`[{"issuer":"https://a.example?x=1"}]`,
		`[{"issuer":"a.example"}]`,
		`[{"issuer":"https://a.example","audience":"x"}]`, // misspelled field
		`[{"issuer":"https://a.example","audiences":[""]}]`,
		`[{"issuer":"https://a.example"},{"issuer":"https://a.example"}]`,
		`{"issuer":"https://a.example"}`,
	} {
		if _, err := LoadTokenIssuers(write(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestParseScopes(t *testing.T) {
	got := parseScopes([]string{
		"openid", "offline_access", "storage.read:/", "storage.create:/a/b", "storage.modify:/../../etc",
		"storage.stage:/tape", "read:/s", "write:/w", "storage.read", "storage.read:relative", "compute.read",
	}, "/vo")
	want := []grant{
		{capRead, "/webdav/vo"},
		{capCreate, "/webdav/vo/a/b"},
		{capCreate | capModify, "/webdav/vo/etc"}, // cannot leave the base path
		{capRead, "/webdav/vo/tape"},
		{capRead, "/webdav/vo/s"},
		{capCreate | capModify, "/webdav/vo/w"},
		{capRead, "/webdav/vo"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestTokenAuthorization(t *testing.T) {
	type result int
	const (
		allowed result = iota
		allowedNoOverwrite
		forbidden
	)
	grants := func(scope string) []grant { return parseScopes(strings.Fields(scope), "/") }
	for _, c := range []struct {
		scope        string
		method, path string
		headers      []string
		want         result
	}{
		{"storage.read:/", "GET", "/webdav/a", nil, allowed},
		{"storage.read:/a", "GET", "/webdav/a/f", nil, allowed},
		{"storage.read:/a", "GET", "/webdav/ab", nil, forbidden},
		{"storage.read:/", "PUT", "/webdav/a", nil, forbidden},
		{"storage.read:/", "PROPFIND", "/webdav/a", []string{"Depth", "1"}, allowed},
		{"storage.create:/", "PROPFIND", "/webdav/a", []string{"Depth", "1"}, forbidden},
		{"storage.create:/", "PROPFIND", "/webdav/a", []string{"Depth", "0"}, allowed},
		{"storage.create:/", "HEAD", "/webdav/a", nil, allowed},
		{"storage.create:/", "GET", "/webdav/a", nil, forbidden},
		{"storage.create:/", "PUT", "/webdav/a", nil, allowedNoOverwrite},
		{"storage.create:/ storage.modify:/a", "PUT", "/webdav/a/f", nil, allowed},
		{"storage.modify:/", "PUT", "/webdav/a", nil, allowed},
		{"write:/", "PUT", "/webdav/a", nil, allowed},
		{"storage.create:/", "MKCOL", "/webdav/a", nil, allowed},
		{"storage.create:/", "DELETE", "/webdav/a", nil, forbidden},
		{"storage.modify:/", "DELETE", "/webdav/a", nil, allowed},
		{"storage.create:/", "PROPPATCH", "/webdav/a", nil, forbidden},
		{"storage.read:/", "OPTIONS", "/webdav/a", nil, allowed},
		{"storage.read:/", "GET", "/proc/whoami", nil, allowed},
		{"storage.read:/", "GET", "/webdav/a/../b", nil, forbidden},
		{"storage.read:/", "TRACE", "/webdav/a", nil, forbidden},
		{"storage.read:/ storage.modify:/", "POST", "/webdav/a", []string{"Content-Type", "application/macaroon-request"}, forbidden},
		{"storage.read:/", "POST", "/webdav/a", nil, allowed},
		// Third-party copies
		{"storage.create:/", "COPY", "/webdav/a", []string{"Source", "https://src.example/f"}, allowedNoOverwrite},
		{"storage.read:/", "COPY", "/webdav/a", []string{"Source", "https://src.example/f"}, forbidden},
		{"storage.read:/", "COPY", "/webdav/a", []string{"Destination", "https://dst.example/f"}, allowed},
		{"storage.create:/", "COPY", "/webdav/a", []string{"Destination", "https://dst.example/f"}, forbidden},
		// Local copies and moves
		{"storage.read:/a storage.create:/b", "COPY", "/webdav/a/f", []string{"Destination", "/webdav/b/f"}, allowedNoOverwrite},
		{"storage.read:/a storage.modify:/b", "COPY", "/webdav/a/f", []string{"Destination", "/webdav/b/f"}, allowed},
		{"storage.create:/", "COPY", "/webdav/a/f", []string{"Destination", "/webdav/b/f"}, forbidden},
		{"storage.read:/", "COPY", "/webdav/a/f", []string{"Destination", "/webdav/b/f"}, forbidden},
		{"storage.create:/", "MOVE", "/webdav/a/f", []string{"Destination", "/webdav/b/f"}, allowedNoOverwrite},
		{"storage.create:/b", "MOVE", "/webdav/a/f", []string{"Destination", "/webdav/b/f"}, forbidden},
		{"storage.modify:/", "MOVE", "/webdav/a/f", []string{"Destination", "/webdav/b/f"}, allowed},
	} {
		r := httptest.NewRequest(c.method, "https://weed.example"+c.path, nil)
		for i := 0; i+1 < len(c.headers); i += 2 {
			r.Header.Set(c.headers[i], c.headers[i+1])
		}
		var got result
		needs, err := tokenRequirements(r)
		if err == nil {
			var noOverwrite bool
			noOverwrite, err = authorizeToken(grants(c.scope), needs)
			if noOverwrite {
				got = allowedNoOverwrite
			}
		}
		if err != nil {
			got = forbidden
		}
		if got != c.want {
			t.Errorf("%q: %s %s %v = %d (%v), want %d", c.scope, c.method, c.path, c.headers, got, err, c.want)
		}
	}
}

func TestAuthenticateToken(t *testing.T) {
	iss := testutil.NewIssuer(t)
	as := tokenStore(t, iss, "/")
	as.MacaroonEnabled = true
	as.InitializeMacaroon(strings.Repeat("k", 32), "weed")
	handler := as.UnifiedAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, _ := GetAuthInfoFromContext(r.Context())
		w.Header().Set("X-User", info.Username)
		w.Header().Set("X-Method", info.Method)
	}))
	do := func(method, path, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://weed.example"+path, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	read := iss.Token(testAudience, "storage.read:/", nil)
	if w := do("GET", "/webdav/f", read); w.Code != 200 || w.Header().Get("X-User") != "token-user" || w.Header().Get("X-Method") != "token" {
		t.Fatalf("GET: %d %v", w.Code, w.Header())
	}
	if w := do("PUT", "/webdav/f", read); w.Code != 403 {
		t.Fatalf("PUT with a read token: %d", w.Code)
	}
	if w := do("GET", "/webdav/f", iss.Token("https://other", "storage.read:/", nil)); w.Code != 401 {
		t.Fatalf("wrong audience: %d", w.Code)
	}
	// Macaroons are still accepted next to tokens
	mac, err := as.CreateMacaroon([]string{"id:alice", "activity:DOWNLOAD", "before:" + time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	if w := do("GET", "/webdav/f", mac); w.Code != 200 || w.Header().Get("X-Method") != "macaroon" {
		t.Fatalf("macaroon: %d %v", w.Code, w.Header())
	}
	// With token support disabled a JWT is not accepted
	as.TokenEnabled = false
	if w := do("GET", "/webdav/f", read); w.Code != 401 {
		t.Fatalf("tokens disabled: %d", w.Code)
	}
}
