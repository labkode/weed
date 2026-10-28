package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Issuer is a token issuer serving OpenID discovery and its keys (JWKS) over TLS
type Issuer struct {
	*httptest.Server
	// URL is the issuer, as it appears in iss claims
	URL string
	// CAFile holds the certificate of the server, to trust when fetching keys
	CAFile string
	// JWKSFetches counts requests for the keys
	JWKSFetches atomic.Int64

	t         *testing.T
	mu        sync.Mutex
	published []jose.JSONWebKey
	keys      map[string]interface{} // kid -> private key
}

// NewIssuer starts an issuer with an RSA key "rsa1" and an EC key "ec1"
func NewIssuer(t *testing.T) *Issuer {
	t.Helper()
	iss := &Issuer{t: t, keys: make(map[string]interface{})}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": iss.URL, "jwks_uri": iss.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		iss.JWKSFetches.Add(1)
		iss.mu.Lock()
		defer iss.mu.Unlock()
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: iss.published})
	})
	iss.Server = httptest.NewTLSServer(mux)
	t.Cleanup(iss.Server.Close)
	iss.URL = iss.Server.URL

	iss.CAFile = filepath.Join(t.TempDir(), "issuer-ca.pem")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: iss.Server.Certificate().Raw})
	if err := os.WriteFile(iss.CAFile, pemData, 0600); err != nil {
		t.Fatal(err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	iss.AddKey("rsa1", rsaKey, jose.RS256)
	iss.AddKey("ec1", ecKey, jose.ES256)
	return iss
}

// AddKey publishes the public part of key under kid
func (iss *Issuer) AddKey(kid string, key interface{}, alg jose.SignatureAlgorithm) {
	iss.mu.Lock()
	defer iss.mu.Unlock()
	iss.keys[kid] = key
	jwk := jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: string(alg), Use: "sig"}
	pub := jwk.Public()
	iss.published = append(iss.published, pub)
}

// RemoveKey withdraws kid from the published keys; tokens can still be signed with it
func (iss *Issuer) RemoveKey(kid string) {
	iss.mu.Lock()
	defer iss.mu.Unlock()
	for i, k := range iss.published {
		if k.KeyID == kid {
			iss.published = append(iss.published[:i], iss.published[i+1:]...)
			return
		}
	}
}

// Key returns the private key with ID kid
func (iss *Issuer) Key(kid string) interface{} {
	iss.mu.Lock()
	defer iss.mu.Unlock()
	return iss.keys[kid]
}

// Token returns a token signed with the RSA key, issued by iss, valid for an hour,
// with the given audience and scope; extra claims are added or override these
func (iss *Issuer) Token(aud, scope string, extra map[string]interface{}) string {
	now := time.Now()
	claims := map[string]interface{}{
		"iss":      iss.URL,
		"sub":      "token-user",
		"aud":      aud,
		"scope":    scope,
		"iat":      now.Unix(),
		"nbf":      now.Unix(),
		"exp":      now.Add(time.Hour).Unix(),
		"wlcg.ver": "1.0",
	}
	for k, v := range extra {
		if v == nil {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}
	return iss.Sign("rsa1", jose.RS256, claims)
}

// Sign signs claims with key kid
func (iss *Issuer) Sign(kid string, alg jose.SignatureAlgorithm, claims interface{}) string {
	iss.t.Helper()
	return SignJWT(iss.t, iss.Key(kid), kid, alg, claims)
}

// SignJWT signs claims with key, putting kid (if not empty) in the header
func SignJWT(t *testing.T, key interface{}, kid string, alg jose.SignatureAlgorithm, claims interface{}) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if kid != "" {
		opts = opts.WithHeader("kid", kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// WriteIssuers writes a tokens.issuers file trusting iss with the given audience and
// base path, and any extra settings (such as "users")
func (iss *Issuer) WriteIssuers(audience, basePath string, extra ...map[string]interface{}) string {
	iss.t.Helper()
	p := filepath.Join(iss.t.TempDir(), "issuers.json")
	entry := map[string]interface{}{"issuer": iss.URL, "audiences": []string{audience}, "base_path": basePath}
	for _, e := range extra {
		for k, v := range e {
			entry[k] = v
		}
	}
	data, _ := json.Marshal([]map[string]interface{}{entry})
	if err := os.WriteFile(p, data, 0600); err != nil {
		iss.t.Fatal(err)
	}
	return p
}
