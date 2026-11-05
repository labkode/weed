package findlimits

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/crypto/bcrypt"

	"github.com/labkode/weed/internal/x509utils"
)

// The credentials of the weed that weed limits runs, made for it alone in its work
// directory: a CA, weed's host certificate, the account's certificate, an empty CRL,
// a grid-mapfile, a password, and tokens from an issuer that weed limits serves

// keySpec is the kind of a key: "RSA" of Bits, "ECDSA" of Curve, or "Ed25519"
type keySpec struct {
	Kind  string
	Bits  int
	Curve elliptic.Curve
}

func (k keySpec) String() string {
	switch k.Kind {
	case "RSA":
		return fmt.Sprintf("RSA %d", k.Bits)
	case "ECDSA":
		return "ECDSA " + k.Curve.Params().Name
	}
	return k.Kind
}

var defaultHostKey = keySpec{Kind: "RSA", Bits: 2048}

// hostKeyOf is the kind of the key of the certificate in file, the first of a PEM
// file: weed's own, which weed limits's weed gets a key of the same kind as, since
// its signature is most of the cost of a new connection
func hostKeyOf(file string) (keySpec, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return keySpec{}, err
	}
	for {
		var block *pem.Block
		if block, b = pem.Decode(b); block == nil {
			return keySpec{}, fmt.Errorf("%s: no certificate", file)
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return keySpec{}, fmt.Errorf("%s: %w", file, err)
		}
		switch k := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			return keySpec{Kind: "RSA", Bits: k.N.BitLen()}, nil
		case *ecdsa.PublicKey:
			return keySpec{Kind: "ECDSA", Curve: k.Curve}, nil
		case ed25519.PublicKey:
			return keySpec{Kind: "Ed25519"}, nil
		}
		return keySpec{}, fmt.Errorf("%s: a key of an unknown kind", file)
	}
}

func newKey(k keySpec) (crypto.Signer, error) {
	switch k.Kind {
	case "RSA":
		return rsa.GenerateKey(rand.Reader, k.Bits)
	case "ECDSA":
		return ecdsa.GenerateKey(k.Curve, rand.Reader)
	case "Ed25519":
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return key, err
	}
	return nil, fmt.Errorf("unknown key kind %q", k.Kind)
}

// creds are the credentials, and the files they are in
type creds struct {
	dir                  string
	caCert               *x509.Certificate
	caKey                crypto.Signer
	host                 tls.Certificate
	caFile, crlFile      string
	hostCert, hostKey    string
	userCert, userKey    string
	gridmap              string
	htpasswd, appTokens  string
	password, appToken   string
	bcryptCost           int
	userDN               string
	hostKeySpec          keySpec
	issuer               *issuer // nil without tokens
	issuers, tokenFile   string
	audience, tokenScope string
}

var serial = time.Now().UnixNano()

// nextSerial is a serial number of a certificate that no other of the CA has
func nextSerial() *big.Int {
	serial++
	return big.NewInt(serial)
}

// newCreds makes the credentials of account in dir: a host key of hostKey, bcrypt
// hashes of cost, and with tokens, an issuer
func newCreds(dir, account string, hostKey keySpec, cost int, tokens bool) (*creds, error) {
	c := &creds{dir: dir, hostKeySpec: hostKey, bcryptCost: cost}
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: "weed limits CA", Organization: []string{"weed"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(7 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		return nil, err
	}
	if c.caCert, err = x509.ParseCertificate(der); err != nil {
		return nil, err
	}
	c.caKey = caKey
	c.caFile = filepath.Join(dir, "ca.pem")
	if err := writePEM(c.caFile, 0o644, "CERTIFICATE", der); err != nil {
		return nil, err
	}

	// An empty CRL, which crl_mode = "require" needs
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(7 * 24 * time.Hour),
	}, c.caCert, caKey)
	if err != nil {
		return nil, err
	}
	c.crlFile = filepath.Join(dir, "crl.pem")
	if err := writePEM(c.crlFile, 0o644, "X509 CRL", crl); err != nil {
		return nil, err
	}

	// weed's host certificate, for 127.0.0.1 and localhost (the issuer's)
	key, err := newKey(hostKey)
	if err != nil {
		return nil, err
	}
	der, err = c.issue(key.Public(), pkix.Name{CommonName: "localhost", Organization: []string{"weed"}},
		x509.ExtKeyUsageServerAuth, []string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback})
	if err != nil {
		return nil, err
	}
	c.hostCert, c.hostKey = filepath.Join(dir, "host.pem"), filepath.Join(dir, "host.key")
	if err := writeCertKey(c.hostCert, c.hostKey, der, key); err != nil {
		return nil, err
	}
	if c.host, err = tls.LoadX509KeyPair(c.hostCert, c.hostKey); err != nil {
		return nil, err
	}

	// The account's certificate, which the grid-mapfile maps to it
	userKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	der, err = c.issue(userKey.Public(), pkix.Name{CommonName: account, OrganizationalUnit: []string{"weed limits"}, Organization: []string{"weed"}},
		x509.ExtKeyUsageClientAuth, nil, nil)
	if err != nil {
		return nil, err
	}
	c.userCert, c.userKey = filepath.Join(dir, "user.pem"), filepath.Join(dir, "user.key")
	if err := writeCertKey(c.userCert, c.userKey, der, userKey); err != nil {
		return nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	c.userDN = x509utils.GetDNParts(cert)
	c.gridmap = filepath.Join(dir, "grid-mapfile")
	if err := os.WriteFile(c.gridmap, fmt.Appendf(nil, "%q %s\n", c.userDN, account), 0o644); err != nil {
		return nil, err
	}

	// A password, hashed as those of weed's htpasswd file are, and an app token, as
	// weed utils token makes them
	pw := make([]byte, 16)
	rand.Read(pw)
	c.password = hex.EncodeToString(pw)
	hash, err := bcrypt.GenerateFromPassword([]byte(c.password), cost)
	if err != nil {
		return nil, err
	}
	c.htpasswd, c.appTokens = filepath.Join(dir, "htpasswd"), filepath.Join(dir, "app-tokens")
	if err := os.WriteFile(c.htpasswd, fmt.Appendf(nil, "%s:%s\n", account, hash), 0o600); err != nil {
		return nil, err
	}
	tok := make([]byte, 32)
	rand.Read(tok)
	c.appToken = hex.EncodeToString(tok)
	if err := os.WriteFile(c.appTokens, fmt.Appendf(nil, "%s:%s\n", c.appToken, account), 0o600); err != nil {
		return nil, err
	}

	if tokens {
		if c.issuer, err = startIssuer(c.host); err != nil {
			return nil, err
		}
		c.audience = "weed-limits"
		c.tokenScope = "storage.read:/ storage.modify:/ storage.create:/"
		c.issuers = filepath.Join(dir, "issuers.json")
		rules := fmt.Sprintf(`[{"issuer": %q, "audiences": [%q], "base_path": "/", "users": [{"sub": %q, "user": %q}]}]`+"\n",
			c.issuer.url, c.audience, account, account)
		if err := os.WriteFile(c.issuers, []byte(rules), 0o644); err != nil {
			return nil, err
		}
		tok, err := c.issuer.mint(account, c.audience, c.tokenScope, 7*24*time.Hour)
		if err != nil {
			return nil, err
		}
		c.tokenFile = filepath.Join(dir, "token")
		if err := os.WriteFile(c.tokenFile, []byte(tok+"\n"), 0o600); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// issue makes a certificate of the CA
func (c *creds) issue(pub crypto.PublicKey, subject pkix.Name, use x509.ExtKeyUsage, dns []string, ips []net.IP) ([]byte, error) {
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject:      subject,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(7 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{use},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	return x509.CreateCertificate(rand.Reader, tmpl, c.caCert, pub, c.caKey)
}

func (c *creds) close() {
	if c != nil && c.issuer != nil {
		c.issuer.close()
	}
}

func writePEM(file string, perm os.FileMode, typ string, der []byte) error {
	return os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), perm)
}

func writeCertKey(certFile, keyFile string, der []byte, key crypto.Signer) error {
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := writePEM(certFile, 0o644, "CERTIFICATE", der); err != nil {
		return err
	}
	return writePEM(keyFile, 0o600, "PRIVATE KEY", kder)
}

// bcryptCostOf is the cost of the first bcrypt hash of an htpasswd file, as its
// users' passwords cost weed that much to check; bcrypt.DefaultCost without one
func bcryptCostOf(file string) int {
	b, err := os.ReadFile(file)
	if err != nil {
		return bcrypt.DefaultCost
	}
	for line := range strings.Lines(string(b)) {
		if _, hash, ok := strings.Cut(strings.TrimSpace(line), ":"); ok {
			if cost, err := bcrypt.Cost([]byte(hash)); err == nil {
				return cost
			}
		}
	}
	return bcrypt.DefaultCost
}

// --- The token issuer

// issuer is a WLCG token issuer: OpenID discovery and its signing key, over TLS on a
// port of 127.0.0.1, at https://localhost:port
type issuer struct {
	url string
	key *rsa.PrivateKey
	srv *http.Server
}

const issuerKeyID = "weed-limits"

func startIssuer(host tls.Certificate) (*issuer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	is := &issuer{url: fmt.Sprintf("https://localhost:%d", ln.Addr().(*net.TCPAddr).Port), key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer": %q, "jwks_uri": %q, "id_token_signing_alg_values_supported": ["RS256"]}`, is.url, is.url+"/jwks")
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: key.Public(), KeyID: issuerKeyID, Algorithm: string(jose.RS256), Use: "sig"},
		}})
	})
	is.srv = &http.Server{Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{host}}, ReadHeaderTimeout: 10 * time.Second}
	go is.srv.Serve(tls.NewListener(ln, is.srv.TLSConfig))
	return is, nil
}

// mint returns a WLCG token of sub for aud, with scope, valid for lifetime
func (is *issuer) mint(sub, aud, scope string, lifetime time.Duration) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: is.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", issuerKeyID))
	if err != nil {
		return "", err
	}
	now := time.Now()
	jti := make([]byte, 16)
	rand.Read(jti)
	return jwt.Signed(signer).Claims(map[string]any{
		"iss": is.url, "sub": sub, "aud": []string{aud}, "scope": scope,
		"iat": now.Unix(), "nbf": now.Add(-time.Minute).Unix(), "exp": now.Add(lifetime).Unix(),
		"jti": hex.EncodeToString(jti), "wlcg.ver": "1.0",
	}).Serialize()
}

func (is *issuer) close() { is.srv.Close() }
