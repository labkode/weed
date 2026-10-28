// Command issuer is a WLCG token issuer for the interoperability tests: it serves
// OpenID discovery and its signing key over TLS, and mints tokens.
//
//	issuer serve -url https://localhost:8446 -signing-key key.pem -cert host.pem -key host.key
//	issuer mint -url https://localhost:8446 -signing-key key.pem -aud AUD -scope SCOPE [-groups G] [-lifetime 1h]
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const keyID = "interop"

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: issuer serve|mint [flags]")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	issuer := fs.String("url", "", "issuer URL")
	keyFile := fs.String("signing-key", "", "PEM private key (RSA)")
	cert := fs.String("cert", "", "TLS certificate (serve)")
	tlsKey := fs.String("key", "", "TLS key (serve)")
	aud := fs.String("aud", "", "audiences, comma-separated (mint)")
	scope := fs.String("scope", "", "scopes, space-separated (mint)")
	sub := fs.String("sub", "interop-token-user", "subject (mint)")
	groups := fs.String("groups", "", "wlcg.groups, comma-separated (mint)")
	lifetime := fs.Duration("lifetime", time.Hour, "validity (mint); negative for an expired token")
	fs.Parse(os.Args[2:])

	key := loadKey(*keyFile)
	switch os.Args[1] {
	case "serve":
		serve(*issuer, key, *cert, *tlsKey)
	case "mint":
		fmt.Println(mint(*issuer, key, strings.Split(*aud, ","), *scope, *sub, *groups, *lifetime))
	default:
		log.Fatalf("unknown command %s", os.Args[1])
	}
}

func loadKey(file string) crypto.Signer {
	data, err := os.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		log.Fatalf("%s: no PEM data", file)
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("%s: %v", file, err)
	}
	return k.(crypto.Signer)
}

func serve(issuer string, key crypto.Signer, cert, tlsKey string) {
	u, err := url.Parse(issuer)
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                                issuer,
			"jwks_uri":                              issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("JWKS requested by %s (%s)", r.RemoteAddr, r.UserAgent())
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: key.Public(), KeyID: keyID, Algorithm: string(jose.RS256), Use: "sig"},
		}})
	})
	log.Printf("Issuer %s listening on %s", issuer, u.Host)
	log.Fatal(http.ListenAndServeTLS(u.Host, cert, tlsKey, mux))
}

func mint(issuer string, key crypto.Signer, aud []string, scope, sub, groups string, lifetime time.Duration) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID))
	if err != nil {
		log.Fatal(err)
	}
	now := time.Now()
	issued := now
	if lifetime < 0 {
		issued = now.Add(2 * lifetime)
	}
	jti := make([]byte, 16)
	rand.Read(jti)
	claims := map[string]interface{}{
		"iss":      issuer,
		"sub":      sub,
		"aud":      aud,
		"scope":    scope,
		"iat":      issued.Unix(),
		"nbf":      issued.Unix(),
		"exp":      now.Add(lifetime).Unix(),
		"jti":      hex.EncodeToString(jti),
		"wlcg.ver": "1.0",
	}
	if groups != "" {
		claims["wlcg.groups"] = strings.Split(groups, ",")
	}
	tok, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		log.Fatal(err)
	}
	return tok
}
