package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/labkode/weed/internal/davreq"
)

// WLCG (https://doi.org/10.5281/zenodo.3460258) and SciTokens bearer tokens: JWTs
// whose signature is checked against the keys the issuer publishes, granting the
// access listed in their storage scopes

// AudienceAny is the WLCG audience accepted by every service
const AudienceAny = "https://wlcg.cern.ch/jwt/v1/any"

const (
	// Keys are fetched again after tokenKeysMaxAge, so keys an issuer withdraws
	// stop being accepted
	tokenKeysMaxAge = time.Hour
	// Keys are fetched at most once per tokenKeysMinRefresh and issuer, whatever key
	// IDs clients send, so forged tokens cannot make weed flood an issuer
	tokenKeysMinRefresh = time.Minute
	tokenFetchTimeout   = 10 * time.Second
	maxIssuerDocument   = 1 << 20
	tokenClockSkew      = time.Minute
)

// tokenAlgs are the signature algorithms accepted; all are asymmetric
var tokenAlgs = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512, jose.EdDSA,
}

// TokenIssuer is an issuer whose tokens are accepted, as configured in the
// tokens.issuers file
type TokenIssuer struct {
	// Issuer is the iss claim of its tokens, an https URL
	Issuer string `json:"issuer"`
	// Audiences are accepted in the aud claim, in addition to AudienceAny
	Audiences []string `json:"audiences"`
	// BasePath is the directory, relative to the exported directory, that the paths
	// in scopes are relative to (default "/")
	BasePath string `json:"base_path"`
	// Users maps tokens to local accounts: the first matching rule names the
	// account, and a token that no rule matches is refused. Without rules, a
	// token's username is its subject.
	Users []TokenUserRule `json:"users"`
}

// TokenUserRule maps tokens whose sub claim is Sub and whose wlcg.groups claim
// contains Group to the account User. An empty Sub or Group matches any token, so a
// rule with neither matches every token.
type TokenUserRule struct {
	Sub   string `json:"sub"`
	Group string `json:"group"`
	User  string `json:"user"`
}

// normalizeGroup gives WLCG group names their leading slash ("/cms/production")
func normalizeGroup(g string) string {
	return "/" + strings.TrimPrefix(g, "/")
}

// username returns the account a token maps to
func (iss *TokenIssuer) username(sub string, groups []string) (string, error) {
	if len(iss.Users) == 0 {
		if sub == "" {
			return "token", nil
		}
		return sub, nil
	}
	for _, rule := range iss.Users {
		if rule.Sub != "" && rule.Sub != sub {
			continue
		}
		if rule.Group != "" && !slices.ContainsFunc(groups, func(g string) bool { return normalizeGroup(g) == rule.Group }) {
			continue
		}
		return rule.User, nil
	}
	return "", fmt.Errorf("%w: no user rule for %s matches subject %q and groups %q", errForbidden, iss.Issuer, sub, groups)
}

// LoadTokenIssuers reads a JSON list of TokenIssuer, keyed by issuer
func LoadTokenIssuers(filename string) (map[string]*TokenIssuer, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var list []*TokenIssuer
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields() // a misspelled "audiences" must not go unnoticed
	if err := dec.Decode(&list); err != nil {
		return nil, fmt.Errorf("%s: %w", filename, err)
	}
	issuers := make(map[string]*TokenIssuer, len(list))
	for _, iss := range list {
		u, err := url.Parse(iss.Issuer)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("%s: issuer %q is not an https URL", filename, iss.Issuer)
		}
		if issuers[iss.Issuer] != nil {
			return nil, fmt.Errorf("%s: issuer %s is listed twice", filename, iss.Issuer)
		}
		for _, a := range iss.Audiences {
			if a == "" {
				return nil, fmt.Errorf("%s: empty audience for %s", filename, iss.Issuer)
			}
		}
		iss.BasePath = path.Clean("/" + iss.BasePath)
		for i, rule := range iss.Users {
			if rule.User == "" {
				return nil, fmt.Errorf("%s: user rule %d of %s names no user", filename, i+1, iss.Issuer)
			}
			if rule.Group != "" {
				iss.Users[i].Group = normalizeGroup(rule.Group)
			}
		}
		issuers[iss.Issuer] = iss
	}
	return issuers, nil
}

// IsJWT reports whether a bearer token is a JWT rather than a macaroon (base64
// never contains a dot)
func IsJWT(token string) bool {
	return strings.Count(token, ".") == 2
}

// capability is what a storage scope allows
type capability uint8

const (
	capRead   capability = 1 << iota // read data and metadata, list
	capCreate                        // create files and directories, never replacing data
	capModify                        // also overwrite and delete
)

// scopeCapabilities maps the WLCG and SciTokens storage scopes to capabilities
var scopeCapabilities = map[string]capability{
	"storage.read":   capRead,
	"storage.stage":  capRead, // a superset of read, for tape systems
	"storage.create": capCreate,
	"storage.modify": capCreate | capModify,
	"read":           capRead,               // SciTokens
	"write":          capCreate | capModify, // SciTokens
}

// grant is a capability on a URL path and everything below it
type grant struct {
	cap  capability
	path string
}

// parseScopes returns the storage grants among scopes, with paths turned into URL
// paths; other scopes (openid, compute.*, ...) are ignored
func parseScopes(scopes []string, basePath string) []grant {
	var grants []grant
	for _, s := range scopes {
		name, p, hasPath := strings.Cut(s, ":")
		c, ok := scopeCapabilities[name]
		if !ok {
			continue
		}
		if !hasPath {
			p = "/" // as XRootD and dCache do: the whole base path
		}
		if !strings.HasPrefix(p, "/") {
			continue
		}
		// Cleaning the scope path on its own first keeps ".." from leaving the base path
		grants = append(grants, grant{c, path.Join(davreq.Prefix, basePath, path.Clean(p))})
	}
	return grants
}

// tokenNeed is a capability a request needs on one path
type tokenNeed struct {
	path string
	any  capability // any one of these
	// writes is set when the request creates or replaces path: with create but not
	// modify, path must not exist yet
	writes bool
}

// tokenRequirements derives what a request needs from a token's scopes
func tokenRequirements(r *http.Request) ([]tokenNeed, error) {
	if davreq.IsMacaroonRequest(r) {
		// A macaroon has no path-dependent rights, so it could not be bounded by the token
		return nil, errors.New("a macaroon cannot be requested with a token")
	}
	// Outside the WebDAV namespace (e.g. /proc/whoami) a token only proves identity
	if !davreq.InNamespace(r.URL.Path) {
		return nil, nil
	}
	if !davreq.IsClean(r.URL.Path) {
		return nil, fmt.Errorf("non-canonical path %q", r.URL.Path)
	}
	p := r.URL.Path
	one := func(any capability, writes bool) []tokenNeed { return []tokenNeed{{p, any, writes}} }

	switch r.Method {
	case http.MethodGet, http.MethodPost: // the WebDAV handler serves POST like GET
		return one(capRead, false), nil
	case http.MethodHead:
		// Whether a file exists is needed to write it without overwriting
		return one(capRead|capCreate|capModify, false), nil
	case "PROPFIND":
		if r.Header.Get("Depth") == "0" {
			return one(capRead|capCreate|capModify, false), nil
		}
		return one(capRead, false), nil
	case http.MethodOptions:
		return nil, nil
	case http.MethodPut:
		return one(capCreate|capModify, true), nil
	case "MKCOL", "LOCK", "UNLOCK":
		return one(capCreate|capModify, false), nil
	case http.MethodDelete, "PROPPATCH":
		return one(capModify, false), nil
	case "COPY", "MOVE":
		t, err := davreq.ParseTarget(r)
		if err != nil {
			return nil, err
		}
		switch t.Kind {
		case davreq.CopyPull: // writes the local file
			return one(capCreate|capModify, true), nil
		case davreq.CopyPush: // reads the local file
			return one(capRead, false), nil
		}
		dst := tokenNeed{t.Local, capCreate | capModify, true}
		if r.Method == "MOVE" {
			// storage.create "includes renaming files if the destination file does not
			// already exist"
			return []tokenNeed{{p, capCreate | capModify, false}, dst}, nil
		}
		return []tokenNeed{{p, capRead, false}, dst}, nil
	}
	return nil, fmt.Errorf("method %s cannot be used with a token", r.Method)
}

// authorizeToken checks that grants cover needs. noOverwrite is set when a path the
// request writes is covered by create but not modify.
func authorizeToken(grants []grant, needs []tokenNeed) (noOverwrite bool, err error) {
	for _, n := range needs {
		var have capability
		for _, g := range grants {
			if pathMatches(n.path, g.path) {
				have |= g.cap
			}
		}
		if have&n.any == 0 {
			return false, fmt.Errorf("%w: the token's scopes do not allow this request on %s", errForbidden, n.path)
		}
		if n.writes && have&capModify == 0 {
			noOverwrite = true
		}
	}
	return noOverwrite, nil
}

// scopeClaim is the scope claim: space-separated (WLCG, SciTokens) or a list
type scopeClaim []string

func (s *scopeClaim) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err == nil {
		*s = strings.Fields(str)
		return nil
	}
	var list []string
	if err := json.Unmarshal(b, &list); err != nil {
		return errors.New("scope is neither a string nor a list of strings")
	}
	*s = list
	return nil
}

// groupsClaim is the wlcg.groups claim, a list of group names. A single string is
// accepted too, and anything else is ignored: groups only matter to user rules.
type groupsClaim []string

func (g *groupsClaim) UnmarshalJSON(b []byte) error {
	var list []string
	if err := json.Unmarshal(b, &list); err == nil {
		*g = list
		return nil
	}
	var str string
	if err := json.Unmarshal(b, &str); err == nil {
		*g = []string{str}
	}
	return nil
}

// verifiedToken is a token whose signature and validity were checked
type verifiedToken struct {
	issuer *TokenIssuer
	claims jwt.Claims
	scopes []string
	groups []string
	grants []grant
}

// verifyToken checks a JWT's signature, issuer, validity period and audience, and
// that it carries storage scopes
func (as *AuthStore) verifyToken(raw string, now time.Time) (*verifiedToken, error) {
	tok, err := jwt.ParseSigned(raw, tokenAlgs)
	if err != nil {
		return nil, fmt.Errorf("malformed token: %w", err)
	}
	var unverified jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&unverified); err != nil {
		return nil, fmt.Errorf("malformed token: %w", err)
	}
	iss := as.Credentials().TokenIssuers[unverified.Issuer]
	if iss == nil {
		return nil, fmt.Errorf("token issuer %q is not trusted", unverified.Issuer)
	}
	keys, err := as.issuerKeys(iss.Issuer).find(as.tokenHTTPClient(), tok.Headers[0].KeyID, now)
	if err != nil {
		return nil, err
	}

	v := &verifiedToken{issuer: iss}
	var extra struct {
		Scope  scopeClaim  `json:"scope"`
		Groups groupsClaim `json:"wlcg.groups"`
	}
	err = errors.New("no keys")
	for i := range keys {
		if err = tok.Claims(&keys[i], &v.claims, &extra); err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("invalid token signature: %w", err)
	}
	if v.claims.Expiry == nil {
		return nil, errors.New("token has no expiry")
	}
	if err := v.claims.ValidateWithLeeway(jwt.Expected{Issuer: iss.Issuer, Time: now}, tokenClockSkew); err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	if !v.claims.Audience.Contains(AudienceAny) && !anyIn(iss.Audiences, []string(v.claims.Audience)) {
		return nil, fmt.Errorf("token audience %q is not accepted here", []string(v.claims.Audience))
	}
	v.scopes, v.groups = extra.Scope, extra.Groups
	v.grants = parseScopes(v.scopes, iss.BasePath)
	if len(v.grants) == 0 {
		// Without storage scopes access would depend on groups, which weed does not map
		return nil, fmt.Errorf("%w: the token has no storage scopes", errForbidden)
	}
	return v, nil
}

// authenticateToken returns (nil, nil) when no JWT bearer token was presented
func (as *AuthStore) authenticateToken(r *http.Request) (*AuthInfo, error) {
	if !as.TokenEnabled {
		return nil, nil
	}
	token, ok := bearerToken(r)
	if !ok || !IsJWT(token) {
		return nil, nil
	}
	v, err := as.verifyToken(token, time.Now())
	if err != nil {
		return nil, err
	}
	needs, err := tokenRequirements(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errForbidden, err)
	}
	noOverwrite, err := authorizeToken(v.grants, needs)
	if err != nil {
		return nil, err
	}
	username, err := v.issuer.username(v.claims.Subject, v.groups)
	if err != nil {
		return nil, err
	}
	info := &AuthInfo{
		Username: username,
		Method:   "token",
		Details: map[string]interface{}{
			"issuer":  v.issuer.Issuer,
			"subject": v.claims.Subject,
			"scopes":  strings.Join(v.scopes, " "),
			"expires": v.claims.Expiry.Time(),
		},
		NoOverwrite: noOverwrite,
	}
	if len(v.groups) > 0 {
		info.Details["groups"] = strings.Join(v.groups, " ")
	}
	return info, nil
}

// bearerToken returns the token of an "Authorization: Bearer" header
func bearerToken(r *http.Request) (string, bool) {
	authz := r.Header.Get("Authorization")
	if len(authz) < 7 || !strings.EqualFold(authz[:7], "Bearer ") {
		return "", false
	}
	return strings.TrimSpace(authz[7:]), true
}

// SetTokenRootCAs sets the CAs trusted when fetching issuers' keys (nil: the system's)
func (as *AuthStore) SetTokenRootCAs(pool *x509.CertPool) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	as.tokenClient.Store(&http.Client{
		Timeout:   tokenFetchTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" || len(via) >= 5 {
				return errors.New("refusing redirect")
			}
			return nil
		},
	})
}

func (as *AuthStore) tokenHTTPClient() *http.Client {
	if c := as.tokenClient.Load(); c != nil {
		return c
	}
	as.SetTokenRootCAs(nil)
	return as.tokenClient.Load()
}

// issuerKeys returns the key cache of an issuer; caches outlive credential reloads
func (as *AuthStore) issuerKeys(issuer string) *tokenKeys {
	as.tokenKeysMu.Lock()
	defer as.tokenKeysMu.Unlock()
	if as.tokenKeys == nil {
		as.tokenKeys = make(map[string]*tokenKeys)
	}
	k := as.tokenKeys[issuer]
	if k == nil {
		k = &tokenKeys{issuer: issuer}
		as.tokenKeys[issuer] = k
	}
	return k
}

// tokenKeys caches the signing keys an issuer publishes
type tokenKeys struct {
	issuer string

	mu      sync.Mutex // held while fetching, so concurrent requests share one fetch
	keys    []jose.JSONWebKey
	fetched time.Time // of the keys
	tried   time.Time // last fetch attempt
	err     error     // of the last attempt
}

// find returns the keys with ID kid (all keys if kid is empty), fetching them
// when the cache is old or does not have kid, at most once per tokenKeysMinRefresh
func (k *tokenKeys) find(client *http.Client, kid string, now time.Time) ([]jose.JSONWebKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	match := func() []jose.JSONWebKey {
		var m []jose.JSONWebKey
		for _, key := range k.keys {
			if kid == "" || key.KeyID == kid {
				m = append(m, key)
			}
		}
		return m
	}
	stale := k.keys == nil || now.Sub(k.fetched) >= tokenKeysMaxAge
	if (stale || len(match()) == 0) && now.Sub(k.tried) >= tokenKeysMinRefresh {
		k.tried = now
		// Not the request's context: a client hanging up must not count as a failure
		ctx, cancel := context.WithTimeout(context.Background(), tokenFetchTimeout)
		keys, err := fetchIssuerKeys(ctx, client, k.issuer)
		cancel()
		if err != nil {
			slog.Warn("cannot fetch the signing keys of a token issuer, keeping the known ones", "issuer", k.issuer, "keys", len(k.keys), "error", err)
			k.err = err
		} else {
			slog.Info("fetched the signing keys of a token issuer", "issuer", k.issuer, "keys", len(keys))
			k.keys, k.fetched, k.err = keys, now, nil
		}
	}
	if m := match(); len(m) > 0 {
		return m, nil
	}
	if k.keys == nil && k.err != nil {
		return nil, fmt.Errorf("cannot get the signing keys of %s: %w", k.issuer, k.err)
	}
	return nil, fmt.Errorf("%s publishes no signing key %q", k.issuer, kid)
}

var errNotFound = errors.New("not found")

// fetchIssuerKeys finds an issuer's key set through its discovery document and
// returns the signing keys in it
func fetchIssuerKeys(ctx context.Context, client *http.Client, issuer string) ([]jose.JSONWebKey, error) {
	var meta struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	base := strings.TrimSuffix(issuer, "/")
	err := getJSON(ctx, client, base+"/.well-known/openid-configuration", &meta)
	if errors.Is(err, errNotFound) {
		// Used by some SciTokens issuers; appended to the issuer as scitokens-cpp does
		err = getJSON(ctx, client, base+"/.well-known/oauth-authorization-server", &meta)
	}
	if err != nil {
		return nil, err
	}
	if meta.Issuer != issuer {
		return nil, fmt.Errorf("discovery document is for issuer %q", meta.Issuer)
	}
	if u, err := url.Parse(meta.JWKSURI); err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("discovery document has an invalid jwks_uri %q", meta.JWKSURI)
	}

	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := getJSON(ctx, client, meta.JWKSURI, &set); err != nil {
		return nil, err
	}
	var keys []jose.JSONWebKey
	for _, raw := range set.Keys {
		var key jose.JSONWebKey
		if err := key.UnmarshalJSON(raw); err != nil {
			continue // a key of a type weed does not know does not invalidate the others
		}
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		if pub := key.Public(); pub.Valid() { // drops symmetric keys
			keys = append(keys, pub)
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no usable signing keys at %s", meta.JWKSURI)
	}
	return keys, nil
}

func getJSON(ctx context.Context, client *http.Client, u string, v interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("GET %s: %w", u, errNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxIssuerDocument+1))
	if err != nil {
		return fmt.Errorf("GET %s: %w", u, err)
	}
	if len(data) > maxIssuerDocument {
		return fmt.Errorf("GET %s: response too large", u)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("GET %s: %w", u, err)
	}
	return nil
}
