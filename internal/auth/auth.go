package auth

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/labkode/weed/internal/fsuser"
	"github.com/labkode/weed/internal/logger"
	"github.com/labkode/weed/internal/metrics"
	"github.com/labkode/weed/internal/x509utils"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"gopkg.in/macaroon.v2"
)

// Context key for storing authentication information
type contextKey string

const (
	usernameContextKey contextKey = "username"
	authInfoContextKey contextKey = "authInfo"
)

// Limits on in-memory OIDC state, so unauthenticated clients cannot grow it without bound
const (
	maxOIDCLogins   = 10000
	maxOIDCSessions = 100000
	oidcLoginTTL    = 10 * time.Minute
)

// AuthInfo represents detailed authentication information stored in context
type AuthInfo struct {
	Username string                 `json:"username"`
	Method   string                 `json:"method"`
	Details  map[string]interface{} `json:"details"`
	// Macaroon is the verified token when Method is "macaroon"; new macaroons minted
	// with it are attenuations of it, so they can never carry more rights
	Macaroon *macaroon.Macaroon `json:"-"`
	// NoOverwrite is set when the request may create the file it writes but not
	// replace an existing one (a token with storage.create but not storage.modify)
	NoOverwrite bool `json:"-"`
	// Directories are URL paths that the request may only use as directories: a
	// token scope whose path ends in "/" names a directory, not a file of that name
	Directories []string `json:"-"`
	// Unix is the local account the request accesses files as (with UnixUsers)
	Unix *fsuser.User `json:"-"`
}

// OIDCSession represents an authenticated browser session
type OIDCSession struct {
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// oidcLogin is a login in progress, keyed by its OAuth2 state
type oidcLogin struct {
	nonce     string
	expiresAt time.Time
}

// errForbidden marks credentials that are valid but do not allow the request
var errForbidden = errors.New("forbidden")

// SetAuthInfoInContext stores authentication information in the context
func SetAuthInfoInContext(ctx context.Context, authInfo *AuthInfo) context.Context {
	// Store both username (for backward compatibility) and auth info
	ctx = context.WithValue(ctx, usernameContextKey, authInfo.Username)
	ctx = context.WithValue(ctx, authInfoContextKey, authInfo)
	logger.SetUsername(ctx, authInfo.Username)
	return ctx
}

// GetUsernameFromContext retrieves the authenticated username from the request context
func GetUsernameFromContext(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(usernameContextKey).(string)
	return username, ok
}

// GetAuthInfoFromContext retrieves the authentication information from the request context
func GetAuthInfoFromContext(ctx context.Context) (*AuthInfo, bool) {
	authInfo, ok := ctx.Value(authInfoContextKey).(*AuthInfo)
	return authInfo, ok
}

// AuthStore holds authentication data
type AuthStore struct {
	// Enabled authentication methods; a method that is not enabled is never attempted
	BasicEnabled    bool
	X509Enabled     bool
	OIDCEnabled     bool
	MacaroonEnabled bool
	TokenEnabled    bool // WLCG and SciTokens JWTs, from Credentials.TokenIssuers
	// Anonymous serves requests that carry no credentials, as "anonymous"
	Anonymous bool

	// UnixUsers requires every identity to be a local account (see unix.go), found
	// with LookupUnixUser (default fsuser.Lookup)
	UnixUsers      bool
	LookupUnixUser func(name string) (*fsuser.User, error)
	unixMu         sync.Mutex
	unixUsers      map[string]cachedUnixUser

	// File-based credentials, replaced as a whole on reload
	creds atomic.Pointer[Credentials]
	// OIDC configuration
	OIDCProvider *oidc.Provider
	OAuth2Config *oauth2.Config
	OIDCVerifier *oidc.IDTokenVerifier
	// OIDC logins in progress and established sessions
	oidcMu       sync.Mutex
	oidcLogins   map[string]oidcLogin
	oidcSessions map[string]*OIDCSession
	// Macaroon configuration
	MacaroonSecretKey []byte
	MacaroonLocation  string
	// Token issuers' signing keys, and the client fetching them
	tokenKeysMu sync.Mutex
	tokenKeys   map[string]*tokenKeys
	tokenClient atomic.Pointer[http.Client]

	// dummyHash is compared against when a user does not exist, so that response
	// times do not reveal which usernames are valid
	dummyHash []byte
}

// Credentials are the file-based inputs of authentication. A set is never modified
// once in use: reloading builds a new set and swaps it in, so that every request
// sees one consistent set.
type Credentials struct {
	Gridmap   map[string]string // certificate DN -> account
	Htpasswd  map[string]string // user -> bcrypt hash
	AppTokens map[string]string // token -> user
	Roots     *x509.CertPool    // CAs trusted for X.509 client authentication
	CRLs      *x509utils.CRLSet // nil disables revocation checks

	TokenIssuers map[string]*TokenIssuer // by issuer
}

// NewAuthStore creates a new authentication store
func NewAuthStore() *AuthStore {
	as := &AuthStore{
		oidcLogins:   make(map[string]oidcLogin),
		oidcSessions: make(map[string]*OIDCSession),
	}
	as.SetCredentials(&Credentials{})
	return as
}

// Credentials returns the credentials in use
func (as *AuthStore) Credentials() *Credentials {
	return as.creds.Load()
}

// SetCredentials replaces the credentials in use; c must not be modified afterwards
func (as *AuthStore) SetCredentials(c *Credentials) {
	as.creds.Store(c)
}

// MapDN returns the account a certificate DN maps to in the grid-mapfile, and whether
// it is listed at all
func (as *AuthStore) MapDN(dn string) (string, bool) {
	user, ok := as.Credentials().Gridmap[dn]
	return user, ok
}

// parseGridmapLine parses `"DN" user[,user...]`; the DN may contain spaces
func parseGridmapLine(line string) (dn, username string, ok bool) {
	var rest string
	if strings.HasPrefix(line, `"`) {
		end := strings.IndexByte(line[1:], '"')
		if end < 0 {
			return "", "", false
		}
		dn, rest = line[1:1+end], line[2+end:]
	} else {
		i := strings.IndexAny(line, " \t")
		if i < 0 {
			return "", "", false
		}
		dn, rest = line[:i], line[i:]
	}
	// grid-mapfiles may list several accounts ("a,b"); the first one is the default
	accounts := strings.FieldsFunc(rest, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	if dn == "" || len(accounts) == 0 {
		return "", "", false
	}
	return dn, accounts[0], true
}

// LoadGridmap reads a grid-mapfile
func LoadGridmap(filename string) (map[string]string, error) {
	result := make(map[string]string)

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Format: "DN" username
		dn, username, ok := parseGridmapLine(line)
		if !ok {
			slog.Warn("ignoring a malformed grid-mapfile line", "file", filename, "line", lineNo)
			continue
		}
		result[dn] = username
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// LoadHtpasswd reads an htpasswd file
func LoadHtpasswd(filename string) (map[string]string, error) {
	result := make(map[string]string)

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Format: username:password_hash
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			if _, err := bcrypt.Cost([]byte(parts[1])); err != nil {
				slog.Warn("htpasswd entry without a bcrypt hash: the user cannot log in (weed utils password sets one)", "file", filename, "user", parts[0])
			}
			result[parts[0]] = parts[1]
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// LoadAppTokens reads an app tokens file
func LoadAppTokens(filename string) (map[string]string, error) {
	result := make(map[string]string)

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Format: token:username
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			result[parts[0]] = parts[1]
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// LoadCAs reads the CA certificates trusted for X.509 client authentication from a
// PEM file or a directory such as /etc/grid-security/certificates
func LoadCAs(path string) (*x509.CertPool, int, error) {
	certs, err := x509utils.LoadCertificates(path)
	if err != nil {
		return nil, 0, err
	}
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool, len(certs), nil
}

// VerifyPassword checks if the provided password matches the stored hash
func (as *AuthStore) VerifyPassword(storedHash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
	return err == nil
}

// VerifyClientCertificate verifies a client certificate chain (leaf first, possibly
// starting with grid proxies) against the CA and returns the end-entity certificate
func (as *AuthStore) VerifyClientCertificate(chain []*x509.Certificate) (*x509.Certificate, int, error) {
	c := as.Credentials()
	return x509utils.VerifyChainCRL(chain, c.Roots, c.CRLs, time.Now())
}

// VerifyCredentialsWithMethod verifies username/password and returns authentication method and additional info
func (as *AuthStore) VerifyCredentialsWithMethod(username, password string) (bool, string, string) {
	creds := as.Credentials()
	// First check if it's an app token (password is 64 char hex string)
	if len(password) == 64 {
		if tokenUsername, exists := creds.AppTokens[password]; exists &&
			subtle.ConstantTimeCompare([]byte(tokenUsername), []byte(username)) == 1 {
			// Return first 8 characters of token for logging
			tokenPrefix := password[:8] + "..."
			return true, "app-token", tokenPrefix
		}
	}

	// Check regular password authentication; unknown users still pay for a bcrypt
	// comparison so that timing does not reveal which accounts exist
	storedHash, exists := creds.Htpasswd[username]
	if !exists {
		if as.dummyHash != nil {
			bcrypt.CompareHashAndPassword(as.dummyHash, []byte(password))
		}
		return false, "unknown", ""
	}
	if as.VerifyPassword(storedHash, password) {
		return true, "password", ""
	}

	return false, "unknown", ""
}

// PrepareBasicAuth precomputes state used by Basic authentication; call it once before serving
func (as *AuthStore) PrepareBasicAuth() {
	as.dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy"), bcrypt.DefaultCost)
}

// randomString returns n random bytes, hex encoded
func randomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// InitializeOIDC initializes the OIDC configuration
func (as *AuthStore) InitializeOIDC(ctx context.Context, issuer, clientID, clientSecret, redirectURL string) error {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return err
	}

	as.OIDCProvider = provider
	as.OAuth2Config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	as.OIDCVerifier = provider.Verifier(&oidc.Config{ClientID: clientID})
	return nil
}

// StartOIDCLogin registers a new login and returns its OAuth2 state and OIDC nonce
func (as *AuthStore) StartOIDCLogin() (state, nonce string, err error) {
	as.oidcMu.Lock()
	defer as.oidcMu.Unlock()

	now := time.Now()
	if len(as.oidcLogins) >= maxOIDCLogins {
		for k, l := range as.oidcLogins {
			if now.After(l.expiresAt) {
				delete(as.oidcLogins, k)
			}
		}
		if len(as.oidcLogins) >= maxOIDCLogins {
			return "", "", errors.New("too many OIDC logins in progress")
		}
	}
	state, nonce = randomString(16), randomString(16)
	as.oidcLogins[state] = oidcLogin{nonce: nonce, expiresAt: now.Add(oidcLoginTTL)}
	return state, nonce, nil
}

// FinishOIDCLogin consumes a login started with StartOIDCLogin and returns its nonce.
// Each state can be used once.
func (as *AuthStore) FinishOIDCLogin(state string) (string, bool) {
	as.oidcMu.Lock()
	defer as.oidcMu.Unlock()

	l, ok := as.oidcLogins[state]
	delete(as.oidcLogins, state)
	if !ok || time.Now().After(l.expiresAt) {
		return "", false
	}
	return l.nonce, true
}

// CreateOIDCSession creates a session for username and returns its identifier.
// The identifier is fresh randomness, unrelated to anything seen in URLs or logs.
func (as *AuthStore) CreateOIDCSession(username string, ttl time.Duration) (string, error) {
	as.oidcMu.Lock()
	defer as.oidcMu.Unlock()

	now := time.Now()
	if len(as.oidcSessions) >= maxOIDCSessions {
		for k, s := range as.oidcSessions {
			if now.After(s.ExpiresAt) {
				delete(as.oidcSessions, k)
			}
		}
		if len(as.oidcSessions) >= maxOIDCSessions {
			return "", errors.New("too many OIDC sessions")
		}
	}
	id := randomString(32)
	as.oidcSessions[id] = &OIDCSession{Username: username, CreatedAt: now, ExpiresAt: now.Add(ttl)}
	return id, nil
}

// GetOIDCSession retrieves a session that has not expired
func (as *AuthStore) GetOIDCSession(id string) (*OIDCSession, bool) {
	as.oidcMu.Lock()
	defer as.oidcMu.Unlock()

	s, ok := as.oidcSessions[id]
	if !ok {
		return nil, false
	}
	if time.Now().After(s.ExpiresAt) {
		delete(as.oidcSessions, id)
		return nil, false
	}
	sc := *s
	return &sc, true
}

// authenticateX509 returns (nil, nil) when no client certificate was presented
func (as *AuthStore) authenticateX509(r *http.Request) (*AuthInfo, error) {
	if !as.X509Enabled || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, nil
	}
	eec, proxies, err := as.VerifyClientCertificate(r.TLS.PeerCertificates)
	if err != nil {
		return nil, err
	}
	dn := x509utils.GetDNParts(eec)
	username, ok := as.MapDN(dn)
	if !ok {
		// Only the certificates listed in the grid-mapfile are let in, not every one the CAs issued
		return nil, fmt.Errorf("%w: %s is not in the grid-mapfile", errForbidden, dn)
	}

	info := &AuthInfo{
		Username: username,
		Method:   "X.509 Certificate",
		Details: map[string]interface{}{
			"distinguished_name":  dn,
			"certificate_subject": eec.Subject.String(),
			"certificate_serial":  eec.SerialNumber.String(),
		},
	}
	if proxies > 0 {
		info.Details["proxy_certificates"] = proxies
	}
	return info, nil
}

// authenticateOIDC returns (nil, nil) when no session cookie was presented
func (as *AuthStore) authenticateOIDC(r *http.Request) (*AuthInfo, error) {
	if !as.OIDCEnabled {
		return nil, nil
	}
	cookie, err := r.Cookie("oidc_session")
	if err != nil {
		return nil, nil
	}
	session, ok := as.GetOIDCSession(cookie.Value)
	if !ok || session.Username == "" {
		return nil, errors.New("invalid or expired OIDC session")
	}
	return &AuthInfo{
		Username: session.Username,
		Method:   "OIDC",
		Details: map[string]interface{}{
			"created_at": session.CreatedAt,
			"expires_at": session.ExpiresAt,
		},
	}, nil
}

// authenticateMacaroon returns (nil, nil) when no bearer token was presented
func (as *AuthStore) authenticateMacaroon(r *http.Request) (*AuthInfo, error) {
	if !as.MacaroonEnabled {
		return nil, nil
	}
	token, ok := bearerToken(r)
	if !ok || (as.TokenEnabled && IsJWT(token)) {
		return nil, nil
	}
	if token == "" {
		return nil, errors.New("empty bearer token")
	}
	access, err := RequestAccess(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errForbidden, err)
	}
	return as.VerifyMacaroon(token, access)
}

// authenticateBasic returns (nil, nil) when no Basic credentials were presented
func (as *AuthStore) authenticateBasic(r *http.Request) (*AuthInfo, error) {
	if !as.BasicEnabled {
		return nil, nil
	}
	authz := r.Header.Get("Authorization")
	if len(authz) < 6 || !strings.EqualFold(authz[:6], "Basic ") {
		return nil, nil
	}
	username, password, ok := r.BasicAuth()
	if !ok {
		return nil, errors.New("malformed Basic credentials")
	}

	// Verify credentials and get authentication method and additional info
	authenticated, authMethod, tokenPrefix := as.VerifyCredentialsWithMethod(username, password)
	if !authenticated {
		return nil, fmt.Errorf("invalid credentials for user %s", username)
	}

	info := &AuthInfo{
		Username: username,
		Method:   "Basic Authentication",
		Details: map[string]interface{}{
			"auth_type": authMethod,
		},
	}
	if authMethod == "app-token" {
		info.Details["app_token"] = tokenPrefix
	}
	return info, nil
}

// challenge writes a 401 advertising the enabled header-based methods
func (as *AuthStore) challenge(w http.ResponseWriter, msg string) {
	if as.BasicEnabled {
		w.Header().Add("WWW-Authenticate", `Basic realm="WebDAV Server"`)
	}
	if as.MacaroonEnabled || as.TokenEnabled {
		w.Header().Add("WWW-Authenticate", `Bearer realm="WebDAV Server"`)
	}
	http.Error(w, msg, http.StatusUnauthorized)
}

// BasicAuthMiddleware provides HTTP Basic Authentication and stores username in context
func (as *AuthStore) BasicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, err := as.authenticateBasic(r)
		if info == nil {
			if err != nil {
				slog.InfoContext(r.Context(), "authentication failed", "method", "basic", "error", err)
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="WebDAV Server"`)
			http.Error(w, "Authorization required", http.StatusUnauthorized)
			return
		}

		slog.DebugContext(r.Context(), "authenticated", "method", "basic", "user", info.Username, "kind", info.Details["auth_type"])
		next.ServeHTTP(w, r.WithContext(SetAuthInfoInContext(r.Context(), info)))
	})
}

// X509AuthMiddleware provides X.509 client certificate authentication and stores username in context
func (as *AuthStore) X509AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, err := as.authenticateX509(r)
		if info == nil {
			if err == nil {
				err = errors.New("no client certificate provided")
			}
			slog.InfoContext(r.Context(), "authentication failed", "method", "x509", "error", err)
			if errors.Is(err, errForbidden) {
				http.Error(w, "Certificate not authorized", http.StatusForbidden)
				return
			}
			http.Error(w, "Valid client certificate required", http.StatusUnauthorized)
			return
		}

		slog.DebugContext(r.Context(), "authenticated", "method", "x509", "user", info.Username, "dn", info.Details["distinguished_name"])
		next.ServeHTTP(w, r.WithContext(SetAuthInfoInContext(r.Context(), info)))
	})
}

// UnifiedAuthMiddleware provides authentication in the specified order: X.509 -> OIDC -> Macaroon -> Basic Auth
func (as *AuthStore) UnifiedAuthMiddleware(next http.Handler) http.Handler {
	type method struct {
		name         string
		authenticate func(*http.Request) (*AuthInfo, error)
	}
	methods := []method{
		{"x509", as.authenticateX509},
		{"oidc", as.authenticateOIDC},
		{"token", as.authenticateToken},
		{"macaroon", as.authenticateMacaroon},
		{"basic", as.authenticateBasic},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		// What each method made of the request, for debugging: skip (no credentials
		// of its kind), fail or ok
		status := make([]string, len(methods))
		flow := func() slog.Attr {
			attrs := make([]any, len(methods))
			for i, m := range methods {
				attrs[i] = slog.String(m.name, status[i])
			}
			return slog.Group("auth", attrs...)
		}

		forbiddenBy := ""
		for i, m := range methods {
			info, err := m.authenticate(r)
			if info != nil && as.UnixUsers {
				if info.Unix, err = as.unixUser(info.Username); err != nil {
					info = nil
				}
			}
			switch {
			case info != nil:
				status[i] = "ok"
				slog.DebugContext(ctx, "authenticated", "method", m.name, "user", info.Username, flow())
				metrics.Auth.Inc(m.name, "success")
				next.ServeHTTP(w, r.WithContext(SetAuthInfoInContext(ctx, info)))
				return
			case err != nil:
				status[i] = "fail"
				if forbiddenBy == "" && errors.Is(err, errForbidden) {
					forbiddenBy = m.name
				}
				slog.InfoContext(ctx, "authentication failed", "method", m.name, "error", err)
			default:
				status[i] = "skip"
			}
		}

		// Requests without credentials may be anonymous (only on loopback, see config)
		if as.Anonymous && !slices.ContainsFunc(status, func(s string) bool { return s != "skip" }) {
			slog.DebugContext(ctx, "anonymous request", flow())
			metrics.Auth.Inc("anonymous", "success")
			next.ServeHTTP(w, r.WithContext(SetAuthInfoInContext(ctx, &AuthInfo{Username: "anonymous", Method: "anonymous"})))
			return
		}

		// Valid credentials that do not cover this request get 403, not a login prompt
		if forbiddenBy != "" {
			slog.DebugContext(ctx, "forbidden", "method", forbiddenBy, flow())
			metrics.Auth.Inc(forbiddenBy, "forbidden")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		slog.DebugContext(ctx, "authentication required", flow())
		metrics.Auth.Inc("none", "unauthorized")
		as.challenge(w, "Authorization required")
	})
}
