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
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/labkode/weed/internal/logger"
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

	Gridmap   map[string]string
	Htpasswd  map[string]string
	AppTokens map[string]string
	// X.509 certificate verification
	CACertPool *x509.CertPool
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

	// dummyHash is compared against when a user does not exist, so that response
	// times do not reveal which usernames are valid
	dummyHash []byte
}

// NewAuthStore creates a new authentication store
func NewAuthStore() *AuthStore {
	return &AuthStore{
		Gridmap:      make(map[string]string),
		Htpasswd:     make(map[string]string),
		AppTokens:    make(map[string]string),
		oidcLogins:   make(map[string]oidcLogin),
		oidcSessions: make(map[string]*OIDCSession),
	}
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

// LoadGridmap loads and parses the gridmap file
func (as *AuthStore) LoadGridmap(filename string) error {
	result := make(map[string]string)

	file, err := os.Open(filename)
	if err != nil {
		return err
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
			log.Printf("[GRIDMAP] Ignoring malformed line %d in %s", lineNo, filename)
			continue
		}
		result[dn] = username
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	as.Gridmap = result
	return nil
}

// LoadHtpasswd loads and parses the htpasswd file
func (as *AuthStore) LoadHtpasswd(filename string) error {
	result := make(map[string]string)

	file, err := os.Open(filename)
	if err != nil {
		return err
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
				log.Printf("[HTPASSWD] Warning: user %s does not have a bcrypt hash and will not be able to log in (use: weed utils password)", parts[0])
			}
			result[parts[0]] = parts[1]
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	as.Htpasswd = result
	return nil
}

// LoadAppTokens loads and parses the app tokens file
func (as *AuthStore) LoadAppTokens(filename string) error {
	result := make(map[string]string)

	file, err := os.Open(filename)
	if err != nil {
		return err
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
		return err
	}

	as.AppTokens = result
	return nil
}

// LoadCACert loads and parses the CA certificate(s) for X.509 verification
func (as *AuthStore) LoadCACert(filename string) error {
	caCert, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate file %s: %w", filename, err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to parse CA certificate from %s", filename)
	}

	as.CACertPool = caCertPool
	return nil
}

// VerifyPassword checks if the provided password matches the stored hash
func (as *AuthStore) VerifyPassword(storedHash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
	return err == nil
}

// VerifyClientCertificate verifies a client certificate chain (leaf first, possibly
// starting with grid proxies) against the CA and returns the end-entity certificate
func (as *AuthStore) VerifyClientCertificate(chain []*x509.Certificate) (*x509.Certificate, int, error) {
	return x509utils.VerifyChain(chain, as.CACertPool, time.Now())
}

// VerifyCredentialsWithMethod verifies username/password and returns authentication method and additional info
func (as *AuthStore) VerifyCredentialsWithMethod(username, password string) (bool, string, string) {
	// First check if it's an app token (password is 64 char hex string)
	if len(password) == 64 {
		if tokenUsername, exists := as.AppTokens[password]; exists &&
			subtle.ConstantTimeCompare([]byte(tokenUsername), []byte(username)) == 1 {
			// Return first 8 characters of token for logging
			tokenPrefix := password[:8] + "..."
			return true, "app-token", tokenPrefix
		}
	}

	// Check regular password authentication; unknown users still pay for a bcrypt
	// comparison so that timing does not reveal which accounts exist
	storedHash, exists := as.Htpasswd[username]
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

	// Map DN to username using gridmap if available
	username := dn
	mappedUser, mapped := as.Gridmap[dn]
	if mapped {
		username = mappedUser
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
	if mapped {
		info.Details["gridmap_mapping"] = mappedUser
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
	authz := r.Header.Get("Authorization")
	if len(authz) < 7 || !strings.EqualFold(authz[:7], "Bearer ") {
		return nil, nil
	}
	token := strings.TrimSpace(authz[7:])
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
	if as.MacaroonEnabled {
		w.Header().Add("WWW-Authenticate", `Bearer realm="WebDAV Server"`)
	}
	http.Error(w, msg, http.StatusUnauthorized)
}

// BasicAuthMiddleware provides HTTP Basic Authentication and stores username in context
func (as *AuthStore) BasicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := logger.GetRequestID(r.Context())

		info, err := as.authenticateBasic(r)
		if info == nil {
			if err == nil {
				err = errors.New("no Basic credentials provided")
			}
			log.Printf("[BASIC-AUTH] [%s] %v - requesting credentials", reqID, err)
			w.Header().Set("WWW-Authenticate", `Basic realm="WebDAV Server"`)
			http.Error(w, "Authorization required", http.StatusUnauthorized)
			return
		}

		log.Printf("[BASIC-AUTH] [%s] User authenticated: %s (method: %s)", reqID, info.Username, info.Details["auth_type"])
		next.ServeHTTP(w, r.WithContext(SetAuthInfoInContext(r.Context(), info)))
	})
}

// X509AuthMiddleware provides X.509 client certificate authentication and stores username in context
func (as *AuthStore) X509AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := logger.GetRequestID(r.Context())

		info, err := as.authenticateX509(r)
		if info == nil {
			if err == nil {
				err = errors.New("no client certificate provided")
			}
			log.Printf("[X509-AUTH] [%s] %v - denying access", reqID, err)
			http.Error(w, "Valid client certificate required", http.StatusUnauthorized)
			return
		}

		log.Printf("[X509-AUTH] [%s] Certificate authenticated - DN: %s -> Username: %s", reqID, info.Details["distinguished_name"], info.Username)
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
		{"X509", as.authenticateX509},
		{"OIDC", as.authenticateOIDC},
		{"MACAROON", as.authenticateMacaroon},
		{"BASIC", as.authenticateBasic},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := logger.GetRequestID(r.Context())

		// Track authentication attempts for logging
		// SKIP = not provided, FAIL = error/invalid, OK = success
		status := make([]string, len(methods))
		flow := func() string {
			parts := make([]string, len(methods))
			for i, m := range methods {
				parts[i] = m.name + "=" + status[i]
			}
			return strings.Join(parts, " ")
		}

		forbidden := false
		for i, m := range methods {
			info, err := m.authenticate(r)
			switch {
			case info != nil:
				status[i] = "OK"
				log.Printf("[AUTH-FLOW] [%s] %s -> SUCCESS (%s) user=%s", reqID, flow(), m.name, info.Username)
				next.ServeHTTP(w, r.WithContext(SetAuthInfoInContext(r.Context(), info)))
				return
			case err != nil:
				status[i] = "FAIL"
				forbidden = forbidden || errors.Is(err, errForbidden)
				log.Printf("[%s-AUTH] [%s] %v - trying next auth method", m.name, reqID, err)
			default:
				status[i] = "SKIP"
			}
		}

		// Valid credentials that do not cover this request get 403, not a login prompt
		if forbidden {
			log.Printf("[AUTH-FLOW] [%s] %s -> DENIED (403)", reqID, flow())
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		log.Printf("[AUTH-FLOW] [%s] %s -> DENIED (401)", reqID, flow())
		as.challenge(w, "Authorization required")
	})
}
