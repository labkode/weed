package auth

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

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

// AuthInfo represents detailed authentication information stored in context
type AuthInfo struct {
	Username string                 `json:"username"`
	Method   string                 `json:"method"`
	Details  map[string]interface{} `json:"details"`
}

// OIDCSession represents an OIDC session
type OIDCSession struct {
	Username  string    `json:"username"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SetAuthInfoInContext stores authentication information in the context
func SetAuthInfoInContext(ctx context.Context, authInfo *AuthInfo) context.Context {
	// Store both username (for backward compatibility) and auth info
	ctx = context.WithValue(ctx, usernameContextKey, authInfo.Username)
	ctx = context.WithValue(ctx, authInfoContextKey, authInfo)
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
	Gridmap   map[string]string
	Htpasswd  map[string]string
	AppTokens map[string]string
	// X.509 certificate verification
	CACertPool *x509.CertPool
	// OIDC configuration
	OIDCProvider *oidc.Provider
	OAuth2Config *oauth2.Config
	OIDCVerifier *oidc.IDTokenVerifier
	// Session store for OIDC state
	Sessions map[string]*OIDCSession
	// Macaroon configuration
	MacaroonSecretKey []byte
	MacaroonLocation  string
}

// NewAuthStore creates a new authentication store
func NewAuthStore() *AuthStore {
	return &AuthStore{
		Gridmap:   make(map[string]string),
		Htpasswd:  make(map[string]string),
		AppTokens: make(map[string]string),
		Sessions:  make(map[string]*OIDCSession),
	}
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
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Format: "DN" username
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			// Remove quotes from DN if present
			dn := strings.Trim(parts[0], "\"")
			username := parts[1]
			result[dn] = username
		}
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

// LoadCACert loads and parses the CA certificate for X.509 verification
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

// VerifyClientCertificate manually verifies a client certificate against the CA
func (as *AuthStore) VerifyClientCertificate(cert *x509.Certificate) error {
	if as.CACertPool == nil {
		return errors.New("no CA certificate pool available for verification")
	}

	// Check certificate validity period
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("certificate expired or not yet valid: valid from %v to %v",
			cert.NotBefore, cert.NotAfter)
	}

	// Verify certificate against CA
	opts := x509.VerifyOptions{
		Roots:     as.CACertPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	_, err := cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	return nil
}

// VerifyCredentialsWithMethod verifies username/password and returns authentication method and additional info
func (as *AuthStore) VerifyCredentialsWithMethod(username, password string) (bool, string, string) {
	// First check if it's an app token (password is 64 char hex string)
	if len(password) == 64 {
		if tokenUsername, exists := as.AppTokens[password]; exists && tokenUsername == username {
			// Return first 8 characters of token for logging
			tokenPrefix := password[:8] + "..."
			return true, "app-token", tokenPrefix
		}
	}

	// Check regular password authentication
	if storedHash, exists := as.Htpasswd[username]; exists {
		if as.VerifyPassword(storedHash, password) {
			return true, "password", ""
		}
	}

	return false, "unknown", ""
}

// BasicAuthMiddleware provides HTTP Basic Authentication and stores username in context
func (as *AuthStore) BasicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := logger.GetRequestID(r.Context())

		// Get the Authorization header
		auth := r.Header.Get("Authorization")
		if auth == "" {
			log.Printf("[BASIC-AUTH] [%s] No Authorization header - requesting credentials", reqID)
			w.Header().Set("WWW-Authenticate", `Basic realm="WebDAV Server"`)
			http.Error(w, "Authorization required", http.StatusUnauthorized)
			return
		}

		// Check if it's Basic auth
		if !strings.HasPrefix(auth, "Basic ") {
			log.Printf("[BASIC-AUTH] [%s] Non-Basic authorization - denying access", reqID)
			w.Header().Set("WWW-Authenticate", `Basic realm="WebDAV Server"`)
			http.Error(w, "Basic authentication required", http.StatusUnauthorized)
			return
		}

		// Decode the credentials
		encoded := auth[6:] // Remove "Basic " prefix
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			log.Printf("[BASIC-AUTH] [%s] Invalid base64 encoding - denying access", reqID)
			w.Header().Set("WWW-Authenticate", `Basic realm="WebDAV Server"`)
			http.Error(w, "Invalid credentials format", http.StatusUnauthorized)
			return
		}

		// Split username:password
		credentials := string(decoded)
		parts := strings.SplitN(credentials, ":", 2)
		if len(parts) != 2 {
			log.Printf("[BASIC-AUTH] [%s] Invalid credentials format - denying access", reqID)
			w.Header().Set("WWW-Authenticate", `Basic realm="WebDAV Server"`)
			http.Error(w, "Invalid credentials format", http.StatusUnauthorized)
			return
		}

		username := parts[0]
		password := parts[1]

		// Verify credentials and get authentication method and additional info
		authenticated, authMethod, authInfo := as.VerifyCredentialsWithMethod(username, password)
		if !authenticated {
			log.Printf("[BASIC-AUTH] [%s] Authentication failed for user: %s", reqID, username)
			w.Header().Set("WWW-Authenticate", `Basic realm="WebDAV Server"`)
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Enhanced logging with authentication details
		if authMethod == "app-token" {
			log.Printf("[BASIC-AUTH] [%s] User authenticated: %s (method: %s, token: %s)", reqID, username, authMethod, authInfo)
		} else {
			log.Printf("[BASIC-AUTH] [%s] User authenticated: %s (method: %s)", reqID, username, authMethod)
		}

		// Store authentication info in request context
		userAuthInfo := &AuthInfo{
			Username: username,
			Method:   "Basic Authentication",
			Details: map[string]interface{}{
				"auth_type": authMethod,
			},
		}
		if authMethod == "app-token" {
			userAuthInfo.Details["app_token"] = authInfo
		}
		ctx := SetAuthInfoInContext(r.Context(), userAuthInfo)
		r = r.WithContext(ctx)

		// Call next handler
		next.ServeHTTP(w, r)
	})
}

// GenerateState generates a random state string for OIDC
func (as *AuthStore) GenerateState() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// StoreOIDCSession stores an OIDC session
func (as *AuthStore) StoreOIDCSession(state string, session *OIDCSession) {
	as.Sessions[state] = session
}

// GetOIDCSession retrieves an OIDC session by state
func (as *AuthStore) GetOIDCSession(state string) (*OIDCSession, bool) {
	session, exists := as.Sessions[state]
	return session, exists
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

// InitializeMacaroon initializes the macaroon configuration
func (as *AuthStore) InitializeMacaroon(secretKey, location string) error {
	if len(secretKey) < 32 {
		return fmt.Errorf("macaroon secret key must be at least 32 characters long")
	}

	as.MacaroonSecretKey = []byte(secretKey)
	as.MacaroonLocation = location
	return nil
}

// CreateMacaroon creates a new macaroon with the specified caveats
func (as *AuthStore) CreateMacaroon(caveats []string) (string, error) {
	// Create a new macaroon
	mac, err := macaroon.New(as.MacaroonSecretKey, []byte("random-id"), as.MacaroonLocation, macaroon.LatestVersion)
	if err != nil {
		return "", fmt.Errorf("failed to create macaroon: %w", err)
	}

	// Add caveats
	for _, caveat := range caveats {
		if err := mac.AddFirstPartyCaveat([]byte(caveat)); err != nil {
			return "", fmt.Errorf("failed to add caveat %s: %w", caveat, err)
		}
	}

	// Serialize the macaroon
	macBytes, err := mac.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("failed to marshal macaroon: %w", err)
	}

	// Encode as base64
	return base64.StdEncoding.EncodeToString(macBytes), nil
}

// OIDCAuthMiddleware provides OIDC authentication middleware (placeholder)
func (as *AuthStore) OIDCAuthMiddleware(next http.Handler) http.Handler {
	return next
}

// VerifyMacaroon verifies a macaroon token and extracts information
func (as *AuthStore) VerifyMacaroon(tokenString, requestPath, httpMethod string) (*AuthInfo, error) {
	// Decode the base64-encoded macaroon
	macBytes, err := base64.StdEncoding.DecodeString(tokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid macaroon encoding: %w", err)
	}

	// Deserialize the received macaroon
	receivedMac := &macaroon.Macaroon{}
	if err := receivedMac.UnmarshalBinary(macBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal macaroon: %w", err)
	}

	// Verify the macaroon signature and caveats
	// Pass the HTTP method to caveat verification for activity enforcement
	verifyCaveatWithPath := func(caveat string) error {
		return as.verifyCaveatWithMethod(caveat, requestPath, httpMethod)
	}
	if err := receivedMac.Verify(as.MacaroonSecretKey, verifyCaveatWithPath, nil); err != nil {
		return nil, fmt.Errorf("macaroon verification failed: %w", err)
	}

	// Extract authentication information from caveats
	authInfo, err := as.extractAuthInfoFromMacaroon(receivedMac)
	if err != nil {
		return nil, fmt.Errorf("failed to extract auth info: %w", err)
	}

	return authInfo, nil
}

// verifyCaveatWithMethod validates individual macaroon caveats, enforcing activity mapping to HTTP method
func (as *AuthStore) verifyCaveatWithMethod(caveat string, requestPath string, httpMethod string) error {
	parts := strings.SplitN(caveat, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid caveat format: %s", caveat)
	}

	key, value := parts[0], parts[1]

	switch key {
	case "before":
		// Parse the timestamp and check if it's still valid
		expiry, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return fmt.Errorf("invalid before caveat timestamp: %s", value)
		}
		if time.Now().After(expiry) {
			return fmt.Errorf("macaroon expired at %s", value)
		}
	case "id":
		// Identity caveat - will be used for username extraction
		if value == "" {
			return fmt.Errorf("empty id caveat")
		}
	case "activity":
		// Activity restrictions - validate that the activity matches the HTTP method
		activities := strings.Split(value, ",")
		requiredActivity := getActivityForMethod(httpMethod)
		found := false
		for _, activity := range activities {
			activity = strings.TrimSpace(activity)
			if strings.EqualFold(activity, requiredActivity) {
				found = true
			}
			if !isValidActivity(activity) {
				return fmt.Errorf("invalid activity: %s", activity)
			}
		}
		if !found {
			return fmt.Errorf("activity caveat %s does not match required activity %s for method %s", value, requiredActivity, httpMethod)
		}
	case "path":
		// Path restrictions - ensure the request path matches or is under the allowed path
		if !strings.HasPrefix(value, "/") {
			return fmt.Errorf("invalid path caveat: %s", value)
		}
		// Check if the request path is allowed by this caveat
		if !pathMatches(requestPath, value) {
			return fmt.Errorf("path %s not allowed by caveat path:%s", requestPath, value)
		}
	case "ip":
		// IP restrictions - basic validation that it's not empty
		if value == "" {
			return fmt.Errorf("empty ip caveat")
		}
	default:
		// Unknown caveat - log but don't fail (forward compatibility)
		log.Printf("[MACAROON] Unknown caveat: %s:%s", key, value)
	}

	return nil
}

// getActivityForMethod maps HTTP methods to activity strings per FTS3/dCache standards
func getActivityForMethod(method string) string {
	switch strings.ToUpper(method) {
	case "GET":
		return "DOWNLOAD"
	case "PUT":
		return "UPLOAD"
	case "PROPFIND":
		return "LIST"
	case "DELETE":
		return "DELETE"
	case "MKCOL":
		return "MANAGE"
	case "HEAD":
		return "READ"
	case "POST":
		return "WRITE"
	default:
		return ""
	}
}

// pathMatches checks if a request path is allowed by a path caveat
// The caveat path can be:
// - An exact path: /webdav/file.txt
// - A directory path: /webdav/ (allows access to /webdav/ and all subdirectories)
func pathMatches(requestPath, caveatPath string) bool {
	// Exact match
	if requestPath == caveatPath {
		return true
	}

	// If caveat path ends with '/', it allows access to subdirectories
	if strings.HasSuffix(caveatPath, "/") {
		return strings.HasPrefix(requestPath, caveatPath)
	}

	// If caveat path doesn't end with '/', it only allows exact match or subdirectories if it's a directory
	// Check if request path is a subdirectory of the caveat path
	return strings.HasPrefix(requestPath, caveatPath+"/")
}

// extractAuthInfoFromMacaroon extracts authentication information from macaroon caveats
func (as *AuthStore) extractAuthInfoFromMacaroon(mac *macaroon.Macaroon) (*AuthInfo, error) {
	authInfo := &AuthInfo{
		Method:  "macaroon",
		Details: make(map[string]interface{}),
	}

	// Look for caveats to extract identity and other information
	for _, cav := range mac.Caveats() {
		caveatStr := string(cav.Id)
		parts := strings.SplitN(caveatStr, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key, value := parts[0], parts[1]
		switch key {
		case "id":
			authInfo.Username = value
		case "activity":
			authInfo.Details["activities"] = strings.Split(value, ",")
		case "path":
			authInfo.Details["path"] = value
		case "before":
			authInfo.Details["expires"] = value
		case "ip":
			authInfo.Details["allowed_ips"] = value
		default:
			authInfo.Details[key] = value
		}
	}

	// If no username found in caveats, use a default
	if authInfo.Username == "" {
		return nil, fmt.Errorf("no id caveat found in macaroon")
	}

	return authInfo, nil
}

// isValidActivity checks if an activity is supported
func isValidActivity(activity string) bool {
	validActivities := map[string]bool{
		"DOWNLOAD": true,
		"UPLOAD":   true,
		"LIST":     true,
		"MANAGE":   true,
		"DELETE":   true,
		"READ":     true,
		"WRITE":    true,
	}
	return validActivities[strings.ToUpper(activity)]
}

// MacaroonAuthMiddleware provides macaroon bearer token authentication
func (as *AuthStore) MacaroonAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := logger.GetRequestID(r.Context())

		// Check for Bearer token in Authorization header
		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			log.Printf("[MACAROON-AUTH] [%s] No Bearer token provided", reqID)
			http.Error(w, "Bearer token required", http.StatusUnauthorized)
			return
		}

		token := auth[7:] // Remove "Bearer " prefix
		if token == "" {
			log.Printf("[MACAROON-AUTH] [%s] Empty Bearer token", reqID)
			http.Error(w, "Invalid Bearer token", http.StatusUnauthorized)
			return
		}

		// Verify the macaroon
		authInfo, err := as.VerifyMacaroon(token, r.URL.Path, r.Method)
		if err != nil {
			log.Printf("[MACAROON-AUTH] [%s] Macaroon verification failed: %v", reqID, err)
			http.Error(w, "Invalid macaroon token", http.StatusUnauthorized)
			return
		}

		log.Printf("[MACAROON-AUTH] [%s] User authenticated: %s", reqID, authInfo.Username)

		// Store authentication info in context
		ctx := SetAuthInfoInContext(r.Context(), authInfo)
		r = r.WithContext(ctx)

		// Call next handler
		next.ServeHTTP(w, r)
	})
}

// UnifiedAuthMiddleware provides authentication in the specified order: X.509 -> OIDC -> Macaroon -> Basic Auth
func (as *AuthStore) UnifiedAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := logger.GetRequestID(r.Context())

		// Debug: Log every request entering the unified auth middleware
		log.Printf("[UNIFIED-AUTH] [%s] Processing request %s %s, Content-Type: %s", reqID, r.Method, r.URL.Path, r.Header.Get("Content-Type"))

		// Track authentication attempts for logging
		// SKIP = not provided, FAIL = error/invalid, OK = success
		x509Status := "SKIP"     // SKIP = not provided
		oidcStatus := "SKIP"     // SKIP = not provided
		macaroonStatus := "SKIP" // SKIP = not provided
		basicStatus := "SKIP"    // SKIP = not provided

		// 1. Try X.509 Client Certificate Authentication first (if TLS enabled)
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			cert := r.TLS.PeerCertificates[0]

			// Manually verify the certificate against our CA
			if err := as.VerifyClientCertificate(cert); err == nil {
				x509Status = "OK"
				dn := x509utils.GetDNParts(cert)

				// Map DN to username using gridmap if available
				var username string
				if mappedUser, exists := as.Gridmap[dn]; exists {
					username = mappedUser
					log.Printf("[X509-AUTH] [%s] Certificate authenticated and CA verified - DN: %s -> Username: %s", reqID, dn, username)
				} else {
					username = dn
					log.Printf("[X509-AUTH] [%s] Certificate authenticated and CA verified - DN: %s (no mapping)", reqID, dn)
				}

				// Store authentication info in request context
				userAuthInfo := &AuthInfo{
					Username: username,
					Method:   "X.509 Certificate",
					Details: map[string]interface{}{
						"distinguished_name":  dn,
						"certificate_subject": cert.Subject.String(),
						"certificate_serial":  cert.SerialNumber.String(),
					},
				}
				if mappedUser, exists := as.Gridmap[dn]; exists {
					userAuthInfo.Details["gridmap_mapping"] = mappedUser
				}
				ctx := SetAuthInfoInContext(r.Context(), userAuthInfo)
				r = r.WithContext(ctx)

				// Log authentication summary and proceed
				log.Printf("[AUTH-FLOW] [%s] X509=%s OIDC=%s MACAROON=%s BASIC=%s -> SUCCESS (X.509)", reqID, x509Status, oidcStatus, macaroonStatus, basicStatus)
				next.ServeHTTP(w, r)
				return
			} else {
				// Certificate provided but verification failed
				x509Status = "FAIL"
				log.Printf("[X509-AUTH] [%s] Client certificate verification failed: %v - trying next auth method", reqID, err)
			}
		}

		// 2. Try OIDC Session Cookie Authentication
		if cookie, err := r.Cookie("oidc_session"); err == nil {
			// OIDC session cookie provided, validate it
			if session, exists := as.GetOIDCSession(cookie.Value); exists && session.Username != "" {
				oidcStatus = "OK"
				// Valid session, add username to context
				authInfo := &AuthInfo{
					Username: session.Username,
					Method:   "OIDC",
					Details: map[string]interface{}{
						"session_state": session.State,
						"expires_at":    session.ExpiresAt,
					},
				}
				ctx := SetAuthInfoInContext(r.Context(), authInfo)
				r = r.WithContext(ctx)

				log.Printf("[OIDC-AUTH] [%s] Valid OIDC session for user: %s", reqID, session.Username)
				// Log authentication summary and proceed
				log.Printf("[AUTH-FLOW] [%s] X509=%s OIDC=%s MACAROON=%s BASIC=%s -> SUCCESS (OIDC)", reqID, x509Status, oidcStatus, macaroonStatus, basicStatus)
				next.ServeHTTP(w, r)
				return
			}
			// Invalid or expired session - this is a failure
			oidcStatus = "FAIL"
			log.Printf("[OIDC-AUTH] [%s] Invalid/expired OIDC session - trying next auth method", reqID)
		}

		// 3. Try Macaroon Bearer Token Authentication
		if auth := r.Header.Get("Authorization"); auth != "" && strings.HasPrefix(auth, "Bearer ") {
			// Bearer token provided, validate it
			token := auth[7:] // Remove "Bearer " prefix
			if authInfo, err := as.VerifyMacaroon(token, r.URL.Path, r.Method); err == nil && authInfo != nil {
				macaroonStatus = "OK"
				log.Printf("[MACAROON-AUTH] [%s] Valid macaroon for user: %s", reqID, authInfo.Username)

				// Store authentication info in request context
				ctx := SetAuthInfoInContext(r.Context(), authInfo)
				r = r.WithContext(ctx)

				// Log authentication summary and proceed
				log.Printf("[AUTH-FLOW] [%s] X509=%s OIDC=%s MACAROON=%s BASIC=%s -> SUCCESS (MACAROON)", reqID, x509Status, oidcStatus, macaroonStatus, basicStatus)
				next.ServeHTTP(w, r)
				return
			} else {
				// Macaroon provided but verification failed
				macaroonStatus = "FAIL"
				log.Printf("[MACAROON-AUTH] [%s] Macaroon verification failed: %v - trying next auth method", reqID, err)
			}
		}

		// 4. Try Basic Authentication (includes app tokens)
		auth := r.Header.Get("Authorization")
		if auth != "" && strings.HasPrefix(auth, "Basic ") {
			// Basic auth header provided, validate it
			encoded := auth[6:] // Remove "Basic " prefix
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err == nil {
				// Split username:password
				credentials := string(decoded)
				parts := strings.SplitN(credentials, ":", 2)
				if len(parts) == 2 {
					username := parts[0]
					password := parts[1]

					// Verify credentials and get authentication method and additional info
					authenticated, authMethod, authInfo := as.VerifyCredentialsWithMethod(username, password)
					if authenticated {
						basicStatus = "OK"
						log.Printf("[BASIC-AUTH] [%s] Authentication successful for user: %s (method: %s)", reqID, username, authMethod)

						// Store authentication info in request context
						userAuthInfo := &AuthInfo{
							Username: username,
							Method:   "Basic Authentication",
							Details: map[string]interface{}{
								"auth_type": authMethod,
							},
						}
						if authMethod == "app-token" {
							userAuthInfo.Details["app_token"] = authInfo
						}
						ctx := SetAuthInfoInContext(r.Context(), userAuthInfo)
						r = r.WithContext(ctx)

						// Log authentication summary and proceed
						log.Printf("[AUTH-FLOW] [%s] X509=%s OIDC=%s MACAROON=%s BASIC=%s -> SUCCESS (BASIC)", reqID, x509Status, oidcStatus, macaroonStatus, basicStatus)
						next.ServeHTTP(w, r)
						return
					}
					// Invalid credentials - this is a failure
					basicStatus = "FAIL"
					log.Printf("[BASIC-AUTH] [%s] Authentication failed for user: %s", reqID, username)
				} else {
					// Malformed credentials - this is a failure
					basicStatus = "FAIL"
					log.Printf("[BASIC-AUTH] [%s] Malformed Basic auth credentials", reqID)
				}
			} else {
				// Base64 decode error - this is a failure
				basicStatus = "FAIL"
				log.Printf("[BASIC-AUTH] [%s] Invalid Base64 in Basic auth header", reqID)
			}
		}

		// 4. All authentication methods failed - log summary and return 401
		log.Printf("[AUTH-FLOW] [%s] X509=%s OIDC=%s MACAROON=%s BASIC=%s -> DENIED (401)", reqID, x509Status, oidcStatus, macaroonStatus, basicStatus)
		log.Printf("[AUTH] [%s] No valid authentication provided - requesting Basic Auth", reqID)
		w.Header().Set("WWW-Authenticate", `Basic realm="WebDAV Server"`)
		http.Error(w, "Authorization required", http.StatusUnauthorized)
	})
} // X509AuthMiddleware provides X.509 client certificate authentication and stores username in context
func (as *AuthStore) X509AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := logger.GetRequestID(r.Context())

		if r.TLS == nil {
			log.Printf("[X509-AUTH] [%s] Request over non-TLS connection - denying access", reqID)
			http.Error(w, "TLS required for X.509 authentication", http.StatusUnauthorized)
			return
		}

		if len(r.TLS.PeerCertificates) == 0 {
			log.Printf("[X509-AUTH] [%s] No client certificate provided - denying access", reqID)
			http.Error(w, "Client certificate required", http.StatusUnauthorized)
			return
		}

		cert := r.TLS.PeerCertificates[0]
		dn := x509utils.GetDNParts(cert)

		// Map DN to username using gridmap if available
		var username string
		if mappedUser, exists := as.Gridmap[dn]; exists {
			username = mappedUser
			log.Printf("[X509-AUTH] [%s] Certificate authenticated - DN: %s -> Username: %s", reqID, dn, username)
		} else {
			username = dn
			log.Printf("[X509-AUTH] [%s] Certificate authenticated - DN: %s (no mapping)", reqID, dn)
		}

		// Store username in request context for downstream handlers
		ctx := context.WithValue(r.Context(), usernameContextKey, username)
		r = r.WithContext(ctx)

		// Call next handler
		next.ServeHTTP(w, r)
	})
}
