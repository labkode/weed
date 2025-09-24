package auth

import (
	"bufio"
	"context"
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"github.com/labkode/weed/internal/x509utils"
)

// Context key for storing the authenticated username
type contextKey string

const usernameContextKey contextKey = "username"

// GetUsernameFromContext retrieves the authenticated username from the request context
func GetUsernameFromContext(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(usernameContextKey).(string)
	return username, ok
}

// AuthStore holds authentication data
type AuthStore struct {
	Gridmap   map[string]string
	Htpasswd  map[string]string
	AppTokens map[string]string
}

// NewAuthStore creates a new authentication store
func NewAuthStore() *AuthStore {
	return &AuthStore{
		Gridmap:   make(map[string]string),
		Htpasswd:  make(map[string]string),
		AppTokens: make(map[string]string),
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

// VerifyPassword checks if the provided password matches the stored hash
func (as *AuthStore) VerifyPassword(storedHash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
	return err == nil
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
		reqID := getRequestID(r.Context())
		
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
		
		// Store username in request context for downstream handlers
		ctx := context.WithValue(r.Context(), usernameContextKey, username)
		r = r.WithContext(ctx)
		
		// Call next handler
		next.ServeHTTP(w, r)
	})
}

// X509AuthMiddleware provides X.509 client certificate authentication and stores username in context
func (as *AuthStore) X509AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := getRequestID(r.Context())
		
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

// TODO: This function should be imported from logger package
func getRequestID(ctx context.Context) string {
	// Temporary implementation - this should be imported from logger package
	return "temp-id"
}
