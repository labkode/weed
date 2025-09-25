package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/labkode/weed/internal/auth"
	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/logger"
	"github.com/labkode/weed/internal/x509utils"
	"golang.org/x/net/webdav"
)

// WebDAVHandler wraps the webdav.Handler with custom functionality
type WebDAVHandler struct {
	*webdav.Handler
	Directory string
	Config    *config.Config
	AuthStore *auth.AuthStore
}

// NewWebDAVHandler creates a new WebDAV handler
func NewWebDAVHandler(directory string, cfg *config.Config, authStore *auth.AuthStore) *WebDAVHandler {
	webdavHandler := &webdav.Handler{
		Prefix:     "/webdav",  // Set prefix to /webdav so hrefs are generated correctly
		FileSystem: webdav.Dir(directory),
		LockSystem: webdav.NewMemLS(),
		Logger: func(r *http.Request, err error) {
			if err != nil {
				reqID := logger.GetRequestID(r.Context())

				// Demonstrate context usage in WebDAV logger
				var userInfo string
				if username, authenticated := auth.GetUsernameFromContext(r.Context()); authenticated {
					userInfo = fmt.Sprintf(" [user: %s]", username)
				}

				log.Printf("[WEBDAV-ERROR] [%s]%s %s", reqID, userInfo, err)
			}
		},
	}

	return &WebDAVHandler{
		Handler:   webdavHandler,
		Directory: directory,
		Config:    cfg,
		AuthStore: authStore,
	}
}

// ServeHTTP handles requests and demonstrates context usage
func (h *WebDAVHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqID := logger.GetRequestID(r.Context())
	
	// For the root path, serve our index page that shows the authenticated user
	if r.URL.Path == "/" && r.Method == "GET" {
		h.IndexHandler(w, r)
		return
	}

	// Check for macaroon minting requests (POST with application/macaroon-request content-type)
	// This happens AFTER authentication middleware has run
	if r.Method == "POST" && r.Header.Get("Content-Type") == "application/macaroon-request" {
		log.Printf("[MACAROON-MINTING] [%s] Processing authenticated macaroon minting request to %s", reqID, r.URL.Path)
		h.handleMacaroonRequest(w, r)
		return
	}

	// Check for infinite depth PROPFIND requests and reject them
	if r.Method == "PROPFIND" {
		depth := r.Header.Get("Depth")
		if depth == "infinity" {
			log.Printf("[SECURITY] [%s] Infinite depth PROPFIND request denied from %s", reqID, r.RemoteAddr)
			http.Error(w, "Infinite depth PROPFIND requests are not allowed", http.StatusForbidden)
			return
		}
	}

	// For all other paths, serve WebDAV
	h.Handler.ServeHTTP(w, r)
}

// IndexHandler serves the server info page with authenticated user info
func (h *WebDAVHandler) IndexHandler(w http.ResponseWriter, r *http.Request) {
	// Only serve the index page for the exact root path "/"
	// Return 404 for all other paths to prevent catch-all behavior
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Build the main page content without authentication status
	var authMethodsSection string

	// Generate authentication methods section - only show enabled methods
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s", scheme, r.Host)

	var authLinks []string
	var accessExamples []string

	// Only show links for enabled authentication methods
	if h.Config.BasicAuth {
		authLinks = append(authLinks, `<li><a href="/auth/basic">Basic Authentication</a> - Use username/password</li>`)
		accessExamples = append(accessExamples, fmt.Sprintf(`<li>curl with basic auth: curl -u user:pass %s/webdav/</li>`, baseURL))
	}

	if h.Config.X509Auth && h.Config.TLS {
		authLinks = append(authLinks, `<li><a href="/auth/x509">X.509 Certificate</a> - Use client certificate</li>`)
		accessExamples = append(accessExamples, fmt.Sprintf(`<li>curl with cert: curl --cert client.crt --key client.key %s/webdav/</li>`, baseURL))
	}

	if h.Config.OIDCAuth {
		authLinks = append(authLinks, `<li><a href="/auth/oidc">OIDC Authentication</a> - Use external provider</li>`)
	}

	// Build the authentication methods section
	authMethodsSection = ""
	if len(authLinks) > 0 {
		authMethodsSection += "<h3>Authentication Methods</h3>\n<ul>\n"
		for _, link := range authLinks {
			authMethodsSection += link + "\n"
		}
		authMethodsSection += "</ul>\n"
	}

	// Build the WebDAV access section
	if len(accessExamples) > 0 {
		authMethodsSection += "<h3>WebDAV Access</h3>\n<ul>\n"
		for _, example := range accessExamples {
			authMethodsSection += example + "\n"
		}
		authMethodsSection += "</ul>"
	}

	// Add utility links section
	authMethodsSection += "<h3>Utility Links</h3>\n<ul>\n"
	authMethodsSection += `<li><a href="/proc/whoami">View account details</a></li>` + "\n"
	authMethodsSection += `<li><a href="/proc/x509">View X.509 certificate info</a></li>` + "\n"
	authMethodsSection += "</ul>"

	// If no authentication methods are enabled
	if len(authLinks) == 0 {
		authMethodsSection = "<h3>Authentication</h3>\n<p>No authentication methods are currently enabled on this server.</p>\n" + authMethodsSection
	}

	html := `<!DOCTYPE html>
<html>
<head>
<title>WebDAV Server</title>
</head>
<body>
<h1>WebDAV Server</h1>

<p>Serving Directory: ` + h.Directory + `</p>
<p>Server Address: ` + r.Host + `</p>

` + authMethodsSection + `

</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// ProcX509Handler shows X.509 certificate information
func (h *WebDAVHandler) ProcX509Handler(w http.ResponseWriter, r *http.Request) {
	reqID := logger.GetRequestID(r.Context())

	w.Header().Set("Content-Type", "text/plain")

	// Demonstrate context usage: Get authenticated username from context
	if username, authenticated := auth.GetUsernameFromContext(r.Context()); authenticated {
		fmt.Fprintf(w, "Authenticated User (from context): %s\n\n", username)
	} else {
		fmt.Fprintf(w, "No authenticated user in context\n")
		fmt.Fprintf(w, "(This route is not protected by authentication middleware)\n\n")
	}

	if r.TLS == nil {
		fmt.Fprint(w, "No TLS connection\n")
		log.Printf("[X509-INFO] [%s] /proc/x509 accessed over non-TLS connection", reqID)
		return
	}

	fmt.Fprintf(w, "TLS Connection Info:\n")
	fmt.Fprintf(w, "Version: %d\n", r.TLS.Version)
	fmt.Fprintf(w, "Cipher Suite: %d\n", r.TLS.CipherSuite)
	fmt.Fprintf(w, "Server Name: %s\n", r.TLS.ServerName)
	fmt.Fprintf(w, "\n")

	if len(r.TLS.PeerCertificates) == 0 {
		fmt.Fprint(w, "No client certificate provided\n")
		if h.Config.X509Auth {
			fmt.Fprint(w, "X.509 Authentication Status: Would FAIL (no certificate)\n")
		}
		log.Printf("[X509-INFO] [%s] /proc/x509 - no client certificate", reqID)
		return
	}

	cert := r.TLS.PeerCertificates[0]
	fmt.Fprintf(w, "Client Certificate:\n")
	fmt.Fprintf(w, "Subject: %s\n", cert.Subject.String())
	fmt.Fprintf(w, "Issuer: %s\n", cert.Issuer.String())
	fmt.Fprintf(w, "Serial Number: %s\n", cert.SerialNumber.String())
	fmt.Fprintf(w, "Not Before: %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Fprintf(w, "Not After: %s\n", cert.NotAfter.Format(time.RFC3339))

	dn := x509utils.GetDNParts(cert)
	fmt.Fprintf(w, "Distinguished Name: %s\n", dn)

	// Show X.509 authentication simulation if X.509 auth is enabled
	if h.Config.X509Auth {
		fmt.Fprintf(w, "\nX.509 Authentication Simulation:\n")
		fmt.Fprintf(w, "X.509 Auth Enabled: %t\n", h.Config.X509Auth)
		fmt.Fprintf(w, "TLS Enabled: %t\n", h.Config.TLS)

		if h.Config.X509Auth && h.Config.TLS {
			fmt.Fprintf(w, "Authentication Status: Would SUCCEED\n")

			// We need access to the AuthStore's gridmap to check mapping
			// For now, we'll indicate that authentication would succeed
			// and that the DN would be used as username unless mapped
			fmt.Fprintf(w, "Username would be: %s\n", dn)
			fmt.Fprintf(w, "Method: X.509 Certificate\n")
			fmt.Fprintf(w, "Note: Username is the DN unless mapped via gridmap file\n")
			fmt.Fprintf(w, "To authenticate: Visit /auth/x509 or any protected route\n")
		} else if !h.Config.TLS {
			fmt.Fprintf(w, "Authentication Status: Would FAIL (TLS not enabled)\n")
		}
	} else {
		fmt.Fprintf(w, "\nX.509 Authentication: DISABLED on this server\n")
	}

	log.Printf("[X509-INFO] [%s] /proc/x509 accessed - DN: %s", reqID, dn)
}

// WhoAmIHandler shows information about the current authenticated user
func (h *WebDAVHandler) WhoAmIHandler(w http.ResponseWriter, r *http.Request) {
	reqID := logger.GetRequestID(r.Context())

	w.Header().Set("Content-Type", "text/plain")

	fmt.Fprintf(w, "=== WebDAV Server - Who Am I ===\n\n")

	// Check if user is authenticated via new AuthInfo context
	if authInfo, authenticated := auth.GetAuthInfoFromContext(r.Context()); authenticated {
		fmt.Fprintf(w, "Status: Authenticated\n")
		fmt.Fprintf(w, "Username: %s\n", authInfo.Username)
		fmt.Fprintf(w, "Authentication Method: %s\n", authInfo.Method)
		fmt.Fprintf(w, "\nAuthentication Details:\n")
		for key, value := range authInfo.Details {
			fmt.Fprintf(w, "  %s: %v\n", key, value)
		}
	} else if username, hasUsername := auth.GetUsernameFromContext(r.Context()); hasUsername {
		// Fallback for backward compatibility
		fmt.Fprintf(w, "Status: Authenticated (legacy)\n")
		fmt.Fprintf(w, "Username: %s\n", username)
		fmt.Fprintf(w, "Authentication Method: Unknown (legacy context)\n")
	} else {
		fmt.Fprintf(w, "Status: Not Authenticated\n")
		fmt.Fprintf(w, "Username: Anonymous\n")
		fmt.Fprintf(w, "Authentication Method: None\n")
	}

	// Additional request information
	fmt.Fprintf(w, "\nRequest Information:\n")
	fmt.Fprintf(w, "  Request ID: %s\n", reqID)
	fmt.Fprintf(w, "  Remote Address: %s\n", r.RemoteAddr)
	fmt.Fprintf(w, "  User Agent: %s\n", r.UserAgent())
	fmt.Fprintf(w, "  Method: %s\n", r.Method)
	fmt.Fprintf(w, "  Path: %s\n", r.URL.Path)
	fmt.Fprintf(w, "  TLS: %t\n", r.TLS != nil)

	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		fmt.Fprintf(w, "  Client Certificate: Present\n")
		fmt.Fprintf(w, "  Certificate Subject: %s\n", r.TLS.PeerCertificates[0].Subject.String())
	}

	log.Printf("[WHOAMI] [%s] /whoami accessed from %s", reqID, r.RemoteAddr)
}

// OIDCHandler handles the initial OIDC authentication request
func (h *WebDAVHandler) OIDCHandler(authStore *auth.AuthStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := logger.GetRequestID(r.Context())

		// Generate state parameter for CSRF protection
		state := authStore.GenerateState()

		// Store session
		session := &auth.OIDCSession{
			State:     state,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(10 * time.Minute),
		}
		authStore.StoreOIDCSession(state, session)

		// Redirect to OIDC provider
		authURL := authStore.OAuth2Config.AuthCodeURL(state)
		log.Printf("[OIDC] [%s] Redirecting to OIDC provider: %s", reqID, authURL)

		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// BasicAuthSuccessHandler handles successful basic authentication
func (h *WebDAVHandler) BasicAuthSuccessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	authInfo, authenticated := auth.GetAuthInfoFromContext(r.Context())
	if !authenticated {
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
	<title>Basic Authentication Success</title>
</head>
<body>
	<h1>Basic Authentication Successful!</h1>
	<p>Welcome, <strong>%s</strong>!</p>
	<p>You have successfully authenticated using Basic Authentication.</p>
	
	<h3>Next Steps:</h3>
	<ul>
		<li><a href="/webdav/">Access WebDAV content</a></li>
		<li><a href="/whoami">View account information</a></li>
		<li><a href="/">Return to home page</a></li>
	</ul>
</body>
</html>`, authInfo.Username)

	w.Write([]byte(html))
}

// X509AuthSuccessHandler handles successful X.509 certificate authentication
func (h *WebDAVHandler) X509AuthSuccessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	authInfo, authenticated := auth.GetAuthInfoFromContext(r.Context())
	if !authenticated {
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
	<title>X.509 Certificate Authentication Success</title>
</head>
<body>
	<h1>X.509 Certificate Authentication Successful!</h1>
	<p>Welcome, <strong>%s</strong>!</p>
	<p>You have successfully authenticated using your client certificate.</p>
	
	<h3>Certificate Information:</h3>
	<p>Certificate Subject: %v</p>
	
	<h3>Next Steps:</h3>
	<ul>
		<li><a href="/webdav/">Access WebDAV content</a></li>
		<li><a href="/proc/x509">View certificate information</a></li>
		<li><a href="/whoami">View account information</a></li>
		<li><a href="/">Return to home page</a></li>
	</ul>
</body>
</html>`, authInfo.Username, authInfo.Details["subject"])

	w.Write([]byte(html))
}

// OIDCRedirectHandler handles the OIDC callback/redirect
func (h *WebDAVHandler) OIDCRedirectHandler(authStore *auth.AuthStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := logger.GetRequestID(r.Context())

		// Get authorization code and state from query parameters
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		if code == "" {
			log.Printf("[OIDC] [%s] No authorization code received", reqID)
			http.Error(w, "Authorization code not received", http.StatusBadRequest)
			return
		}

		if state == "" {
			log.Printf("[OIDC] [%s] No state parameter received", reqID)
			http.Error(w, "State parameter not received", http.StatusBadRequest)
			return
		}

		// Validate state parameter
		session, exists := authStore.GetOIDCSession(state)
		if !exists {
			log.Printf("[OIDC] [%s] Invalid or expired state: %s", reqID, state)
			http.Error(w, "Invalid or expired state", http.StatusBadRequest)
			return
		}

		// Exchange code for token
		ctx := context.Background()
		token, err := authStore.OAuth2Config.Exchange(ctx, code)
		if err != nil {
			log.Printf("[OIDC] [%s] Failed to exchange code for token: %v", reqID, err)
			http.Error(w, "Failed to exchange authorization code", http.StatusInternalServerError)
			return
		}

		// Extract ID token
		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			log.Printf("[OIDC] [%s] No ID token in response", reqID)
			http.Error(w, "No ID token received", http.StatusInternalServerError)
			return
		}

		// Verify ID token
		idToken, err := authStore.OIDCVerifier.Verify(ctx, rawIDToken)
		if err != nil {
			log.Printf("[OIDC] [%s] Failed to verify ID token: %v", reqID, err)
			http.Error(w, "Failed to verify ID token", http.StatusUnauthorized)
			return
		}

		// Extract claims
		var claims struct {
			Email    string `json:"email"`
			Username string `json:"preferred_username"`
			Name     string `json:"name"`
			Subject  string `json:"sub"`
		}

		if err := idToken.Claims(&claims); err != nil {
			log.Printf("[OIDC] [%s] Failed to extract claims: %v", reqID, err)
			http.Error(w, "Failed to extract user information", http.StatusInternalServerError)
			return
		}

		// Determine username (prefer username, fallback to email, then subject)
		username := claims.Username
		if username == "" {
			username = claims.Email
		}
		if username == "" {
			username = claims.Subject
		}

		// Update session with username
		session.Username = username
		session.ExpiresAt = time.Now().Add(24 * time.Hour) // Session valid for 24 hours
		authStore.StoreOIDCSession(state, session)

		// Set session cookie
		cookie := &http.Cookie{
			Name:     "oidc_session",
			Value:    state,
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil,
			MaxAge:   24 * 60 * 60, // 24 hours
		}
		http.SetCookie(w, cookie)

		log.Printf("[OIDC] [%s] Authentication successful - Username: %s", reqID, username)

		// Redirect to root path
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// handleMacaroonRequest handles POST requests with application/macaroon-request content-type
func (h *WebDAVHandler) handleMacaroonRequest(w http.ResponseWriter, r *http.Request) {
	reqID := logger.GetRequestID(r.Context())

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the JSON request body
	var req struct {
		Caveats  []string `json:"caveats"`
		Validity string   `json:"validity,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[MACAROON-REQUEST] [%s] Failed to parse request body: %v", reqID, err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Process caveats
	caveats := req.Caveats

	// Handle validity field (ISO 8601 duration)
	if req.Validity != "" {
		expiryTime, err := parseISODuration(req.Validity)
		if err != nil {
			log.Printf("[MACAROON-REQUEST] [%s] Failed to parse validity duration: %v", reqID, err)
			http.Error(w, "Invalid validity duration", http.StatusBadRequest)
			return
		}
		caveats = append(caveats, fmt.Sprintf("before:%s", expiryTime.Format(time.RFC3339)))
	}

	// Get auth store from context or create one
	// For now, we'll need to pass it somehow - let's modify the handler to accept auth store
	// This is a temporary solution - in a real implementation, the auth store would be available
	authStore := h.AuthStore
	if authStore == nil {
		log.Printf("[MACAROON-REQUEST] [%s] AuthStore not available", reqID)
		http.Error(w, "Macaroon authentication not configured", http.StatusInternalServerError)
		return
	}

	// Get the authenticated user from the context
	var authenticatedUser string
	if authInfo, authenticated := auth.GetAuthInfoFromContext(r.Context()); authenticated {
		authenticatedUser = authInfo.Username
		log.Printf("[MACAROON-REQUEST] [%s] Found authenticated user via AuthInfo: %s", reqID, authenticatedUser)
	} else if username, hasUsername := auth.GetUsernameFromContext(r.Context()); hasUsername {
		authenticatedUser = username
		log.Printf("[MACAROON-REQUEST] [%s] Found authenticated user via username context: %s", reqID, authenticatedUser)
	} else {
		log.Printf("[MACAROON-REQUEST] [%s] No authenticated user found in context", reqID)
		http.Error(w, "Authentication required for macaroon creation", http.StatusUnauthorized)
		return
	}

	// Add the authenticated user's ID as a caveat
	caveats = append(caveats, fmt.Sprintf("id:%s", authenticatedUser))

	// Create macaroon with the provided caveats
	macaroon, err := authStore.CreateMacaroon(caveats)
	if err != nil {
		log.Printf("[MACAROON-REQUEST] [%s] Failed to create macaroon: %v", reqID, err)
		http.Error(w, "Failed to create macaroon", http.StatusInternalServerError)
		return
	}

	log.Printf("[MACAROON-REQUEST] [%s] Created macaroon for user: %s", reqID, authenticatedUser)

	// Return the macaroon as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"macaroon": macaroon,
	})

	log.Printf("[MACAROON-REQUEST] [%s] Macaroon created successfully", reqID)
}

// MacaroonMintingMiddleware is no longer needed as macaroon handling is done in ServeHTTP after authentication
// This middleware is kept for backward compatibility but just passes through to the next handler
func (h *WebDAVHandler) MacaroonMintingMiddleware(next http.Handler) http.Handler {
	return next
}

// parseISODuration parses an ISO 8601 duration string and returns the expiry time
func parseISODuration(durationStr string) (time.Time, error) {
	// Simple implementation for ISO 8601 duration like "PT60M" (60 minutes)
	// This is a basic implementation - a full ISO 8601 parser would be more comprehensive
	if !strings.HasPrefix(durationStr, "PT") {
		return time.Time{}, fmt.Errorf("invalid ISO duration format: %s", durationStr)
	}

	duration := durationStr[2:] // Remove "PT" prefix
	var hours, minutes, seconds int

	// Parse duration components (basic implementation)
	parts := strings.FieldsFunc(duration, func(r rune) bool {
		return r == 'H' || r == 'M' || r == 'S'
	})

	for i, part := range parts {
		if strings.HasSuffix(duration, "H") && i == len(parts)-1 {
			if h, err := strconv.Atoi(part); err == nil {
				hours = h
			}
		} else if strings.HasSuffix(duration, "M") && i == len(parts)-1 {
			if m, err := strconv.Atoi(part); err == nil {
				minutes = m
			}
		} else if strings.HasSuffix(duration, "S") && i == len(parts)-1 {
			if s, err := strconv.Atoi(part); err == nil {
				seconds = s
			}
		}
	}

	// Calculate expiry time
	durationTime := time.Duration(hours)*time.Hour + time.Duration(minutes)*time.Minute + time.Duration(seconds)*time.Second
	return time.Now().Add(durationTime), nil
}
