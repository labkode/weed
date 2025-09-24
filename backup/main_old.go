package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/webdav"
)

var portFlag = flag.Int("port", 9000, "tcp port")
var addressFlag = flag.String("address", "", "bind address (default: all interfaces)")
var dirFlag = flag.String("dir", ".", "local directory to serve")
var tlsFlag = flag.Bool("tls", false, "enable tls")
var x509AuthFlag = flag.Bool("x509-auth", false, "enable X.509 client certificate authentication (requires TLS)")
var caCertFlag = flag.String("ca-cert", "", "path to CA certificate file for X.509 authentication")
var gridmapFlag = flag.String("gridmap-file", "/etc/grid-security/grid-mapfile", "path to gridmap file for X.509 DN to username mapping")
var basicAuthFlag = flag.Bool("basic-auth", false, "enable HTTP Basic Authentication")
var htpasswdFlag = flag.String("htpasswd-file", ".htpasswd", "path to htpasswd file for basic authentication")
var appTokensFlag = flag.String("app-tokens-file", ".app-tokens", "path to app tokens file for application password authentication")

// Context key for storing the authenticated username
const usernameContextKey contextKey = "username"

// getUsernameFromContext retrieves the authenticated username from the request context
func getUsernameFromContext(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(usernameContextKey).(string)
	return username, ok
}

// Global gridmap for DN to username mapping
var gridmap map[string]string

// Global htpasswd for basic auth
var htpasswd map[string]string

// Global app tokens for application passwords
var appTokens map[string]string

// loadGridmap loads and parses the gridmap file
func loadGridmap(filename string) (map[string]string, error) {
	result := make(map[string]string)
	
	file, err := os.Open(filename)
	if err != nil {
		return result, err
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

	return result, scanner.Err()
}

// loadHtpasswd loads and parses the htpasswd file
func loadHtpasswd(filename string) (map[string]string, error) {
	result := make(map[string]string)
	
	file, err := os.Open(filename)
	if err != nil {
		return result, err
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

	return result, scanner.Err()
}

// loadAppTokens loads and parses the app tokens file
func loadAppTokens(filename string) (map[string]string, error) {
	result := make(map[string]string)
	
	file, err := os.Open(filename)
	if err != nil {
		return result, err
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

	return result, scanner.Err()
}

// verifyPassword checks if the provided password matches the stored hash
func verifyPassword(storedHash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
	return err == nil
}

// verifyCredentialsWithMethod verifies username/password and returns authentication method and additional info
func verifyCredentialsWithMethod(username, password string) (bool, string, string) {
	// First check if it's an app token (password is 64 char hex string)
	if len(password) == 64 {
		if tokenUsername, exists := appTokens[password]; exists && tokenUsername == username {
			// Return first 8 characters of token for logging
			tokenPrefix := password[:8] + "..."
			return true, "app-token", tokenPrefix
		}
	}
	
	// Check regular password authentication
	if storedHash, exists := htpasswd[username]; exists {
		if verifyPassword(storedHash, password) {
			return true, "password", ""
		}
	}
	
	return false, "unknown", ""
}

type handler struct {
	*webdav.Handler
}

// ServeHTTP handles requests and demonstrates context usage
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// For the root path, serve our index page that shows the authenticated user
	if r.URL.Path == "/" && r.Method == "GET" {
		h.indexHandler(w, r)
		return
	}
	
	// For all other paths, serve WebDAV
	h.Handler.ServeHTTP(w, r)
}

// indexHandler serves the server info page with authenticated user info
func (h *handler) indexHandler(w http.ResponseWriter, r *http.Request) {
	// Get authenticated username from context - this is the key demonstration of context usage
	var userInfo string
	if username, authenticated := getUsernameFromContext(r.Context()); authenticated {
		userInfo = fmt.Sprintf("<p>Authenticated as: <strong>%s</strong></p>", username)
	} else {
		userInfo = "<p><em>Not authenticated</em></p>"
	}

	html := `<!DOCTYPE html>
<html>
<head>
<title>WebDAV Server</title>
</head>
<body>
<h1>WebDAV Server</h1>
<p>This is a WebDAV server serving: <strong>` + *dirFlag + `</strong></p>
<p>Server address: ` + r.Host + `</p>
` + userInfo + `
<p><strong>Context Demonstration:</strong> The username above was retrieved from the request context, 
showing how authentication middlewares store the username for downstream handlers to use.</p>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// procX509Handler shows X.509 certificate information
func (h *handler) procX509Handler(w http.ResponseWriter, r *http.Request) {
	reqID := getRequestID(r.Context())
	
	w.Header().Set("Content-Type", "text/plain")
	
	// Demonstrate context usage: Get authenticated username from context
	if username, authenticated := getUsernameFromContext(r.Context()); authenticated {
		fmt.Fprintf(w, "Authenticated User (from context): %s\n\n", username)
	} else {
		fmt.Fprintf(w, "No authenticated user in context\n\n")
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
	
	dn := getDNParts(cert)
	fmt.Fprintf(w, "Distinguished Name: %s\n", dn)
	
	if username, mapped := gridmap[dn]; mapped {
		fmt.Fprintf(w, "Mapped Username: %s\n", username)
	} else {
		fmt.Fprintf(w, "Username: %s (DN)\n", dn)
	}
	
	log.Printf("[X509-INFO] [%s] /proc/x509 accessed - DN: %s", reqID, dn)
}

// BasicAuthMiddleware provides HTTP Basic Authentication and stores username in context
func BasicAuthMiddleware(next http.Handler) http.Handler {
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
		authenticated, authMethod, authInfo := verifyCredentialsWithMethod(username, password)
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
		
		// CRITICAL: Store username in request context for downstream handlers to use
		ctx := context.WithValue(r.Context(), usernameContextKey, username)
		r = r.WithContext(ctx)
		
		// Call next handler
		next.ServeHTTP(w, r)
	})
}

// X509AuthMiddleware provides X.509 client certificate authentication and stores username in context
func X509AuthMiddleware(next http.Handler) http.Handler {
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
		dn := getDNParts(cert)
		
		// Map DN to username using gridmap if available
		var username string
		if mappedUser, exists := gridmap[dn]; exists {
			username = mappedUser
			log.Printf("[X509-AUTH] [%s] Certificate authenticated - DN: %s -> Username: %s", reqID, dn, username)
		} else {
			username = dn
			log.Printf("[X509-AUTH] [%s] Certificate authenticated - DN: %s (no mapping)", reqID, dn)
		}
		
		// CRITICAL: Store username in request context for downstream handlers to use
		ctx := context.WithValue(r.Context(), usernameContextKey, username)
		r = r.WithContext(ctx)
		
		// Call next handler
		next.ServeHTTP(w, r)
	})
}

func main() {
	// Check for utility commands
	if len(os.Args) > 1 && os.Args[1] == "utils" {
		handleUtilsCommand()
		return
	}

	flag.Parse()

	// Validate configuration
	if *x509AuthFlag && !*tlsFlag {
		log.Fatal("X.509 authentication requires TLS to be enabled")
	}

	// Initialize authentication systems if enabled
	if *basicAuthFlag {
		var err error
		htpasswd, err = loadHtpasswd(*htpasswdFlag)
		if err != nil {
			log.Printf("[HTPASSWD] Warning: Failed to load htpasswd file %s: %v", *htpasswdFlag, err)
			htpasswd = make(map[string]string)
		} else {
			log.Printf("[HTPASSWD] Successfully loaded %d users from %s", len(htpasswd), *htpasswdFlag)
		}

		// Load app tokens
		appTokens, err = loadAppTokens(*appTokensFlag)
		if err != nil {
			log.Printf("[APP-TOKENS] Warning: Failed to load app tokens file %s: %v", *appTokensFlag, err)
			appTokens = make(map[string]string)
		} else {
			log.Printf("[APP-TOKENS] Successfully loaded %d app tokens from %s", len(appTokens), *appTokensFlag)
		}
	}

	if *x509AuthFlag {
		var err error
		gridmap, err = loadGridmap(*gridmapFlag)
		if err != nil {
			log.Printf("[GRIDMAP] Warning: Failed to load gridmap file %s: %v", *gridmapFlag, err)
			gridmap = make(map[string]string)
		} else {
			log.Printf("[GRIDMAP] Successfully loaded %d DN mappings from %s", len(gridmap), *gridmapFlag)
		}
	}

	// Create WebDAV handler
	webdavHandler := &webdav.Handler{
		Prefix:     "/",
		FileSystem: webdav.Dir(*dirFlag),
		LockSystem: webdav.NewMemLS(),
		Logger: func(r *http.Request, err error) {
			if err != nil {
				reqID := getRequestID(r.Context())
				
				// Demonstrate context usage in WebDAV logger
				var userInfo string
				if username, authenticated := getUsernameFromContext(r.Context()); authenticated {
					userInfo = fmt.Sprintf(" [user: %s]", username)
				}
				
				log.Printf("[WEBDAV-ERROR] [%s]%s %s", reqID, userInfo, err)
			}
		},
	}

	// Create custom handler that demonstrates context usage
	h := &handler{webdavHandler}

	// Setup middleware chain
	var middlewareChain http.Handler = h

	// Add authentication middleware - these store the username in context
	if *basicAuthFlag {
		middlewareChain = BasicAuthMiddleware(middlewareChain)
	}
	if *x509AuthFlag {
		middlewareChain = X509AuthMiddleware(middlewareChain)
	}

	// Add logging middleware
	middlewareChain = LoggingMiddleware(middlewareChain)

	// Create HTTP server
	address := fmt.Sprintf("%s:%d", *addressFlag, *portFlag)
	
	// Setup routes
	mux := http.NewServeMux()
	mux.Handle("/", middlewareChain)
	mux.HandleFunc("/proc/x509", h.procX509Handler)

	s := &http.Server{
		Addr:    address,
		Handler: mux,
	}

	log.Println("=== WebDAV Server Starting ===")
	log.Printf("Configuration:")
	log.Printf("  - Port: %d", *portFlag)
	log.Printf("  - Address: %s", *addressFlag)
	log.Printf("  - Directory: %s", *dirFlag)
	log.Printf("  - TLS: %t", *tlsFlag)
	log.Printf("  - X.509 Auth: %t", *x509AuthFlag)
	log.Printf("  - Basic Auth: %t", *basicAuthFlag)
	if *basicAuthFlag {
		log.Printf("  - Htpasswd File: %s", *htpasswdFlag)
		log.Printf("  - App Tokens File: %s", *appTokensFlag)
	}
	log.Println("===============================")
	log.Printf("Context Feature: Authentication middlewares store username in request context")
	log.Printf("Downstream handlers can access the authenticated username using getUsernameFromContext()")

	if *tlsFlag {
		// Setup TLS configuration
		tlsConfig := &tls.Config{}
		
		if *x509AuthFlag {
			// Load CA certificate if specified
			if *caCertFlag != "" {
				caCert, err := ioutil.ReadFile(*caCertFlag)
				if err != nil {
					log.Fatalf("Failed to read CA certificate: %v", err)
				}
				
				caCertPool := x509.NewCertPool()
				if !caCertPool.AppendCertsFromPEM(caCert) {
					log.Fatal("Failed to parse CA certificate")
				}
				
				tlsConfig.ClientCAs = caCertPool
				tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
				log.Printf("[STARTUP] X.509 client authentication enabled with CA: %s", *caCertFlag)
			} else {
				tlsConfig.ClientAuth = tls.RequestClientCert
				log.Printf("[STARTUP] X.509 client authentication enabled (no CA verification)")
			}
		}
		
		s.TLSConfig = tlsConfig
		log.Printf("[STARTUP] Starting HTTPS server on %s (serving directory: %s)", address, *dirFlag)
		log.Fatal(s.ListenAndServeTLS("server.crt", "server.key"))
	} else {
		log.Printf("[STARTUP] Starting HTTP server on %s (serving directory: %s)", address, *dirFlag)
		log.Fatal(s.ListenAndServe())
	}
}

// Utility functions for token management, certificates, etc.
func handleUtilsCommand() {
	if len(os.Args) < 3 {
		printUtilsHelp()
		return
	}

	switch os.Args[2] {
	case "cert":
		handleCertCommand()
	case "password":
		handlePasswordCommand()
	case "token":
		handleTokenCommand()
	default:
		fmt.Printf("Unknown utils command: %s\n", os.Args[2])
		printUtilsHelp()
	}
}

func printUtilsHelp() {
	fmt.Println("Usage: weed utils <command>")
	fmt.Println("")
	fmt.Println("Available commands:")
	fmt.Println("  cert     - Generate TLS certificates")
	fmt.Println("  password - Generate password hashes")
	fmt.Println("  token    - Manage application tokens")
}

func handleCertCommand() {
	if err := generateTLSCertificates(); err != nil {
		fmt.Printf("Error generating certificates: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Generated server.crt and server.key")
}

func handlePasswordCommand() {
	if len(os.Args) < 5 {
		fmt.Println("Usage: weed utils password <username> <password>")
		return
	}

	username := os.Args[3]
	password := os.Args[4]

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Printf("Error hashing password: %v\n", err)
		os.Exit(1)
	}

	entry := fmt.Sprintf("%s:%s\n", username, string(hashedPassword))
	
	file, err := os.OpenFile(".htpasswd", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Printf("Error opening .htpasswd file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	if _, err := file.WriteString(entry); err != nil {
		fmt.Printf("Error writing to .htpasswd file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Added user '%s' to .htpasswd\n", username)
}

func handleTokenCommand() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: weed utils token <generate|list|revoke>")
		return
	}

	switch os.Args[3] {
	case "generate":
		if len(os.Args) < 5 {
			fmt.Println("Usage: weed utils token generate <username>")
			return
		}
		username := os.Args[4]
		token := generateAppToken()
		entry := fmt.Sprintf("%s:%s\n", token, username)
		
		file, err := os.OpenFile(*appTokensFlag, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			fmt.Printf("Error opening app tokens file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		
		if _, err := file.WriteString(entry); err != nil {
			fmt.Printf("Error writing token: %v\n", err)
			os.Exit(1)
		}
		
		fmt.Printf("Generated token for user '%s': %s\n", username, token)
	default:
		fmt.Println("Usage: weed utils token <generate|list|revoke>")
	}
}

func generateAppToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func generateTLSCertificates() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	certOut, err := os.Create("server.crt")
	if err != nil {
		return err
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	keyOut, err := os.Create("server.key")
	if err != nil {
		return err
	}
	defer keyOut.Close()

	privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyDER}); err != nil {
		return err
	}

	return nil
}
