package handlers

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/net/webdav"
	"github.com/labkode/weed/internal/auth"
	"github.com/labkode/weed/internal/logger"
	"github.com/labkode/weed/internal/x509utils"
)

// WebDAVHandler wraps the webdav.Handler with custom functionality
type WebDAVHandler struct {
	*webdav.Handler
	Directory string
}

// NewWebDAVHandler creates a new WebDAV handler
func NewWebDAVHandler(directory string) *WebDAVHandler {
	webdavHandler := &webdav.Handler{
		Prefix:     "/",
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
	}
}

// ServeHTTP handles requests and demonstrates context usage
func (h *WebDAVHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// For the root path, serve our index page that shows the authenticated user
	if r.URL.Path == "/" && r.Method == "GET" {
		h.IndexHandler(w, r)
		return
	}
	
	// For all other paths, serve WebDAV
	h.Handler.ServeHTTP(w, r)
}

// IndexHandler serves the server info page with authenticated user info
func (h *WebDAVHandler) IndexHandler(w http.ResponseWriter, r *http.Request) {
	// Get authenticated username from context - this is the key demonstration of context usage
	var userInfo string
	if username, authenticated := auth.GetUsernameFromContext(r.Context()); authenticated {
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
<p>This is a WebDAV server serving: <strong>` + h.Directory + `</strong></p>
<p>Server address: ` + r.Host + `</p>
` + userInfo + `
<p><strong>Context Demonstration:</strong> The username above was retrieved from the request context, 
showing how authentication middlewares store the username for downstream handlers to use.</p>
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
	
	dn := x509utils.GetDNParts(cert)
	fmt.Fprintf(w, "Distinguished Name: %s\n", dn)
	
	log.Printf("[X509-INFO] [%s] /proc/x509 accessed - DN: %s", reqID, dn)
}
