package logger

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"time"
)

// Request ID context key
type contextKey string

const requestIDKey contextKey = "requestID"

// GenerateRequestID creates a short unique identifier for the request
func GenerateRequestID() string {
	bytes := make([]byte, 4)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// GetRequestID extracts the request ID from context
func GetRequestID(ctx context.Context) string {
	if reqID, ok := ctx.Value(requestIDKey).(string); ok {
		return reqID
	}
	return "unknown"
}

// Logger logs a request with optional error information
func Logger(r *http.Request, err error) {
	reqID := GetRequestID(r.Context())
	remoteAddr := r.RemoteAddr
	if r.Header.Get("X-Forwarded-For") != "" {
		remoteAddr = r.Header.Get("X-Forwarded-For")
	}

	if err != nil {
		log.Printf("[ERROR] [%s] %s %s %s - Error: %v", reqID, remoteAddr, r.Method, r.URL.Path, err)
	} else {
		log.Printf("[WebDAV] [%s] %s %s %s - Success", reqID, remoteAddr, r.Method, r.URL.Path)
	}
}

// Middleware wraps an http.Handler and logs all requests and responses
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Generate unique request ID
		requestID := GenerateRequestID()

		// Add request ID to context
		ctx := context.WithValue(r.Context(), requestIDKey, requestID)
		r = r.WithContext(ctx)

		// Get client IP
		remoteAddr := r.RemoteAddr
		if r.Header.Get("X-Forwarded-For") != "" {
			remoteAddr = r.Header.Get("X-Forwarded-For")
		}

		// Create a response writer wrapper to capture status code
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: 200}

		// Call the next handler
		next.ServeHTTP(lrw, r)

		// Log the complete request-response in a single line
		duration := time.Since(start)
		userAgent := r.Header.Get("User-Agent")
		if userAgent == "" {
			userAgent = "-"
		}

		log.Printf("[HTTP] [%s] %s %s %s %s -> %d (%v) [%s]",
			requestID, remoteAddr, r.Method, r.URL.Path, r.Proto, lrw.statusCode, duration, userAgent)
	})
}

// loggingResponseWriter wraps http.ResponseWriter to capture status code
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}
