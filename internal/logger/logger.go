package logger

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/labkode/weed/internal/metrics"
)

// Request info context key
type contextKey string

const requestInfoKey contextKey = "requestInfo"

// requestInfo is shared between the logging middleware and inner handlers so that
// values discovered downstream (e.g. the authenticated user) end up in the access log.
type requestInfo struct {
	id       string
	username string
}

// GenerateRequestID creates a short unique identifier for the request
func GenerateRequestID() string {
	bytes := make([]byte, 4)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// GetRequestID extracts the request ID from context
func GetRequestID(ctx context.Context) string {
	if info, ok := ctx.Value(requestInfoKey).(*requestInfo); ok {
		return info.id
	}
	return "unknown"
}

// SetUsername records the authenticated user for the access log line
func SetUsername(ctx context.Context, username string) {
	if info, ok := ctx.Value(requestInfoKey).(*requestInfo); ok {
		info.username = username
	}
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

		// Reuse the request info if an outer middleware already created it
		info, ok := r.Context().Value(requestInfoKey).(*requestInfo)
		if !ok {
			info = &requestInfo{id: GenerateRequestID(), username: "-"}
			r = r.WithContext(context.WithValue(r.Context(), requestInfoKey, info))
		}

		// Get client IP (X-Forwarded-For is informational only, never used for authorization)
		remoteAddr := r.RemoteAddr
		if r.Header.Get("X-Forwarded-For") != "" {
			remoteAddr = r.Header.Get("X-Forwarded-For")
		}

		// Create a response writer wrapper to capture status code
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Call the next handler
		next.ServeHTTP(lrw, r)

		// Log the complete request-response in a single line
		duration := time.Since(start)
		userAgent := r.Header.Get("User-Agent")
		if userAgent == "" {
			userAgent = "-"
		}

		log.Printf("[HTTP] [%s] %s %s %s %s %s -> %d %dB (%v) [%s]",
			info.id, info.username, remoteAddr, r.Method, r.URL.Path, r.Proto, lrw.statusCode, lrw.bytes, duration, userAgent)
		if !ok { // count each request once, in the outermost middleware
			method := metrics.Method(r.Method)
			metrics.HTTPRequests.Inc(method, strconv.Itoa(lrw.statusCode))
			metrics.HTTPResponseBytes.Add(lrw.bytes, method)
		}
	})
}

// loggingResponseWriter wraps http.ResponseWriter to capture status code and size
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode  int
	bytes       int64
	wroteHeader bool
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	if !lrw.wroteHeader && code >= 200 {
		lrw.statusCode = code
		lrw.wroteHeader = true
	}
	lrw.ResponseWriter.WriteHeader(code)
}

func (lrw *loggingResponseWriter) Write(b []byte) (int, error) {
	lrw.wroteHeader = true
	n, err := lrw.ResponseWriter.Write(b)
	lrw.bytes += int64(n)
	return n, err
}

// Flush is required for streaming responses such as TPC performance markers
func (lrw *loggingResponseWriter) Flush() {
	lrw.wroteHeader = true
	if f, ok := lrw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer
func (lrw *loggingResponseWriter) Unwrap() http.ResponseWriter {
	return lrw.ResponseWriter
}
