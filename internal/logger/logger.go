// Package logger sets up weed's logging, with log/slog, and logs HTTP requests.
//
// Records are text (key=value) or JSON lines. Those logged with a request's context
// (slog.InfoContext and the like) carry its request_id, which the access log line of
// the request also has. The log package writes through slog too, at level INFO.
package logger

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/labkode/weed/internal/metrics"
)

// Formats of log records (server.log_format)
const (
	FormatText = "text"
	FormatJSON = "json"
)

// Options say how weed logs
type Options struct {
	Level  slog.Level
	Format string // FormatText (default) or FormatJSON
	File   string // "" for standard error
}

// Setup makes slog's default logger log as opts say. It returns a function that
// reopens the log file, for log rotation (a no-op without a file).
func Setup(opts Options) (reopen func() error, err error) {
	var out io.Writer = os.Stderr
	reopen = func() error { return nil }
	if opts.File != "" {
		f := &reopenable{path: opts.File}
		if err := f.Reopen(); err != nil {
			return nil, err
		}
		out, reopen = f, f.Reopen
	}
	slog.SetDefault(slog.New(NewHandler(out, opts.Format, opts.Level)))
	return reopen, nil
}

// NewHandler returns a handler writing records in format to out, which adds the
// request ID of the context to them. Durations are written as text (e.g. 1.5s) in
// both formats.
func NewHandler(out io.Writer, format string, level slog.Leveler) slog.Handler {
	ho := &slog.HandlerOptions{Level: level, ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		if a.Value.Kind() == slog.KindDuration {
			a.Value = slog.StringValue(a.Value.Duration().String())
		}
		return a
	}}
	if format == FormatJSON {
		return contextHandler{slog.NewJSONHandler(out, ho)}
	}
	return contextHandler{slog.NewTextHandler(out, ho)}
}

// contextHandler adds the request ID of the context to records
type contextHandler struct{ slog.Handler }

func (h contextHandler) Handle(ctx context.Context, r slog.Record) error {
	if info, ok := ctx.Value(requestInfoKey).(*requestInfo); ok {
		r.AddAttrs(slog.String("request_id", info.id))
	}
	return h.Handler.Handle(ctx, r)
}

func (h contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return contextHandler{h.Handler.WithAttrs(attrs)}
}

func (h contextHandler) WithGroup(name string) slog.Handler {
	return contextHandler{h.Handler.WithGroup(name)}
}

// reopenable is a log file that can be reopened after logrotate has moved it
type reopenable struct {
	path string
	mu   sync.Mutex
	f    *os.File
}

func (r *reopenable) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Write(p)
}

func (r *reopenable) Reopen() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return err
	}
	r.mu.Lock()
	old := r.f
	r.f = f
	r.mu.Unlock()
	if old != nil {
		old.Close()
	}
	return nil
}

// Relay logs a line that another process wrote: a JSON record of its logger, whose
// time, level, message and attributes are kept, or other output (such as that of the
// Go runtime when it crashes) at ERROR. attrs, which say where the line came from,
// are added, and replace attributes of the same names.
func Relay(line []byte, attrs ...slog.Attr) {
	ctx := context.Background()
	rec, ok := parseRecord(line)
	if !ok {
		rec = slog.NewRecord(time.Now(), slog.LevelError, string(line), 0)
	}
	h := slog.Default().Handler()
	if !h.Enabled(ctx, rec.Level) {
		return
	}
	out := slog.NewRecord(rec.Time, rec.Level, rec.Message, 0)
	out.AddAttrs(attrs...)
	rec.Attrs(func(a slog.Attr) bool {
		if !slices.ContainsFunc(attrs, func(b slog.Attr) bool { return b.Key == a.Key }) {
			out.AddAttrs(a)
		}
		return true
	})
	h.Handle(ctx, out)
}

// parseRecord reads a record written by a JSON handler, keeping the order of its
// attributes
func parseRecord(line []byte) (slog.Record, bool) {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return slog.Record{}, false
	}
	t, level, msg := time.Now(), slog.LevelInfo, ""
	var attrs []slog.Attr
	for dec.More() {
		tok, err := dec.Token()
		key, isKey := tok.(string)
		var v any
		if err != nil || !isKey || dec.Decode(&v) != nil {
			return slog.Record{}, false
		}
		s, isString := v.(string)
		switch key {
		case slog.TimeKey, slog.LevelKey, slog.MessageKey:
			if !isString {
				return slog.Record{}, false
			}
		}
		switch key {
		case slog.TimeKey:
			if parsed, err := time.Parse(time.RFC3339Nano, s); err == nil {
				t = parsed
			}
		case slog.LevelKey:
			level.UnmarshalText([]byte(s))
		case slog.MessageKey:
			msg = s
		default:
			attrs = append(attrs, slog.Any(key, fromJSON(v)))
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') || dec.More() {
		return slog.Record{}, false
	}
	rec := slog.NewRecord(t, level, msg, 0)
	rec.AddAttrs(attrs...)
	return rec, true
}

// fromJSON turns the numbers in a decoded JSON value into integers where they are
func fromJSON(v any) any {
	switch v := v.(type) {
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i
		}
		f, _ := v.Float64()
		return f
	case map[string]any:
		for k, e := range v {
			v[k] = fromJSON(e)
		}
	case []any:
		for i, e := range v {
			v[i] = fromJSON(e)
		}
	}
	return v
}

// Fatal logs err and exits
func Fatal(msg string, err error) {
	slog.Error(msg, "error", err)
	os.Exit(1)
}

// ErrorLog is a log.Logger for http.Server.ErrorLog: TLS handshake errors, which
// scanners and clients that give up cause all the time, are logged at INFO, panics at
// ERROR and other errors at WARN
func ErrorLog() *log.Logger {
	return log.New(errorLogWriter{}, "", 0)
}

type errorLogWriter struct{}

func (errorLogWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSuffix(string(p), "\n")
	level := slog.LevelWarn
	switch {
	case strings.Contains(msg, "TLS handshake error"):
		level = slog.LevelInfo
	case strings.Contains(msg, "panic"):
		level = slog.LevelError
	}
	slog.Log(context.Background(), level, msg, "component", "http")
	return len(p), nil
}

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

// WithRequestID returns a context carrying an existing request ID, e.g. one assigned
// by the process that forwarded the request
func WithRequestID(ctx context.Context, id string) context.Context {
	if id == "" {
		id = GenerateRequestID()
	}
	return context.WithValue(ctx, requestInfoKey, &requestInfo{id: id, username: Nobody})
}

// Nobody is the user of requests that no credentials map to: anonymous requests, and
// requests whose credentials are invalid or that take none (such as /healthz)
const Nobody = "nobody"

// SetUsername records the user that the request's credentials map to, for its
// "request" record (Nobody until then)
func SetUsername(ctx context.Context, username string) {
	if info, ok := ctx.Value(requestInfoKey).(*requestInfo); ok {
		info.username = username
	}
}

// Middleware assigns each request an ID and logs it once answered ("request"), with
// the status, size and duration of the response
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Reuse the request info if an outer middleware already created it
		info, ok := r.Context().Value(requestInfoKey).(*requestInfo)
		if !ok {
			info = &requestInfo{id: GenerateRequestID(), username: Nobody}
			r = r.WithContext(context.WithValue(r.Context(), requestInfoKey, info))
		}

		// Create a response writer wrapper to capture status code
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Log the complete request-response in a single line, also when the handler
		// panics, as a reverse proxy does to abort a response it cannot complete
		defer func() {
			v := recover()
			attrs := []slog.Attr{
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("proto", r.Proto),
				slog.Int("status", lrw.statusCode),
				slog.Int64("bytes", lrw.bytes),
				slog.Duration("duration", time.Since(start)),
				slog.String("user", info.username),
				slog.String("remote", r.RemoteAddr),
				slog.String("user_agent", r.Header.Get("User-Agent")),
			}
			// Informational only: clients can set it to anything
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				attrs = append(attrs, slog.String("forwarded_for", xff))
			}
			level := slog.LevelInfo
			if v != nil {
				attrs = append(attrs, slog.Bool("aborted", true))
				if v != http.ErrAbortHandler {
					level = slog.LevelError
					attrs = append(attrs, slog.String("panic", fmt.Sprint(v)))
				}
			}
			slog.LogAttrs(r.Context(), level, "request", attrs...)
			if !ok { // count each request once, in the outermost middleware
				method := metrics.Method(r.Method)
				metrics.HTTPRequests.Inc(method, strconv.Itoa(lrw.statusCode))
				metrics.HTTPResponseBytes.Add(lrw.bytes, method)
			}
			if v != nil {
				panic(v)
			}
		}()
		next.ServeHTTP(lrw, r)
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
