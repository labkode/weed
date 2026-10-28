package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labkode/weed/internal/metrics"
)

// capture makes the default logger write JSON records to the returned buffer
func capture(t *testing.T, format string, level slog.Level) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(NewHandler(&buf, format, level)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// records decodes the JSON records in buf
func records(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("not a JSON record: %q", line)
		}
		out = append(out, m)
	}
	return out
}

func TestMiddleware(t *testing.T) {
	buf := capture(t, FormatJSON, slog.LevelInfo)
	var id string
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id = GetRequestID(r.Context())
		SetUsername(r.Context(), "alice")
		slog.InfoContext(r.Context(), "inside")
		w.WriteHeader(201)
		w.Write([]byte("created"))
	}))
	r := httptest.NewRequest("PUT", "/webdav/f", nil)
	r.RemoteAddr = "192.0.2.1:4242"
	r.Header.Set("X-Forwarded-For", "198.51.100.7")
	r.Header.Set("User-Agent", "gfal2")
	h.ServeHTTP(httptest.NewRecorder(), r)

	recs := records(t, buf)
	if len(recs) != 2 {
		t.Fatalf("logged %d records: %s", len(recs), buf)
	}
	if recs[0]["msg"] != "inside" || recs[0]["request_id"] != id {
		t.Errorf("record logged with the request's context: %v (request ID %s)", recs[0], id)
	}
	want := map[string]any{
		"level": "INFO", "msg": "request", "request_id": id, "method": "PUT", "path": "/webdav/f",
		"proto": "HTTP/1.1", "status": 201.0, "bytes": 7.0, "user": "alice",
		"remote": "192.0.2.1:4242", "forwarded_for": "198.51.100.7", "user_agent": "gfal2",
	}
	for k, v := range want {
		if recs[1][k] != v {
			t.Errorf("access log %s = %v, want %v", k, recs[1][k], v)
		}
	}
	if d, ok := recs[1]["duration"].(string); !ok || !strings.HasSuffix(d, "s") {
		t.Errorf("duration %v, want text such as 1.5ms", recs[1]["duration"])
	}
}

// A path cannot forge log lines
func TestMiddlewareQuotes(t *testing.T) {
	buf := capture(t, FormatText, slog.LevelInfo)
	r := httptest.NewRequest("GET", "/webdav/f", nil)
	r.URL.Path = "/webdav/f\nlevel=ERROR msg=forged"
	Middleware(http.NotFoundHandler()).ServeHTTP(httptest.NewRecorder(), r)
	if lines := strings.Count(buf.String(), "\n"); lines != 1 {
		t.Errorf("logged %d lines: %s", lines, buf)
	}
}

// A response that a handler aborts (as a reverse proxy does when it cannot complete
// it) is logged and counted, and still aborted
func TestMiddlewareLogsAbortedResponses(t *testing.T) {
	buf := capture(t, FormatJSON, slog.LevelInfo)
	before := metrics.HTTPRequests.Get("GET", "200")

	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("partial"))
		panic(http.ErrAbortHandler)
	}))
	func() {
		defer func() {
			if v := recover(); v != http.ErrAbortHandler {
				t.Errorf("recovered %v, want http.ErrAbortHandler", v)
			}
		}()
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/webdav/f", nil))
	}()
	recs := records(t, buf)
	if len(recs) != 1 || recs[0]["status"] != 200.0 || recs[0]["bytes"] != 7.0 || recs[0]["aborted"] != true || recs[0]["level"] != "INFO" {
		t.Errorf("logged %s", buf)
	}
	if got := metrics.HTTPRequests.Get("GET", "200") - before; got != 1 {
		t.Errorf("counted %d requests", got)
	}
}

// Records of a worker are logged by weed as they were, marked as the worker's
func TestRelay(t *testing.T) {
	// What a worker writes
	var worker bytes.Buffer
	wl := slog.New(NewHandler(&worker, FormatJSON, slog.LevelDebug))
	ctx := WithRequestID(context.Background(), "0badc0de")
	wl.WarnContext(ctx, "third-party copy failed", "bytes", 1<<40, "ratio", 0.5, "duration", 1500*time.Millisecond, "worker", "forged")
	wl.Debug("detail")
	worker.WriteString("panic: runtime error\n")

	buf := capture(t, FormatJSON, slog.LevelInfo)
	for _, line := range strings.Split(strings.TrimSpace(worker.String()), "\n") {
		Relay([]byte(line), slog.String("worker", "alice"), slog.Int("pid", 1630))
	}
	recs := records(t, buf)
	if len(recs) != 2 {
		t.Fatalf("relayed %d records (DEBUG is below the level): %s", len(recs), buf)
	}
	want := map[string]any{
		"level": "WARN", "msg": "third-party copy failed", "worker": "alice", "pid": 1630.0,
		"request_id": "0badc0de", "bytes": float64(1 << 40), "ratio": 0.5, "duration": "1.5s",
	}
	for k, v := range want {
		if recs[0][k] != v {
			t.Errorf("relayed %s = %v, want %v", k, recs[0][k], v)
		}
	}
	if !strings.Contains(buf.String(), `{"time":"`) || strings.Count(strings.Split(buf.String(), "\n")[0], `"worker"`) != 1 {
		t.Errorf("relayed %s", buf)
	}
	if recs[1]["level"] != "ERROR" || recs[1]["msg"] != "panic: runtime error" || recs[1]["worker"] != "alice" {
		t.Errorf("other output relayed as %v", recs[1])
	}

	// The time of the record is kept
	line := []byte(`{"time":"2026-10-28T15:00:00.5Z","level":"INFO","msg":"m"}`)
	Relay(line)
	if got := records(t, buf)[2]["time"]; got != "2026-10-28T15:00:00.5Z" {
		t.Errorf("time %v", got)
	}

	// Lines that are not records
	for _, line := range []string{`{"msg":"m"} trailing`, `{"msg":`, `[1]`, `{"time":1,"level":2,"msg":3}`} {
		buf.Reset()
		Relay([]byte(line))
		recs := records(t, buf)
		if len(recs) != 1 || recs[0]["msg"] != line || recs[0]["level"] != "ERROR" {
			t.Errorf("%s: %s", line, buf)
		}
	}
}

// log rotation: logrotate moves the file, and weed reopens it on SIGHUP
func TestReopen(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	path := filepath.Join(t.TempDir(), "weed.log")
	reopen, err := Setup(Options{Level: slog.LevelInfo, Format: FormatText, File: path})
	if err != nil {
		t.Fatal(err)
	}
	slog.Info("before")
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	slog.Info("still before")
	if err := reopen(); err != nil {
		t.Fatal(err)
	}
	slog.Info("after")
	old, _ := os.ReadFile(path + ".1")
	cur, _ := os.ReadFile(path)
	if !strings.Contains(string(old), "msg=before") || !strings.Contains(string(old), `msg="still before"`) || strings.Contains(string(old), "after") {
		t.Errorf("rotated file: %s", old)
	}
	if !strings.Contains(string(cur), "msg=after") || strings.Contains(string(cur), "before") {
		t.Errorf("reopened file: %s", cur)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm()&0o007 != 0 {
		t.Errorf("log file mode: %v %v", fi.Mode(), err)
	}
}

func TestErrorLog(t *testing.T) {
	buf := capture(t, FormatJSON, slog.LevelDebug)
	l := ErrorLog()
	l.Printf("http: TLS handshake error from 192.0.2.1:4242: EOF")
	l.Printf("http: panic serving 192.0.2.1:4242: boom")
	l.Printf("http: Accept error: too many open files")
	recs := records(t, buf)
	for i, want := range []string{"INFO", "ERROR", "WARN"} {
		if recs[i]["level"] != want || recs[i]["component"] != "http" {
			t.Errorf("record %d: %v, want level %s", i, recs[i], want)
		}
	}
}
