package logger

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labkode/weed/internal/metrics"
)

// A response that a handler aborts (as a reverse proxy does when it cannot complete
// it) is logged and counted, and still aborted
func TestMiddlewareLogsAbortedResponses(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
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
	if line := buf.String(); !strings.Contains(line, "GET /webdav/f HTTP/1.1 -> 200 (aborted) 7B") {
		t.Errorf("logged %q", line)
	}
	if got := metrics.HTTPRequests.Get("GET", "200") - before; got != 1 {
		t.Errorf("counted %d requests", got)
	}
}
