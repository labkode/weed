package server

import (
	"net/http"
	"net/http/httptest"
	"path"
	"regexp"
	"strings"
	"testing"
)

// The dashboard is the page of the metrics address: its files are served with the
// headers that keep what /status says from running as code, and it only reads
func TestDashboard(t *testing.T) {
	h := new(Server).MetricsHandler()
	do := func(method, target string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
		return rec
	}
	for _, target := range []string{"/", "/dashboard"} {
		if rec := do("GET", target); rec.Code/100 != 3 || rec.Header().Get("Location") != "/dashboard/" {
			t.Errorf("%s: %d %s", target, rec.Code, rec.Header())
		}
	}
	if rec := do("GET", "/elsewhere"); rec.Code != http.StatusNotFound {
		t.Errorf("/elsewhere: %d", rec.Code)
	}

	page := do("GET", "/dashboard/")
	if page.Code != 200 || page.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("/dashboard/: %d %s", page.Code, page.Header())
	}
	types := map[string]string{".css": "text/css", ".js": "javascript", ".svg": "image/svg+xml"}
	files := 0
	for _, m := range regexp.MustCompile(`(?:src|href)="([^"]+)"`).FindAllStringSubmatch(page.Body.String(), -1) {
		ref := m[1]
		if strings.HasPrefix(ref, "../") {
			continue // /status, /metrics, /healthz
		}
		files++
		rec := do("GET", "/dashboard/"+ref)
		if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Type"), types[path.Ext(ref)]) {
			t.Errorf("%s: %d %s", ref, rec.Code, rec.Header())
		}
	}
	if files != 3 {
		t.Errorf("the page names %d files of its own, want its script, style and icon", files)
	}
	for _, rec := range []*httptest.ResponseRecorder{page, do("GET", "/dashboard/dashboard.js")} {
		if rec.Header().Get("Content-Security-Policy") != dashboardCSP || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("headers: %s", rec.Header())
		}
	}

	for _, method := range []string{"POST", "PUT", "DELETE"} {
		if rec := do(method, "/dashboard/"); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /dashboard/: %d", method, rec.Code)
		}
	}
}
