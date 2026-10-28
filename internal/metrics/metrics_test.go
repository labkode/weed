package metrics

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExposition(t *testing.T) {
	c := NewCounter("test_requests_total", "Test requests.", "method", "path")
	c.Inc("GET", `a"b\c`+"\n")
	c.Add(2, "PUT", "/x")
	g := NewGauge("test_active", "Test gauge.")
	g.Inc()
	g.Inc()
	g.Dec()

	w := httptest.NewRecorder()
	Handler(func(w io.Writer) {
		WriteGauge(w, "test_computed", "Computed.", 1.5e9, []string{"k"}, []string{"v"})
	}).ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	body := w.Body.String()
	for _, want := range []string{
		"# HELP test_requests_total Test requests.\n# TYPE test_requests_total counter\n",
		`test_requests_total{method="GET",path="a\"b\\c\n"} 1` + "\n",
		`test_requests_total{method="PUT",path="/x"} 2` + "\n",
		"# TYPE test_active gauge\ntest_active 1\n",
		"# TYPE test_computed gauge\ntest_computed{k=\"v\"} 1.5e+09\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Errorf("Content-Type %q", ct)
	}
}

func TestMethodLabelsAreBounded(t *testing.T) {
	if Method("PROPFIND") != "PROPFIND" || Method("BREW") != "other" || Method("get") != "other" {
		t.Fatal("unexpected method labels")
	}
}
