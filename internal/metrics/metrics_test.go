package metrics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestExposition(t *testing.T) {
	c := NewCounter("test_requests_total", "Test requests.", "method", "path")
	c.Inc("GET", `a"b\c`+"\n")
	c.Add(2, "PUT", "/x")
	g := NewGauge("test_active", "Test gauge.")
	g.Inc()
	g.Inc()
	g.Dec()
	d := NewCounter("test_wait_seconds_total", "Test durations.").InSeconds()
	d.Add(int64(1500 * time.Millisecond))

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
		"# TYPE test_wait_seconds_total counter\ntest_wait_seconds_total 1.5\n",
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

func TestRemote(t *testing.T) {
	line := func(name string, delta int64, labels ...string) []byte {
		b, _ := json.Marshal(change{Name: name, Labels: labels, Delta: delta})
		return append(b, '\n')
	}
	var r Remote
	before := UploadBytes.Get()
	if err := r.Apply(line("weed_upload_bytes_total", 100)); err != nil {
		t.Fatal(err)
	}
	if got := UploadBytes.Get() - before; got != 100 {
		t.Errorf("upload bytes grew by %d", got)
	}
	activeBefore := TPCActive.Get("pull")
	r.Apply(line("weed_tpc_active_transfers", 1, "pull"))
	r.Apply(line("weed_tpc_active_transfers", 1, "pull"))
	r.Apply(line("weed_tpc_active_transfers", -1, "pull"))
	if got := TPCActive.Get("pull") - activeBefore; got != 1 {
		t.Errorf("active transfers grew by %d", got)
	}

	// Workers only report what they record
	for _, bad := range [][]byte{
		line("weed_http_requests_total", 1, "GET", "200"), // recorded by the front process
		line("weed_reloads_total", 1, "success"),
		line("weed_no_such_metric", 1),
		line("weed_tpc_bytes_total", 1), // missing label
		[]byte("not json"),
	} {
		if err := r.Apply(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	// ...with a bounded number of label sets
	var err error
	for i := 0; i < maxRemoteSeries+1 && err == nil; i++ {
		err = r.Apply(line("weed_checksum_mismatches_total", 1, fmt.Sprint("op", i)))
	}
	if err == nil {
		t.Error("unbounded label sets")
	}

	// Gauges describe what the worker was doing, which ends with it
	r.Close()
	if got := TPCActive.Get("pull"); got != activeBefore {
		t.Errorf("active transfers %d after the worker exited, want %d", got, activeBefore)
	}
	if got := UploadBytes.Get() - before; got != 100 {
		t.Errorf("counters changed when the worker exited: %d", got)
	}
}

func TestForwardTo(t *testing.T) {
	var buf bytes.Buffer
	ForwardTo(&buf)
	defer func() { forwarding.Store(false) }()
	before := UploadBytes.Get()
	UploadBytes.Add(5)
	TPCActive.Inc("push")
	if UploadBytes.Get() != before {
		t.Error("forwarded changes are also recorded locally")
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("forwarded %q", buf.String())
	}
	var r Remote
	for _, l := range lines {
		if err := r.Apply([]byte(l)); err != nil {
			t.Fatal(err)
		}
	}
	if UploadBytes.Get() != before+5 {
		t.Error("forwarded change not applied")
	}
	r.Close()
}
