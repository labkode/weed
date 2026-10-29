package server

import (
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labkode/weed/internal/metrics"
)

func TestRequestKind(t *testing.T) {
	for _, c := range []struct {
		method string
		header []string
		want   string
	}{
		{"GET", nil, kindDownload},
		{"PUT", nil, kindUpload},
		{"COPY", []string{"Source", "https://other.example.org/f"}, kindTPCPull},
		{"COPY", []string{"Destination", "https://other.example.org/f"}, kindTPCPush},
		{"COPY", []string{"Destination", "http://weed.example.org/webdav/g"}, kindOther},
		{"COPY", []string{"Source", "not a url"}, kindOther},
		{"MOVE", []string{"Destination", "/webdav/g"}, kindOther},
		{"HEAD", nil, kindOther},
		{"PROPFIND", nil, kindOther},
	} {
		r := httptest.NewRequest(c.method, "http://weed.example.org/webdav/f", nil)
		if len(c.header) > 0 {
			r.Header.Set(c.header[0], c.header[1])
		}
		if got := requestKind(r); got != c.want {
			t.Errorf("%s %v: %s, want %s", c.method, c.header, got, c.want)
		}
	}
}

// Transfers in progress are counted by kind and by user while they last
func TestRequestsInProgress(t *testing.T) {
	n := newNode(t, nil)
	inProgress := func() statusInProgress {
		var st status
		json.Unmarshal([]byte(serve(n.srv.MetricsHandler(), "/status")), &st)
		return st.InProgress
	}
	gauge := func(kind string) int64 { return metrics.RequestsInProgress.Get(kind) }
	before := map[string]int64{}
	for _, k := range requestKinds {
		before[k] = gauge(k)
	}
	if st := inProgress(); len(st.ByUser) != 0 || len(st.Total) != len(requestKinds) || st.Total[kindUpload] != 0 {
		t.Fatalf("idle: %+v", st)
	}
	if body := serve(n.srv.MetricsHandler(), "/metrics"); !strings.Contains(body, `weed_requests_in_progress{kind="tpc_push"} `) {
		t.Errorf("every kind is exported: %s", grepLines(body, "in_progress"))
	}

	done := make(chan struct{}, 4)
	send := func(req *http.Request, read bool) *http.Response {
		req.SetBasicAuth(basicUser, basicPass)
		resp, err := n.ts.Client().Do(req)
		if err != nil {
			t.Error(err)
			return nil
		}
		if read {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		return resp
	}
	// An upload whose body has not all arrived
	body, more := io.Pipe()
	up, _ := http.NewRequest("PUT", n.url("/up"), body)
	up.ContentLength = 10
	go func() { send(up, true); done <- struct{}{} }()
	more.Write([]byte("12345"))

	// A download that its client does not read: it fills the socket buffers
	big := filepath.Join(n.dir, "big")
	os.WriteFile(big, make([]byte, 64<<20), 0o644)
	down, _ := http.NewRequest("GET", n.url("/big"), nil)
	resp := send(down, false)

	// Third-party copies with remote ends that hang
	release := make(chan struct{})
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Header().Set("Content-Length", "100")
			w.Write([]byte("a few bytes"))
			w.(http.Flusher).Flush()
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer hang.Close()
	n.write("/out", "pushed data")
	for _, h := range [][]string{{"Source", hang.URL + "/f"}, {"Destination", hang.URL + "/g"}} {
		target := map[string]string{"Source": "/pulled", "Destination": "/out"}[h[0]]
		req, _ := http.NewRequest("COPY", n.url(target), nil)
		req.Header.Set(h[0], h[1])
		go func() { send(req, true); done <- struct{}{} }()
	}

	want := map[string]int{kindDownload: 1, kindUpload: 1, kindTPCPull: 1, kindTPCPush: 1}
	var st statusInProgress
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if st = inProgress(); maps.Equal(st.ByUser[basicUser], want) || time.Now().After(deadline) {
			break
		}
	}
	if !maps.Equal(st.ByUser[basicUser], want) || len(st.ByUser) != 1 || st.Total[kindOther] != 0 || st.Total[kindTPCPull] != 1 {
		t.Errorf("in progress: %+v", st)
	}
	for _, k := range requestKinds {
		if got := gauge(k) - before[k]; got != int64(want[k]) {
			t.Errorf("weed_requests_in_progress{kind=%q} rose by %d", k, got)
		}
	}

	more.Write([]byte("67890"))
	more.Close()
	resp.Body.Close()
	close(release)
	for range 3 {
		<-done
	}
	eventually(t, "the requests to end", func() bool { return len(inProgress().ByUser) == 0 })
	for _, k := range requestKinds {
		if gauge(k) != before[k] {
			t.Errorf("weed_requests_in_progress{kind=%q} is %d after, %d before", k, gauge(k), before[k])
		}
	}
}
