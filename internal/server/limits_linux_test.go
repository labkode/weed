//go:build linux

package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/labkode/weed/internal/config"
)

// limitedSize at limitedRate takes a second, less the leads of what transfers move
// before they pay (the relay's buffer, two quanta for third-party copies)
const (
	limitedSize = 2 << 20
	limitedRate = "2MiB/s"
	slow        = 600 * time.Millisecond // at limitedRate
	fast        = 300 * time.Millisecond // without
)

// timed returns how long f takes
func timed(f func()) time.Duration {
	start := time.Now()
	f()
	return time.Since(start)
}

// statusOf returns what /status reports
func statusOf(t *testing.T, s *Server) status {
	t.Helper()
	rec := httptest.NewRecorder()
	s.statusHandler(rec, httptest.NewRequest("GET", "/status", nil))
	var st status
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	return st
}

// Each account sends and receives at most at its rates: those of the configuration,
// unless the limits file says otherwise, which a reload applies
func TestAccountRates(t *testing.T) {
	file := filepath.Join(t.TempDir(), "limits.json")
	os.WriteFile(file, []byte(`[{"user": "bob", "egress_rate": "max"}]`), 0644)
	n := newUnixNode(t, func(cfg *config.Config) {
		cfg.AccountEgressRate, cfg.AccountIngressRate = limitedRate, limitedRate
		cfg.LimitsFile = file
	})
	n.setup("/alice/", 0755, 6001, 6001)
	n.setup("/bob/", 0755, 6002, 6002)
	data := strings.Repeat("x", limitedSize)

	if d := timed(func() {
		if code := n.status("PUT", "/alice/f", data); code != 201 {
			t.Fatalf("PUT: %d", code)
		}
	}); d < slow {
		t.Errorf("alice's upload of 2 MiB took %v, at 2 MiB/s", d)
	}
	if d := timed(func() {
		if _, body := n.do("GET", "/alice/f", ""); len(body) != limitedSize {
			t.Fatalf("GET: %d bytes", len(body))
		}
	}); d < slow {
		t.Errorf("alice's download of 2 MiB took %v, at 2 MiB/s", d)
	}
	os.WriteFile(n.local("/bob/f"), []byte(data), 0644)
	if d := timed(func() { n.do("GET", "/bob/f", "", n.as("bob")...) }); d > fast {
		t.Errorf("bob's download of 2 MiB took %v, with no egress rate", d)
	}

	st := statusOf(t, n.srv)
	if st.Network == nil || st.Network.Rules != 1 {
		t.Fatalf("/status network: %+v", st.Network)
	}
	// Both accounts have workers, whose third-party copies would pay with them
	if a := st.Network.Accounts; len(a) != 2 || a[0].Account != "alice" || a[0].EgressRate != 2<<20 || a[0].Weight != 100 ||
		a[1].Account != "bob" || a[1].EgressRate != 0 || a[1].IngressRate != 2<<20 {
		t.Errorf("/status network accounts: %+v", a)
	}

	os.WriteFile(file, []byte(`[{"user": "alice", "egress_rate": "max"}]`), 0644)
	n.srv.Reload()
	if d := timed(func() { n.do("GET", "/alice/f", "") }); d > fast {
		t.Errorf("after the reload, alice's download of 2 MiB took %v, with no egress rate", d)
	}
	if d := timed(func() { n.do("GET", "/bob/f", "", n.as("bob")...) }); d < slow {
		t.Errorf("after the reload, bob's download of 2 MiB took %v, at 2 MiB/s", d)
	}

	// A file that cannot be read keeps the rules
	os.WriteFile(file, []byte(`[{"user": "alice", "egress": "max"}]`), 0644)
	n.srv.Reload()
	if st := statusOf(t, n.srv); st.Reload.Successful || st.Network.Rules != 1 {
		t.Errorf("after a reload of a broken limits file: %+v, %+v", st.Reload, st.Network)
	}
}

// The accounts that want more than weed's total share it by weight
func TestTotalRateByWeight(t *testing.T) {
	file := filepath.Join(t.TempDir(), "limits.json")
	os.WriteFile(file, []byte(`[{"user": "alice", "weight": 300}]`), 0644)
	n := newUnixNode(t, func(cfg *config.Config) {
		cfg.EgressRate = "8MB/s"
		cfg.LimitsFile = file
	})
	data := strings.Repeat("x", 4*limitedSize)
	for _, u := range []string{"alice", "bob"} {
		n.setup("/"+u+"/", 0755, 0, 0)
		os.WriteFile(n.local("/"+u+"/f"), []byte(data), 0644)
	}
	// alice gets 6 MB/s until she has her 4 MB, bob 2 MB/s, then 8 MB/s
	var wg sync.WaitGroup
	took := make(map[string]time.Duration)
	var mu sync.Mutex
	for _, u := range []string{"alice", "bob"} {
		wg.Go(func() {
			d := timed(func() {
				if _, body := n.do("GET", "/"+u+"/f", "", n.as(u)...); len(body) != len(data) {
					t.Errorf("%s: %d bytes", u, len(body))
				}
			})
			mu.Lock()
			took[u] = d
			mu.Unlock()
		})
	}
	wg.Wait()
	if took["alice"] > took["bob"]*85/100 || took["bob"] < 800*time.Millisecond {
		t.Errorf("alice (weight 300) took %v, bob (weight 100) %v: want about 0.67 s and 1 s", took["alice"], took["bob"])
	}
}

// Third-party copies are paced too, though their connections are the worker's
func TestTPCRates(t *testing.T) {
	data := strings.Repeat("x", limitedSize)
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			io.Copy(io.Discard, r.Body)
			w.WriteHeader(201)
			return
		}
		io.WriteString(w, data)
	}))
	defer src.Close()
	n := newUnixNode(t, func(cfg *config.Config) { cfg.IngressRate, cfg.AccountEgressRate = limitedRate, limitedRate })
	n.setup("/alice/", 0755, 6001, 6001)

	if d := timed(func() {
		code, body := copyTPC(t, n.node, "/alice/pulled", "Source", src.URL+"/f")
		expectSuccess(t, code, body)
	}); d < slow {
		t.Errorf("a pull of 2 MiB took %v, at 2 MiB/s", d)
	}
	if d := timed(func() {
		code, body := copyTPC(t, n.node, "/alice/pulled", "Destination", src.URL+"/pushed")
		if code != 202 || !strings.HasPrefix(finalLine(body), "success") {
			t.Fatalf("push: %d %q", code, body)
		}
	}); d < slow {
		t.Errorf("a push of 2 MiB took %v, at 2 MiB/s", d)
	}
}
