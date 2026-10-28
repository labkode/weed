package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/metrics"
)

func scrape(t *testing.T, n *node) string {
	w := httptest.NewRecorder()
	n.srv.MetricsHandler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != 200 {
		t.Fatalf("/metrics: %d", w.Code)
	}
	return w.Body.String()
}

func TestMetrics(t *testing.T) {
	n := newNode(t, nil)
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "4")
		w.Write([]byte("data"))
	}))
	defer src.Close()

	before := map[string]int64{
		"put":       metrics.HTTPRequests.Get("PUT", "201"),
		"brew":      metrics.HTTPRequests.Get("other", "401"),
		"mismatch":  metrics.ChecksumMismatches.Get("put"),
		"tpcOK":     metrics.TPCTransfers.Get("pull", "success"),
		"tpcFail":   metrics.TPCTransfers.Get("pull", "failure"),
		"tpcBad":    metrics.ChecksumMismatches.Get("tpc_pull"),
		"tpcBytes":  metrics.TPCBytes.Get("pull"),
		"upload":    metrics.UploadBytes.Get(),
		"basic":     metrics.Auth.Get("basic", "success"),
		"unauth":    metrics.Auth.Get("none", "unauthorized"),
		"forbidden": metrics.Auth.Get("macaroon", "forbidden"),
		"reloads":   metrics.Reloads.Get("success"),
		"tpcActive": metrics.TPCActive.Get("pull"),
		"respBytes": metrics.HTTPResponseBytes.Get("GET"),
	}

	n.do("PUT", "/a", "12345")
	n.do("PUT", "/b", "x", "Repr-Digest", "adler=:AAAAAA==:")
	n.do("GET", "/a", "")
	n.do("BREW", "/a", "", "Authorization", "none")
	ro, _ := n.mint("/", `{"caveats":["activity:DOWNLOAD"]}`)
	n.do("DELETE", "/a", "", "Authorization", "Bearer "+ro)
	copyTPC(t, n, "/c", "Source", src.URL+"/f")
	copyTPC(t, n, "/d", "Source", src.URL+"/f", "Repr-Digest", "adler=:AAAAAA==:")
	n.srv.Reload()

	for name, c := range map[string]struct {
		got  int64
		want int64
	}{
		"put":       {metrics.HTTPRequests.Get("PUT", "201"), 1},
		"brew":      {metrics.HTTPRequests.Get("other", "401"), 1},
		"mismatch":  {metrics.ChecksumMismatches.Get("put"), 1},
		"tpcOK":     {metrics.TPCTransfers.Get("pull", "success"), 1},
		"tpcFail":   {metrics.TPCTransfers.Get("pull", "failure"), 1},
		"tpcBad":    {metrics.ChecksumMismatches.Get("tpc_pull"), 1},
		"tpcBytes":  {metrics.TPCBytes.Get("pull"), 8},
		"upload":    {metrics.UploadBytes.Get(), 5},
		"unauth":    {metrics.Auth.Get("none", "unauthorized"), 1},
		"forbidden": {metrics.Auth.Get("macaroon", "forbidden"), 1},
		"reloads":   {metrics.Reloads.Get("success"), 1},
		"tpcActive": {metrics.TPCActive.Get("pull"), 0},
		"respBytes": {metrics.HTTPResponseBytes.Get("GET"), 5},
	} {
		if d := c.got - before[name]; d != c.want {
			t.Errorf("%s: changed by %d, want %d", name, d, c.want)
		}
	}
	if d := metrics.Auth.Get("basic", "success") - before["basic"]; d < 4 {
		t.Errorf("basic successes: %d", d)
	}

	body := scrape(t, n)
	for _, re := range []string{
		`(?m)^weed_http_requests_total\{method="PUT",code="201"\} \d+$`,
		`(?m)^weed_tpc_transfers_total\{mode="pull",result="success"\} \d+$`,
		`(?m)^weed_build_info\{version="[^"]*",goversion="go[^"]*"\} 1$`,
	} {
		if !regexp.MustCompile(re).MatchString(body) {
			t.Errorf("no match for %s in:\n%s", re, body)
		}
	}
	if strings.Contains(body, "weed_crl_expiry") || strings.Contains(body, "weed_tls_certificate_expiry") {
		t.Error("expiry gauges without CRLs or a TLS certificate")
	}
}

func TestExpiryGauges(t *testing.T) {
	// TestReloadCRLRevokesCertificate's setup, plus a TLS certificate loaded by the server
	n := newNode(t, func(cfg *config.Config, _ string) {})
	n.srv.Config.TLSCert, n.srv.Config.TLSKey = writeTestKeyPair(t)
	if err := n.srv.loadCertificate(); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^weed_tls_certificate_expiry_timestamp_seconds \d\.\d+e\+09$`).MatchString(scrape(t, n)) {
		t.Errorf("no TLS certificate expiry in:\n%s", scrape(t, n))
	}
}

func TestHealthz(t *testing.T) {
	n := newNode(t, nil)
	resp, body := n.do("GET", n.ts.URL+"/healthz", "", "Authorization", "none")
	if resp.StatusCode != 200 || body != "ok\n" {
		t.Fatalf("/healthz: %d %q", resp.StatusCode, body)
	}
	os.RemoveAll(n.dir)
	if resp, _ := n.do("GET", n.ts.URL+"/healthz", "", "Authorization", "none"); resp.StatusCode != 503 {
		t.Fatalf("/healthz without storage: %d", resp.StatusCode)
	}
}
