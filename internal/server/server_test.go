package server

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labkode/weed/internal/config"
	"golang.org/x/crypto/bcrypt"
)

func TestMain(m *testing.M) {
	// The tests of worker processes start this binary as their workers
	if len(os.Args) > 1 && os.Args[1] == "worker" {
		if err := RunWorker(); err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}
	if !testingVerbose() {
		log.SetOutput(io.Discard)
	}
	os.Exit(m.Run())
}

func testingVerbose() bool {
	for _, a := range os.Args {
		if a == "-test.v=true" || a == "-test.v" {
			return true
		}
	}
	return false
}

// node is a weed instance under test
type node struct {
	t   testing.TB
	srv *Server
	ts  *httptest.Server
	dir string
}

const basicUser, basicPass = "alice", "pw"

// newNode starts a weed server with Basic auth (alice:pw), macaroons and TPC enabled.
// mod may adjust the configuration; it receives the server's base URL.
// wraps, if given, wrap the server's handler (e.g. to put a redirecting door in front).
// It serves files in this process, as its user (see Server.inProcess);
// newWorkerNode does as weed does.
func newNode(t testing.TB, mod func(cfg *config.Config, baseURL string), wraps ...func(http.Handler) http.Handler) *node {
	t.Helper()
	return startNode(t, true, mod, wraps...)
}

// newWorkerNode is newNode with a worker process per Unix account, as weed serves
// (Linux, as root)
func newWorkerNode(t testing.TB, mod func(cfg *config.Config, baseURL string), wraps ...func(http.Handler) http.Handler) *node {
	t.Helper()
	return startNode(t, false, mod, wraps...)
}

// newServer is New for tests of request handling, which serve files in this process
func newServer(cfg *config.Config) *Server {
	s := New(cfg)
	s.inProcess = true
	return s
}

func startNode(t testing.TB, inProcess bool, mod func(cfg *config.Config, baseURL string), wraps ...func(http.Handler) http.Handler) *node {
	t.Helper()
	dir := t.TempDir()
	hash, _ := bcrypt.GenerateFromPassword([]byte(basicPass), bcrypt.MinCost)
	htpasswd := filepath.Join(t.TempDir(), "htpasswd")
	os.WriteFile(htpasswd, []byte(basicUser+":"+string(hash)+"\n"), 0600)

	cfg := &config.Config{
		Directory:           dir,
		BasicAuth:           true,
		HtpasswdFile:        htpasswd,
		AppTokensFile:       filepath.Join(t.TempDir(), "app-tokens"),
		MacaroonAuth:        true,
		MacaroonSecretKey:   fmt.Sprintf("%032d", time.Now().UnixNano()),
		MacaroonLocation:    "weed",
		MacaroonMaxValidity: time.Hour,
		TPC:                 true,
		TPCAllowHTTP:        true,
		TPCAllowLocal:       true,
		TPCMaxTransfers:     4,
		TPCMarkerInterval:   20 * time.Millisecond,
	}
	ts := httptest.NewUnstartedServer(nil)
	scheme := "http"
	if mod != nil {
		probe := &config.Config{}
		mod(probe, "")
		if probe.TLS {
			scheme = "https"
		}
		mod(cfg, scheme+"://"+ts.Listener.Addr().String())
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	s := New(cfg)
	s.inProcess = inProcess
	if err := s.Initialize(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close) // after the server has closed
	var handler http.Handler = s.SetupRoutes()
	for _, wrap := range wraps {
		handler = wrap(handler)
	}
	ts.Config.Handler = handler
	if cfg.TLS {
		tlsCfg, err := s.SetupTLS()
		if err != nil {
			t.Fatal(err)
		}
		ts.TLS = tlsCfg
		ts.StartTLS()
	} else {
		ts.Start()
	}
	t.Cleanup(ts.Close)
	return &node{t: t, srv: s, ts: ts, dir: dir}
}

func (n *node) url(p string) string { return n.ts.URL + "/webdav" + p }

func (n *node) write(p, content string) {
	n.t.Helper()
	full := filepath.Join(n.dir, filepath.FromSlash(p))
	os.MkdirAll(filepath.Dir(full), 0755)
	if err := os.WriteFile(full, []byte(content), 0644); err != nil {
		n.t.Fatal(err)
	}
}

func (n *node) read(p string) (string, bool) {
	b, err := os.ReadFile(filepath.Join(n.dir, filepath.FromSlash(p)))
	return string(b), err == nil
}

// do sends a request; it authenticates as alice unless an Authorization header is given
func (n *node) do(method, p, body string, headers ...string) (*http.Response, string) {
	n.t.Helper()
	target := p
	if !strings.HasPrefix(p, "http") {
		target = n.url(p)
	}
	req, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		n.t.Fatal(err)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	if req.Header.Get("Authorization") == "" {
		req.SetBasicAuth(basicUser, basicPass)
	} else if req.Header.Get("Authorization") == "none" {
		req.Header.Del("Authorization")
	}
	resp, err := n.ts.Client().Do(req)
	if err != nil {
		n.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (n *node) status(method, p, body string, headers ...string) int {
	n.t.Helper()
	resp, _ := n.do(method, p, body, headers...)
	return resp.StatusCode
}

// mint requests a macaroon for p
func (n *node) mint(p, request string, headers ...string) (string, int) {
	n.t.Helper()
	resp, body := n.do("POST", p, request, append([]string{"Content-Type", "application/macaroon-request"}, headers...)...)
	if resp.StatusCode != 200 {
		n.t.Fatalf("minting macaroon for %s: %d %s", p, resp.StatusCode, body)
	}
	var out struct {
		Macaroon  string `json:"macaroon"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		n.t.Fatal(err)
	}
	return out.Macaroon, out.ExpiresIn
}

func writePEM(t *testing.T, der []byte) string {
	p := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	return p
}

func clientWithCert(n *node, cert tls.Certificate) *http.Client {
	c := n.ts.Client()
	tr := c.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
	return &http.Client{Transport: tr}
}
