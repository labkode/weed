package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/webdav"
)

// Every scenario ramps against a WebDAV server in memory, as identities of two
// methods: each step succeeds, no client of a crowd falls behind, and stress leaves
// nothing behind
func TestRun(t *testing.T) {
	ctx := context.Background()
	fs := webdav.NewMemFS()
	for _, u := range []string{"u1", "u2", "u3"} {
		if err := fs.Mkdir(ctx, "/"+u, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	dav := &webdav.Handler{FileSystem: fs, LockSystem: webdav.NewMemLS()}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if r.Header.Get("Authorization") == "Bearer t3" {
			user, password, ok = "u3", "p-u3", true
		}
		if !ok || password != "p-"+user || !strings.HasPrefix(r.URL.Path, "/"+user+"/") {
			http.Error(w, "who?", http.StatusUnauthorized)
			return
		}
		dav.ServeHTTP(w, r)
	}))
	defer srv.Close()

	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	ids := filepath.Join(dir, "identities")
	results := filepath.Join(dir, "results.json")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644)
	// u1 twice, as one account by two methods would be: a directory each
	os.WriteFile(ids, []byte("# name kind arguments\nu1 basic p-u1\nu2 basic p-u2\nu3 bearer t3\nu1 basic p-u1\n"), 0o644)
	var stdout, stderr bytes.Buffer
	code := run(ctx, []string{"-url", srv.URL + "/{user}", "-ca", ca, "-identities", ids,
		"-max", "2", "-step", "200ms", "-warmup", "50ms", "-small-size", "1KiB", "-download-size", "1MiB",
		"-upload-size", "256KiB", "-list-entries", "3", "-clients", "2", "-interval", "50ms", "-client-rate", "256KiB",
		"-json", results}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, &stdout, &stderr)
	}

	b, err := os.ReadFile(results)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Results []struct {
			Name  string `json:"name"`
			Steps []step `json:"steps"`
		} `json:"results"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range got.Results {
		names = append(names, r.Name)
		if len(r.Steps) != 2 {
			t.Errorf("%s: %d steps, want those of 1 and 2 clients", r.Name, len(r.Steps))
		}
		for _, s := range r.Steps {
			if s.Requests == 0 || s.Errors > 0 || s.Behind > 0 {
				t.Errorf("%s with %d clients: %d requests, %d behind, errors %v", r.Name, s.Clients, s.Requests, s.Behind, s.ErrorKinds)
			}
		}
	}
	// auth: u1 authenticates with a password, u3 with a token; accounts: u1, u2 and u1 again
	want := []string{"get-small", "put-small", "list", "connect", "download", "upload", "auth-bearer", "accounts", "clients", "slow-download"}
	if !slices.Equal(names, want) {
		t.Errorf("scenarios %v, want %v", names, want)
	}
	if !strings.Contains(stdout.String(), "Limits found at") {
		t.Errorf("no summary:\n%s", &stdout)
	}

	for _, u := range []string{"u1", "u2", "u3"} {
		f, err := fs.OpenFile(ctx, "/"+u, os.O_RDONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		left, _ := f.Readdir(-1)
		f.Close()
		for _, fi := range left {
			t.Errorf("/%s/%s is left", u, fi.Name())
		}
	}
}

// With -crowd-accounts, the clients of crowds are the identities of accounts
func TestCrowdAccounts(t *testing.T) {
	ids := []*identity{{Name: "u1", Kind: "basic"}, {Name: "u2", Kind: "basic"}, {Name: "u3", Kind: "bearer"}}
	for _, spread := range []bool{false, true} {
		cfg := &config{scenarios: []string{"clients", "slow-download"}, crowdAccounts: spread}
		list, _, err := scenarios(cfg, ids[0], ids)
		if err != nil {
			t.Fatal(err)
		}
		want := "u1 (basic)"
		if spread {
			want = "u1 (basic) and 1 more"
		}
		for _, s := range list {
			if s.As != want {
				t.Errorf("-crowd-accounts=%v: %s as %q, want %q", spread, s.Name, s.As, want)
			}
		}
	}
}

// A token from a file is read again before each step, as the file is renewed
func TestTokenFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "token")
	os.WriteFile(file, []byte("old\n"), 0o600)
	id, err := newIdentity(&config{}, []string{"u", "bearer", "@" + file}, &tls.Config{}, "https://x/{user}", "run")
	if err != nil || *id.header.Load() != "Bearer old" {
		t.Fatalf("%v %q", err, *id.header.Load())
	}
	os.WriteFile(file, []byte("new\n"), 0o600)
	if err := id.refresh(); err != nil || *id.header.Load() != "Bearer new" {
		t.Errorf("%v %q", err, *id.header.Load())
	}
	if id.base != "https://x/u/run/" {
		t.Errorf("base %s", id.base)
	}
}

// A ramp stops on errors, on clients behind, on latency (of requests, not
// transfers), and but for a crowd, once two doublings of the clients added less than
// 10% each
func TestVerdict(t *testing.T) {
	for _, c := range []struct {
		name     string
		rates    []float64
		errors   int64
		behind   int
		p99      float64
		transfer bool
		crowd    bool
		stops    bool
	}{
		{name: "growing", rates: []float64{100, 200, 400}},
		{name: "two steps", rates: []float64{100, 100}},
		{name: "flat twice", rates: []float64{100, 200, 210, 215}, stops: true},
		{name: "flat then growing", rates: []float64{100, 200, 210, 300}},
		{name: "falling", rates: []float64{100, 200, 150, 120}, stops: true},
		{name: "errors", rates: []float64{100}, errors: 2, stops: true},
		{name: "slow requests", rates: []float64{100}, p99: 3, stops: true},
		{name: "slow transfers", rates: []float64{100}, p99: 3, transfer: true},
		{name: "a crowd flat", rates: []float64{100, 200, 210, 215}, crowd: true},
		{name: "a crowd behind", rates: []float64{100}, behind: 2, transfer: true, crowd: true, stops: true},
		{name: "a crowd 1% behind", rates: []float64{100}, behind: 1, transfer: true, crowd: true},
	} {
		sc := &scenario{Unit: "req/s"}
		if c.transfer {
			sc.Unit = "B/s"
		}
		if c.crowd {
			sc.crowdOp = func(context.Context, *member) error { return nil }
		}
		steps := make([]step, len(c.rates))
		for i, r := range c.rates {
			steps[i] = step{Clients: 100, ReqRate: r, ByteRate: r, Requests: 98}
		}
		steps[len(steps)-1].Errors = c.errors
		steps[len(steps)-1].Behind = c.behind
		steps[len(steps)-1].P99 = c.p99
		got := verdict(steps, sc, 2*time.Second)
		if (got != "") != c.stops {
			t.Errorf("%s: %q", c.name, got)
		}
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"4KiB": 4096, "64 MiB": 64 << 20, "1GiB": 1 << 30, "100MB": 1e8, "2kB": 2000, "512": 512, "8B": 8} {
		if got, err := parseSize(in); got != want || err != nil {
			t.Errorf("%q: %d %v, want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "x", "0", "-1KiB", "1.5GiB", "KiB"} {
		if _, err := parseSize(in); err == nil {
			t.Errorf("%q: no error", in)
		}
	}
	if s := bytesIEC(64 << 20); s != "64 MiB" {
		t.Errorf("bytesIEC: %s", s)
	}
}
