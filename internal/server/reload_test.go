package server

import (
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/testutil"
	"golang.org/x/crypto/bcrypt"
)

func TestReloadHtpasswd(t *testing.T) {
	n := newNode(t, nil)
	n.write("/f", "x")
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw2"), bcrypt.MinCost)
	os.WriteFile(n.srv.Config.HtpasswdFile, []byte("bob:"+string(hash)+"\n"), 0600)
	n.srv.Reload()

	if code := n.status("GET", "/f", ""); code != 401 {
		t.Fatalf("removed user still accepted: %d", code)
	}
	bob := "Basic " + b64([]byte("bob:pw2"))
	if code := n.status("GET", "/f", "", "Authorization", bob); code != 200 {
		t.Fatalf("added user rejected: %d", code)
	}

	// A file that cannot be read keeps the users that were loaded
	os.Remove(n.srv.Config.HtpasswdFile)
	n.srv.Reload()
	if code := n.status("GET", "/f", "", "Authorization", bob); code != 200 {
		t.Fatalf("users lost when the file disappeared: %d", code)
	}
}

func TestReloadCRLRevokesCertificate(t *testing.T) {
	now := time.Now()
	ca := testutil.NewCA(t, testutil.Name(t, "CN=Grid CA"))
	user := testutil.NewUser(t, ca, testutil.Name(t, "CN=jdoe"), now.Add(-time.Hour), now.Add(time.Hour))
	crlDir := t.TempDir()
	writeCRL := func(revoked ...*testutil.Cert) {
		der := testutil.NewCRL(t, ca, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), revoked...)
		os.WriteFile(filepath.Join(crlDir, "ca.r0"), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0644)
	}
	writeCRL()

	gridmap := filepath.Join(t.TempDir(), "grid-mapfile")
	os.WriteFile(gridmap, []byte(`"/CN=jdoe" jdoe`+"\n"), 0600)
	n := newNode(t, func(cfg *config.Config, _ string) {
		cfg.TLS, cfg.X509Auth = true, true
		cfg.CACert = writePEM(t, ca.Cert.Raw)
		cfg.CRLPath = crlDir
		cfg.GridmapFile = gridmap
	})
	n.write("/f", "x")
	client := clientWithCert(n, testutil.TLS(testutil.NewProxy(t, user, true, now.Add(time.Hour)), user))
	get := func() int {
		resp, err := client.Get(n.ts.URL + "/webdav/f")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get(); code != 200 {
		t.Fatalf("valid certificate: %d", code)
	}
	if !strings.Contains(scrape(t, n), "\nweed_crl_expiry_timestamp_seconds ") {
		t.Error("no CRL expiry metric")
	}
	writeCRL(user)
	n.srv.Reload()
	if code := get(); code != 401 {
		t.Fatalf("revoked certificate after reload: %d", code)
	}
}

func TestMissingRequiredCRLIsFatal(t *testing.T) {
	ca := testutil.NewCA(t, testutil.Name(t, "CN=Grid CA"))
	gridmap := filepath.Join(t.TempDir(), "grid-mapfile")
	os.WriteFile(gridmap, nil, 0600)
	cfg := &config.Config{Directory: t.TempDir(), TLS: true, X509Auth: true, CACert: writePEM(t, ca.Cert.Raw),
		GridmapFile: gridmap, CRLPath: t.TempDir(), CRLMode: config.CRLRequire}
	if err := New(cfg).Initialize(); err == nil || !strings.Contains(err.Error(), "CRL") {
		t.Fatalf("startup without CRLs: %v", err)
	}
}

// X.509 accepts only the certificates listed in the grid-mapfile, so it cannot work without one
func TestMissingGridmapIsFatal(t *testing.T) {
	ca := testutil.NewCA(t, testutil.Name(t, "CN=Grid CA"))
	cfg := &config.Config{Directory: t.TempDir(), TLS: true, X509Auth: true, CACert: writePEM(t, ca.Cert.Raw),
		GridmapFile: filepath.Join(t.TempDir(), "grid-mapfile")}
	if err := New(cfg).Initialize(); err == nil || !strings.Contains(err.Error(), "grid-mapfile") {
		t.Fatalf("startup without a grid-mapfile: %v", err)
	}
}

func writeKeyPair(t *testing.T, c *testutil.Cert, certFile, keyFile string) {
	key, err := x509.MarshalECPrivateKey(c.Key)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw}), 0644)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: key}), 0600)
}

func TestReloadTLSCertificate(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "host.pem"), filepath.Join(dir, "host.key")
	ca := testutil.NewCA(t, testutil.Name(t, "CN=Host CA"))
	first := testutil.NewUser(t, ca, testutil.Name(t, "CN=weed.example"), time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	writeKeyPair(t, first, certFile, keyFile)

	s := New(&config.Config{Directory: dir, TLS: true, TLSCert: certFile, TLSKey: keyFile})
	if err := s.Initialize(); err != nil {
		t.Fatal(err)
	}
	if err := s.loadCertificate(); err != nil {
		t.Fatal(err)
	}
	serving := func() *x509.Certificate {
		c, _ := x509.ParseCertificate(s.cert.Load().Certificate[0])
		return c
	}

	renewed := testutil.NewUser(t, ca, testutil.Name(t, "CN=weed.example"), time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour))
	writeKeyPair(t, renewed, certFile, keyFile)
	s.Reload()
	if !serving().Equal(renewed.Cert) {
		t.Fatal("renewed certificate not served after reload")
	}

	os.WriteFile(keyFile, []byte("half-written"), 0600)
	s.Reload()
	if !serving().Equal(renewed.Cert) {
		t.Fatal("a broken key file replaced the certificate")
	}
}

func TestReloadTPCCAs(t *testing.T) {
	src := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "4")
		io.WriteString(w, "data")
	}))
	defer src.Close()
	caFile := writePEM(t, testutil.NewCA(t, testutil.Name(t, "CN=Unrelated")).Cert.Raw)

	n := newNode(t, func(cfg *config.Config, _ string) { cfg.TPCCAPath = caFile })
	code, body := copyTPC(t, n, "/a", "Source", src.URL+"/f")
	expectFailure(t, code, body, "certificate")

	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: src.Certificate().Raw}), 0644)
	n.srv.Reload()
	code, body = copyTPC(t, n, "/b", "Source", src.URL+"/f")
	expectSuccess(t, code, body)
}

func writeTestKeyPair(t *testing.T) (certFile, keyFile string) {
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "host.pem"), filepath.Join(dir, "host.key")
	ca := testutil.NewCA(t, testutil.Name(t, "CN=Host CA"))
	writeKeyPair(t, testutil.NewUser(t, ca, testutil.Name(t, "CN=weed.example"), time.Now().Add(-time.Hour), time.Now().Add(time.Hour)), certFile, keyFile)
	return certFile, keyFile
}
