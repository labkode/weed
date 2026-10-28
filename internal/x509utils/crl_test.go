package x509utils

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labkode/weed/internal/testutil"
)

func writeCRLs(t *testing.T, ders ...[]byte) string {
	dir := t.TempDir()
	for i, der := range ders {
		// fetch-crl writes PEM <hash>.r0 files; DER files are accepted too
		if i%2 == 0 {
			os.WriteFile(filepath.Join(dir, string(rune('a'+i))+".r0"), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0644)
		} else {
			os.WriteFile(filepath.Join(dir, string(rune('a'+i))+".crl"), der, 0644)
		}
	}
	return dir
}

func TestCRLChecks(t *testing.T) {
	now := time.Now()
	hour := time.Hour
	root := testutil.NewCA(t, testutil.Name(t, "CN=Root"))
	inter := testutil.NewIntermediate(t, root, testutil.Name(t, "CN=Intermediate"))
	alice := testutil.NewUser(t, inter, testutil.Name(t, "CN=alice"), now.Add(-hour), now.Add(hour))
	bob := testutil.NewUser(t, inter, testutil.Name(t, "CN=bob"), now.Add(-hour), now.Add(hour))
	bobProxy := testutil.NewProxy(t, bob, true, now.Add(hour))
	interRevoked := testutil.NewIntermediate(t, root, testutil.Name(t, "CN=Revoked Intermediate"))
	carol := testutil.NewUser(t, interRevoked, testutil.Name(t, "CN=carol"), now.Add(-hour), now.Add(hour))
	rogue := testutil.NewCA(t, testutil.Name(t, "CN=Intermediate")) // same name, different key

	rootCRL := testutil.NewCRL(t, root, now.Add(-hour), now.Add(hour), interRevoked)
	interCRL := testutil.NewCRL(t, inter, now.Add(-hour), now.Add(hour), bob)
	expiredInterCRL := testutil.NewCRL(t, inter, now.Add(-3*hour), now.Add(-2*hour), bob)
	forgedNewer := testutil.NewCRL(t, rogue, now.Add(-time.Minute), now.Add(hour)) // revokes nothing

	pool := testutil.Pool(root)
	for _, c := range []struct {
		name    string
		chain   []*testutil.Cert
		crls    [][]byte
		require bool
		wantErr string
	}{
		{"valid certificate", []*testutil.Cert{alice, inter}, [][]byte{rootCRL, interCRL}, true, ""},
		{"revoked certificate", []*testutil.Cert{bob, inter}, [][]byte{rootCRL, interCRL}, true, "has been revoked"},
		{"proxy of a revoked certificate", []*testutil.Cert{bobProxy, bob, inter}, [][]byte{rootCRL, interCRL}, false, "has been revoked"},
		{"revoked intermediate", []*testutil.Cert{carol, interRevoked}, [][]byte{rootCRL}, false, "Revoked Intermediate"},
		{"required CRL missing", []*testutil.Cert{alice, inter}, [][]byte{rootCRL}, true, "no current CRL"},
		{"optional CRL missing", []*testutil.Cert{alice, inter}, [][]byte{rootCRL}, false, ""},
		{"required CRL expired", []*testutil.Cert{bob, inter}, [][]byte{rootCRL, expiredInterCRL}, true, "no current CRL"},
		{"optional CRL expired", []*testutil.Cert{bob, inter}, [][]byte{rootCRL, expiredInterCRL}, false, ""},
		{"forged newer CRL is ignored", []*testutil.Cert{bob, inter}, [][]byte{rootCRL, interCRL, forgedNewer}, true, "has been revoked"},
		{"only a forged CRL", []*testutil.Cert{alice, inter}, [][]byte{rootCRL, forgedNewer}, true, "no current CRL"},
	} {
		crls, err := LoadCRLs(writeCRLs(t, c.crls...), c.require)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		_, _, err = VerifyChainCRL(chain(c.chain...), pool, crls, now)
		if c.wantErr == "" && err != nil || c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.wantErr)
		}
	}

	// The newest current CRL decides (a certificate taken off hold is valid again)
	newer := testutil.NewCRL(t, inter, now.Add(-time.Minute), now.Add(hour))
	crls, _ := LoadCRLs(writeCRLs(t, rootCRL, interCRL, newer), true)
	if _, _, err := VerifyChainCRL(chain(bob, inter), pool, crls, now); err != nil {
		t.Errorf("newest CRL not used: %v", err)
	}
}

func TestLoadCertificatesAndCRLsFromGridSecurityDir(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.NewCA(t, testutil.Name(t, "CN=Grid CA"))
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
	os.WriteFile(filepath.Join(dir, "Grid-CA.pem"), certPEM, 0644)
	os.Symlink("Grid-CA.pem", filepath.Join(dir, "1a2b3c4d.0"))
	os.WriteFile(filepath.Join(dir, "1a2b3c4d.signing_policy"), []byte("access_id_CA X509 '/CN=Grid CA'"), 0644)
	os.WriteFile(filepath.Join(dir, "1a2b3c4d.namespaces"), []byte("TO Issuer ..."), 0644)
	os.WriteFile(filepath.Join(dir, "1a2b3c4d.r0"), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL",
		Bytes: testutil.NewCRL(t, ca, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))}), 0644)

	certs, err := LoadCertificates(dir)
	if err != nil || len(certs) != 2 || !certs[0].Equal(ca.Cert) {
		t.Fatalf("certificates: %d %v", len(certs), err)
	}
	crls, err := LoadCRLs(dir, true)
	if err != nil || crls.Len() != 1 {
		t.Fatalf("CRLs: %v", err)
	}
	if _, err := LoadCRLs(filepath.Join(dir, "Grid-CA.pem"), true); err == nil {
		t.Error("a file without CRLs was accepted")
	}
	if _, err := LoadCertificates(filepath.Join(dir, "1a2b3c4d.r0")); err == nil {
		t.Error("a file without certificates was accepted")
	}
}
