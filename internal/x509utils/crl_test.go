package x509utils

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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
	// Version 1 CRLs, as some IGTF CAs publish
	rootCRLv1 := testutil.NewCRLv1(t, root, now.Add(-hour), now.Add(hour), nil, interRevoked)
	interCRLv1 := testutil.NewCRLv1(t, inter, now.Add(-hour), now.Add(hour), nil, bob)
	expiredInterCRLv1 := testutil.NewCRLv1(t, inter, now.Add(-3*hour), now.Add(-2*hour), nil, bob)
	forgedV1 := testutil.NewCRLv1(t, rogue, now.Add(-time.Minute), now.Add(hour), nil)

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
		{"version 1: valid certificate", []*testutil.Cert{alice, inter}, [][]byte{rootCRLv1, interCRLv1}, true, ""},
		{"version 1: revoked certificate", []*testutil.Cert{bob, inter}, [][]byte{rootCRLv1, interCRLv1}, true, "has been revoked"},
		{"version 1: revoked intermediate", []*testutil.Cert{carol, interRevoked}, [][]byte{rootCRLv1}, false, "Revoked Intermediate"},
		{"version 1: required CRL expired", []*testutil.Cert{bob, inter}, [][]byte{rootCRLv1, expiredInterCRLv1}, true, "no current CRL"},
		{"version 1: only a forged CRL", []*testutil.Cert{alice, inter}, [][]byte{rootCRLv1, forgedV1}, true, "no current CRL"},
		{"version 1 and 2 from one CA", []*testutil.Cert{bob, inter}, [][]byte{rootCRL, interCRLv1, forgedNewer}, true, "has been revoked"},
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

// A version 1 CRL is read, but not one with extensions, which only version 2 may have
// and which would be ignored (a delta CRL, or one that covers only some certificates),
// nor one whose signature algorithms disagree
func TestLoadCRLsOfVersion1(t *testing.T) {
	now := time.Now()
	ca := testutil.NewCA(t, testutil.Name(t, "CN=Old CA"))
	v1 := testutil.NewCRLv1(t, ca, now.Add(-time.Hour), now.Add(time.Hour), nil)
	if c, err := parseCRL(v1); err != nil || c.checkSignatureFrom(ca.Cert) != nil {
		t.Fatalf("version 1 CRL: %v", err)
	}
	deltaCRLIndicator := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: []byte{0x02, 0x01, 0x01}}
	withExtensions := testutil.NewCRLv1(t, ca, now.Add(-time.Hour), now.Add(time.Hour), []pkix.Extension{deltaCRLIndicator})
	if _, err := LoadCRLs(writeCRLs(t, withExtensions), true); err == nil || !strings.Contains(err.Error(), "extensions") {
		t.Errorf("version 1 CRL with extensions: err = %v", err)
	}

	// The outer signature algorithm changed to sha384, the inner one left
	mismatched := bytes.Replace(v1, []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}, []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03}, 2)
	i := bytes.LastIndex(mismatched, []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03})
	copy(mismatched[:i], v1[:i]) // the TBSCertList's algorithm back to sha256
	if _, err := parseCRL(mismatched); err == nil || !strings.Contains(err.Error(), "don't match") {
		t.Errorf("mismatched signature algorithms: err = %v", err)
	}

	// Anything else that is not a CRL gets the error of crypto/x509's parser
	if _, err := parseCRL([]byte{0x30, 0x03, 0x02, 0x01, 0x05}); err == nil || !strings.Contains(err.Error(), "x509:") {
		t.Errorf("not a CRL: err = %v", err)
	}

	// Signed by a certificate that may not sign CRLs, as RevocationList.CheckSignatureFrom
	// checks: an end-entity certificate, refused for its key usage (no cRLSign), and
	// for not being a CA when it has no key usage
	user := testutil.NewUser(t, ca, testutil.Name(t, "CN=user"), now.Add(-time.Hour), now.Add(time.Hour))
	c, err := parseCRL(testutil.NewCRLv1(t, user, now.Add(-time.Hour), now.Add(time.Hour), nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.checkSignatureFrom(user.Cert); err == nil {
		t.Error("version 1 CRL signed by an end-entity certificate without cRLSign was accepted")
	}
	noKeyUsage := *user.Cert
	noKeyUsage.KeyUsage = 0
	if err := c.checkSignatureFrom(&noKeyUsage); err == nil {
		t.Error("version 1 CRL signed by an end-entity certificate without key usage was accepted")
	}
	// and by a CA whose key usage has no cRLSign
	noCRLSign := *ca.Cert
	noCRLSign.KeyUsage = x509.KeyUsageCertSign
	if c, err := parseCRL(v1); err != nil || c.checkSignatureFrom(&noCRLSign) == nil {
		t.Errorf("version 1 CRL signed by a CA without cRLSign: parse %v, accepted", err)
	}
}
