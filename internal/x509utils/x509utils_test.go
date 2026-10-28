package x509utils

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/labkode/weed/internal/testutil"
)

const cernDN = "/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=gonzalhu/CN=756361/CN=Hugo Gonzalez Labrador"

func cernSubject(t *testing.T) []byte {
	return testutil.Name(t, "DC=ch", "DC=cern", "OU=Organic Units", "OU=Users", "CN=gonzalhu", "CN=756361", "CN=Hugo Gonzalez Labrador")
}

func TestGetDNPartsKeepsCertificateOrder(t *testing.T) {
	ca := testutil.NewCA(t, testutil.Name(t, "CN=Test CA"))
	user := testutil.NewUser(t, ca, cernSubject(t), time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if got := GetDNParts(user.Cert); got != cernDN {
		t.Fatalf("GetDNParts = %q, want %q", got, cernDN)
	}
}

func TestGetDNPartsShortNames(t *testing.T) {
	ca := testutil.NewCA(t, testutil.Name(t, "CN=Test CA"))
	user := testutil.NewUser(t, ca, testutil.Name(t, "C=US", "O=Test Org", "OU=Test Unit", "CN=Test Client"), time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if got, want := GetDNParts(user.Cert), "/C=US/O=Test Org/OU=Test Unit/CN=Test Client"; got != want {
		t.Fatalf("GetDNParts = %q, want %q", got, want)
	}
}

func setup(t *testing.T) (*testutil.Cert, *testutil.Cert) {
	ca := testutil.NewCA(t, testutil.Name(t, "DC=ch", "DC=cern", "CN=Test CA"))
	user := testutil.NewUser(t, ca, cernSubject(t), time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	return ca, user
}

func chain(certs ...*testutil.Cert) []*x509.Certificate {
	out := make([]*x509.Certificate, len(certs))
	for i, c := range certs {
		out[i] = c.Cert
	}
	return out
}

func TestVerifyChainPlainCertificate(t *testing.T) {
	ca, user := setup(t)
	eec, proxies, err := VerifyChain(chain(user), testutil.Pool(ca), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if eec != user.Cert || proxies != 0 {
		t.Fatalf("got eec=%v proxies=%d", GetDNParts(eec), proxies)
	}
}

func TestVerifyChainWithIntermediate(t *testing.T) {
	root := testutil.NewCA(t, testutil.Name(t, "CN=Root"))
	inter := testutil.NewIntermediate(t, root, testutil.Name(t, "CN=Intermediate"))
	user := testutil.NewUser(t, inter, testutil.Name(t, "CN=alice"), time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if _, _, err := VerifyChain(chain(user, inter), testutil.Pool(root), time.Now()); err != nil {
		t.Fatalf("chain with intermediate rejected: %v", err)
	}
}

func TestVerifyChainProxies(t *testing.T) {
	ca, user := setup(t)
	for _, rfc := range []bool{true, false} {
		p1 := testutil.NewProxy(t, user, rfc, time.Now().Add(12*time.Hour))
		p2 := testutil.NewProxy(t, p1, rfc, time.Now().Add(12*time.Hour))
		eec, proxies, err := VerifyChain(chain(p2, p1, user), testutil.Pool(ca), time.Now())
		if err != nil {
			t.Fatalf("rfc=%v: %v", rfc, err)
		}
		if GetDNParts(eec) != cernDN || proxies != 2 {
			t.Fatalf("rfc=%v: identity %q with %d proxies", rfc, GetDNParts(eec), proxies)
		}
	}
}

func TestVerifyChainRejectsBadProxies(t *testing.T) {
	ca, user := setup(t)
	pool := testutil.Pool(ca)

	// Expired proxy
	expired := testutil.NewProxy(t, user, true, time.Now().Add(-time.Second))
	if _, _, err := VerifyChain(chain(expired, user), pool, time.Now()); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired proxy: err = %v", err)
	}

	// Proxy claiming the user as issuer but signed by another user's key
	other := testutil.NewUser(t, ca, cernSubject(t), time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	forged := testutil.NewProxy(t, other, true, time.Now().Add(time.Hour))
	if _, _, err := VerifyChain(chain(forged, user), pool, time.Now()); err == nil {
		t.Fatal("proxy signed by a different key was accepted")
	}

	// A proxy without its issuer in the chain is not a valid end entity
	p := testutil.NewProxy(t, user, true, time.Now().Add(time.Hour))
	if _, _, err := VerifyChain(chain(p), pool, time.Now()); err == nil {
		t.Fatal("lone proxy accepted")
	}

	// Self-signed user with a proxy: the end entity does not chain to the CA
	rogueCA := testutil.NewCA(t, testutil.Name(t, "CN=Rogue"))
	rogue := testutil.NewUser(t, rogueCA, cernSubject(t), time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	rp := testutil.NewProxy(t, rogue, true, time.Now().Add(time.Hour))
	if _, _, err := VerifyChain(chain(rp, rogue), pool, time.Now()); err == nil {
		t.Fatal("proxy of an untrusted user accepted")
	}
}

func TestCAIssuedCertIsNotAProxy(t *testing.T) {
	// A user whose DN is the CA DN plus a CN looks like a proxy structurally, but CAs
	// do not issue proxies: identity must remain the user, not the CA
	ca := testutil.NewCA(t, testutil.Name(t, "DC=org", "CN=CA"))
	user := testutil.NewUser(t, ca, testutil.Name(t, "DC=org", "CN=CA", "CN=alice"), time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	// Even when it is named like a legacy proxy
	sneaky := testutil.NewUser(t, ca, testutil.Name(t, "DC=org", "CN=CA", "CN=proxy"), time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	for _, c := range []*testutil.Cert{user, sneaky} {
		if IsProxyOf(c.Cert, ca.Cert) {
			t.Fatalf("CA-issued certificate %s treated as a proxy", GetDNParts(c.Cert))
		}
		eec, proxies, err := VerifyChain(chain(c, ca), testutil.Pool(ca), time.Now())
		if err != nil || eec != c.Cert || proxies != 0 {
			t.Fatalf("eec=%v proxies=%d err=%v", GetDNParts(eec), proxies, err)
		}
	}
}

func TestVerifyChainRejectsExpiredUser(t *testing.T) {
	ca := testutil.NewCA(t, testutil.Name(t, "CN=CA"))
	user := testutil.NewUser(t, ca, testutil.Name(t, "CN=old"), time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	if _, _, err := VerifyChain(chain(user), testutil.Pool(ca), time.Now()); err == nil {
		t.Fatal("expired certificate accepted")
	}
}
