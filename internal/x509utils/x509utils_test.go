package x509utils

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
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

func TestProxyPolicies(t *testing.T) {
	ca, user := setup(t)
	rfc := testutil.ProxyOptions{PathLen: -1}
	with := func(f func(o *testutil.ProxyOptions)) testutil.ProxyOptions {
		o := rfc
		f(&o)
		return o
	}
	limited := with(func(o *testutil.ProxyOptions) { o.Policy = testutil.PolicyLimited })
	legacy := with(func(o *testutil.ProxyOptions) { o.Legacy = true })
	legacyLimited := with(func(o *testutil.ProxyOptions) { o.Legacy, o.Limited = true, true })
	draft := with(func(o *testutil.ProxyOptions) { o.Draft = true })
	pathLen := func(base testutil.ProxyOptions, n int) testutil.ProxyOptions {
		base.PathLen = n
		return base
	}

	for _, c := range []struct {
		name    string
		proxies []testutil.ProxyOptions // in issuing order: the first is signed by the user
		wantErr string
	}{
		{"impersonation proxy", []testutil.ProxyOptions{rfc}, ""},
		{"pre-RFC proxy", []testutil.ProxyOptions{draft, draft}, ""},
		{"limited proxy", []testutil.ProxyOptions{limited}, ""},
		{"limited proxy of a limited proxy", []testutil.ProxyOptions{limited, limited}, ""},
		{"limited proxy of an impersonation proxy", []testutil.ProxyOptions{rfc, limited}, ""},
		{"unrestricted proxy of a limited proxy", []testutil.ProxyOptions{limited, rfc}, "limited proxy issued unrestricted"},
		{"legacy limited proxies", []testutil.ProxyOptions{legacyLimited, legacyLimited}, ""},
		{"legacy proxy of a legacy limited proxy", []testutil.ProxyOptions{legacyLimited, legacy}, "limited proxy issued unrestricted"},
		{"path length respected", []testutil.ProxyOptions{pathLen(rfc, 1), rfc}, ""},
		{"path length 0 with nothing below", []testutil.ProxyOptions{rfc, pathLen(rfc, 0)}, ""},
		{"path length exceeded", []testutil.ProxyOptions{pathLen(rfc, 0), rfc}, "allows 0 further proxies, but 1 follow"},
		{"path length exceeded further down", []testutil.ProxyOptions{pathLen(rfc, 1), rfc, rfc}, "allows 1 further proxies, but 2 follow"},
		{"pre-RFC path length exceeded", []testutil.ProxyOptions{pathLen(draft, 0), draft}, "allows 0 further proxies"},
		{"pre-RFC path length respected", []testutil.ProxyOptions{pathLen(draft, 1), draft}, ""},
		{"independent proxy", []testutil.ProxyOptions{with(func(o *testutil.ProxyOptions) { o.Policy = testutil.PolicyIndependent })}, "independent proxies"},
		{"unknown policy language", []testutil.ProxyOptions{with(func(o *testutil.ProxyOptions) { o.Policy = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 21, 0} })}, "unsupported proxy policy language"},
		{"RFC proxy of a legacy proxy", []testutil.ProxyOptions{legacy, rfc}, "mixes legacy and RFC 3820"},
		{"legacy proxy of an RFC proxy", []testutil.ProxyOptions{rfc, legacy}, "mixes legacy and RFC 3820"},
		{"issuer may not sign", []testutil.ProxyOptions{with(func(o *testutil.ProxyOptions) { o.KeyUsage = x509.KeyUsageKeyEncipherment }), rfc}, "may not sign"},
	} {
		certs := []*testutil.Cert{user}
		for _, o := range c.proxies {
			certs = append([]*testutil.Cert{testutil.NewProxyWith(t, certs[0], o)}, certs...)
		}
		eec, n, err := VerifyChain(chain(certs...), testutil.Pool(ca), time.Now())
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%s: rejected: %v", c.name, err)
		case c.wantErr == "" && (eec != user.Cert || n != len(c.proxies)):
			t.Errorf("%s: identity %q with %d proxies", c.name, GetDNParts(eec), n)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%s: err = %v, want %q", c.name, err, c.wantErr)
		}
	}
}

func TestParseProxyCertInfoMalformed(t *testing.T) {
	policy, _ := asn1.Marshal(struct{ Language asn1.ObjectIdentifier }{oidPolicyInheritAll})
	seq := func(parts ...[]byte) []byte {
		b, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: bytes.Join(parts, nil)})
		return b
	}
	negative, _ := asn1.Marshal(-1)
	str, _ := asn1.Marshal("x")
	for name, der := range map[string][]byte{
		"empty":              {},
		"not a sequence":     str,
		"no policy":          seq(),
		"negative path len":  seq(negative, policy),
		"two policies":       seq(policy, policy),
		"unexpected element": seq(policy, str),
		"trailing bytes":     append(seq(policy), 0),
	} {
		if _, err := parseProxyCertInfo(der); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
