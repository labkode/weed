// Package testutil builds certificates for tests: a CA, end-entity certificates and
// grid proxy certificates, with subjects in a controlled RDN order.
package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

var (
	oidCN               = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidOU               = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidO                = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidC                = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidDC               = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
	oidProxyCertInfo    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 14}
	oidInheritAllPolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 21, 1}
)

var attrOIDs = map[string]asn1.ObjectIdentifier{"CN": oidCN, "OU": oidOU, "O": oidO, "C": oidC, "DC": oidDC}

// Name encodes a subject from "TYPE=value" pairs, one RDN each, in the given order
func Name(t testing.TB, attrs ...string) []byte {
	t.Helper()
	var rdns pkix.RDNSequence
	for _, a := range attrs {
		typ, val := a, ""
		for i := 0; i < len(a); i++ {
			if a[i] == '=' {
				typ, val = a[:i], a[i+1:]
				break
			}
		}
		oid, ok := attrOIDs[typ]
		if !ok {
			t.Fatalf("unknown attribute type %q", typ)
		}
		rdns = append(rdns, pkix.RelativeDistinguishedNameSET{{Type: oid, Value: val}})
	}
	raw, err := asn1.Marshal(rdns)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Cert is a certificate with its private key
type Cert struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// TLS returns a client certificate presenting chain (leaf first)
func TLS(leaf *Cert, chain ...*Cert) tls.Certificate {
	tc := tls.Certificate{PrivateKey: leaf.Key, Certificate: [][]byte{leaf.Cert.Raw}}
	for _, c := range chain {
		tc.Certificate = append(tc.Certificate, c.Cert.Raw)
	}
	return tc
}

func serial(t testing.TB) *big.Int {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func issue(t testing.TB, tmpl *x509.Certificate, parent *Cert) *Cert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parentCert, parentKey := tmpl, key
	if parent != nil {
		parentCert, parentKey = parent.Cert, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &Cert{Cert: cert, Key: key}
}

// NewCA creates a self-signed CA
func NewCA(t testing.TB, subject []byte) *Cert {
	return issue(t, &x509.Certificate{
		SerialNumber:          serial(t),
		RawSubject:            subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil)
}

// NewIntermediate creates an intermediate CA signed by parent
func NewIntermediate(t testing.TB, parent *Cert, subject []byte) *Cert {
	return issue(t, &x509.Certificate{
		SerialNumber:          serial(t),
		RawSubject:            subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, parent)
}

// NewUser creates a client (end-entity) certificate signed by ca
func NewUser(t testing.TB, ca *Cert, subject []byte, notBefore, notAfter time.Time) *Cert {
	return issue(t, &x509.Certificate{
		SerialNumber:          serial(t),
		RawSubject:            subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}, ca)
}

// NewProxy creates a proxy certificate issued by issuer (a user or another proxy).
// rfc selects an RFC 3820 proxy (ProxyCertInfo extension, numeric CN); otherwise a
// legacy Globus proxy (CN=proxy) is created.
func NewProxy(t testing.TB, issuer *Cert, rfc bool, notAfter time.Time) *Cert {
	t.Helper()
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(issuer.Cert.RawSubject, &rdns); err != nil {
		t.Fatal(err)
	}
	cn := "proxy"
	var exts []pkix.Extension
	if rfc {
		cn = serial(t).String()
		type proxyPolicy struct{ Language asn1.ObjectIdentifier }
		val, err := asn1.Marshal(struct{ Policy proxyPolicy }{proxyPolicy{oidInheritAllPolicy}})
		if err != nil {
			t.Fatal(err)
		}
		exts = append(exts, pkix.Extension{Id: oidProxyCertInfo, Critical: true, Value: val})
	}
	rdns = append(rdns, pkix.RelativeDistinguishedNameSET{{Type: oidCN, Value: cn}})
	subject, err := asn1.Marshal(rdns)
	if err != nil {
		t.Fatal(err)
	}
	return issue(t, &x509.Certificate{
		SerialNumber:    serial(t),
		RawSubject:      subject,
		NotBefore:       time.Now().Add(-time.Minute),
		NotAfter:        notAfter,
		KeyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtraExtensions: exts,
	}, issuer)
}

// Pool returns a pool containing the given CAs
func Pool(cas ...*Cert) *x509.CertPool {
	p := x509.NewCertPool()
	for _, ca := range cas {
		p.AddCert(ca.Cert)
	}
	return p
}
