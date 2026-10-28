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
	oidCN                 = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidOU                 = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidO                  = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidC                  = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidDC                 = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
	oidProxyCertInfo      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 14}
	oidProxyCertInfoDraft = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3536, 1, 222}
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
	return NewProxyWith(t, issuer, ProxyOptions{Legacy: !rfc, PathLen: -1, NotAfter: notAfter})
}

// Proxy policy languages
var (
	PolicyInheritAll  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 21, 1}
	PolicyIndependent = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 21, 2}
	PolicyLimited     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3536, 1, 1, 1, 9}
)

// ProxyOptions describes a proxy certificate
type ProxyOptions struct {
	Legacy   bool                  // Globus legacy proxy: no extension, CN "proxy" (or "limited proxy")
	Limited  bool                  // with Legacy: CN "limited proxy"
	Draft    bool                  // pre-RFC (GT3) ProxyCertInfo extension and encoding
	Policy   asn1.ObjectIdentifier // policy language; default inheritAll
	PathLen  int                   // path length constraint; -1 for none
	NotAfter time.Time             // default one hour from now
	KeyUsage x509.KeyUsage         // default digitalSignature and keyEncipherment
}

// NewProxyWith issues a proxy certificate signed by issuer
func NewProxyWith(t testing.TB, issuer *Cert, o ProxyOptions) *Cert {
	t.Helper()
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(issuer.Cert.RawSubject, &rdns); err != nil {
		t.Fatal(err)
	}
	if o.NotAfter.IsZero() {
		o.NotAfter = time.Now().Add(time.Hour)
	}
	cn := "proxy"
	if o.Limited {
		cn = "limited proxy"
	}
	var exts []pkix.Extension
	if !o.Legacy {
		cn = serial(t).String()
		if o.Policy == nil {
			o.Policy = PolicyInheritAll
		}
		policy := mustMarshal(t, struct{ Language asn1.ObjectIdentifier }{o.Policy})
		var elems []byte
		switch {
		case o.Draft && o.PathLen >= 0:
			pathLen := mustMarshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: mustMarshal(t, o.PathLen)})
			elems = append(policy, pathLen...)
		case !o.Draft && o.PathLen >= 0:
			elems = append(mustMarshal(t, o.PathLen), policy...)
		default:
			elems = policy
		}
		id := oidProxyCertInfo
		if o.Draft {
			id = oidProxyCertInfoDraft
		}
		val := mustMarshal(t, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: elems})
		exts = append(exts, pkix.Extension{Id: id, Critical: true, Value: val})
	}
	notAfter := o.NotAfter
	if o.KeyUsage == 0 {
		o.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
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
		KeyUsage:        o.KeyUsage,
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

func mustMarshal(t testing.TB, v interface{}) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
