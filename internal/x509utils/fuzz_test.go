package x509utils

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/labkode/weed/internal/testutil"
)

func FuzzParseProxyCertInfo(f *testing.F) {
	policy, _ := asn1.Marshal(struct{ Language asn1.ObjectIdentifier }{oidPolicyInheritAll})
	pathLen, _ := asn1.Marshal(3)
	rfc, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: append(pathLen, policy...)})
	tagged, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: pathLen})
	draft, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: append(policy, tagged...)})
	f.Add(rfc)
	f.Add(draft)
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, der []byte) {
		info, err := parseProxyCertInfo(der)
		if err == nil && info.pathLen < -1 {
			t.Fatalf("path length %d", info.pathLen)
		}
	})
}

// CRLs come from the CAs' servers, through fetch-crl: a version 2 one, which
// crypto/x509 parses, and a version 1 one, which parseCRLv1 does
func FuzzParseCRL(f *testing.F) {
	now := time.Now()
	ca := testutil.NewCA(f, testutil.Name(f, "CN=CA"))
	user := testutil.NewUser(f, ca, testutil.Name(f, "CN=user"), now.Add(-time.Hour), now.Add(time.Hour))
	f.Add(testutil.NewCRL(f, ca, now.Add(-time.Hour), now.Add(time.Hour), user))
	f.Add(testutil.NewCRLv1(f, ca, now.Add(-time.Hour), now.Add(time.Hour), nil, user))
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, der []byte) {
		c, err := parseCRL(der)
		if err != nil {
			return
		}
		if c.rawIssuer == nil || c.revoked == nil {
			t.Fatal("parsed CRL without its issuer or revoked serials")
		}
		c.checkSignatureFrom(ca.Cert)
	})
}

func FuzzFormatDN(f *testing.F) {
	f.Add(cernSubjectBytes())
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, raw []byte) {
		var rdns pkix.RDNSequence
		if rest, err := asn1.Unmarshal(raw, &rdns); err != nil || len(rest) > 0 {
			return
		}
		var name pkix.Name
		name.FillFromRDNSequence(&rdns)
		formatDN(raw, name.Names)
	})
}

func cernSubjectBytes() []byte {
	b, _ := asn1.Marshal(pkix.Name{Organization: []string{"CERN"}, CommonName: "Hugo Gonzalez Labrador"}.ToRDNSequence())
	return b
}
