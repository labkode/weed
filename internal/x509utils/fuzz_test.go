package x509utils

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
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
