package x509utils

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"
	"time"
)

// GetDNParts returns the subject DN of a certificate in the OpenSSL "compat" slash
// form used by grid-mapfiles (e.g. /DC=ch/DC=cern/OU=Users/CN=jdoe), keeping the
// RDN order in which the attributes appear in the certificate
func GetDNParts(cert *x509.Certificate) string {
	return formatDN(cert.RawSubject, cert.Subject.Names)
}

// formatDN renders an encoded Name. Attribute values are taken from names (the order
// crypto/x509 parsed them in) because its parser decodes more string types than
// encoding/asn1; rdns is only used to group multi-valued RDNs.
func formatDN(raw []byte, names []pkix.AttributeTypeAndValue) string {
	var rdns pkix.RDNSequence
	if rest, err := asn1.Unmarshal(raw, &rdns); err != nil || len(rest) > 0 || countAttrs(rdns) != len(names) {
		// Fall back to one attribute per RDN
		rdns = rdns[:0]
		for _, n := range names {
			rdns = append(rdns, pkix.RelativeDistinguishedNameSET{n})
		}
	}

	var b strings.Builder
	i := 0
	for _, set := range rdns {
		if len(set) == 0 {
			continue
		}
		b.WriteByte('/')
		for j := range set {
			if j > 0 {
				b.WriteByte('+')
			}
			atv := names[i]
			i++
			b.WriteString(attrDN(atv.Type.String()))
			b.WriteByte('=')
			if s, ok := atv.Value.(string); ok {
				b.WriteString(s)
			} else {
				fmt.Fprint(&b, atv.Value)
			}
		}
	}
	return b.String()
}

func countAttrs(rdns pkix.RDNSequence) int {
	n := 0
	for _, set := range rdns {
		n += len(set)
	}
	return n
}

// attrDN converts an attribute OID to the short name OpenSSL prints
func attrDN(attr string) string {
	switch attr {
	case "2.5.4.3":
		return "CN"
	case "2.5.4.11":
		return "OU"
	case "0.9.2342.19200300.100.1.25":
		return "DC"
	case "2.5.4.6":
		return "C"
	case "2.5.4.10":
		return "O"
	case "2.5.4.5":
		return "serialNumber"
	case "2.5.4.7":
		return "L"
	case "2.5.4.8":
		return "ST"
	case "2.5.4.9":
		return "street"
	case "2.5.4.17":
		return "postalCode"
	case "2.5.4.12":
		return "title"
	case "2.5.4.42":
		return "GN"
	case "2.5.4.43":
		return "initials"
	case "2.5.4.4":
		return "SN"
	case "2.5.4.46":
		return "dnQualifier"
	case "2.5.4.65":
		return "pseudonym"
	case "0.9.2342.19200300.100.1.1":
		return "UID"
	case "1.2.840.113549.1.9.1":
		return "emailAddress"
	}
	return attr
}

// FindCN extracts CN from given subject
func FindCN(subject string) (string, error) {
	parts := strings.Split(subject, " ")
	for i, s := range parts {
		if strings.HasPrefix(s, "CN=") && len(parts) > i {
			cn := s
			for _, ss := range parts[i+1:] {
				if strings.Contains(ss, "=") {
					break
				}
				cn = fmt.Sprintf("%s %s", cn, ss)
			}
			return cn, nil
		}
	}
	return "", errors.New("no user CN is found in subject: " + subject)
}

var (
	oidCommonName         = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidProxyCertInfo      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 14}     // RFC 3820
	oidProxyCertInfoDraft = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3536, 1, 222} // pre-RFC (GT3) proxies
)

// IsProxyOf reports whether cert is a grid proxy certificate (RFC 3820, or a legacy
// Globus proxy) issued by issuer. It checks the structural rules only, not signatures.
func IsProxyOf(cert, issuer *x509.Certificate) bool {
	// Proxies are issued by end entities (or other proxies), never by CAs, and are never CAs
	if cert.IsCA || issuer.IsCA {
		return false
	}
	if !bytes.Equal(cert.RawIssuer, issuer.RawSubject) {
		return false
	}

	// The proxy subject is the issuer subject plus exactly one CN RDN
	var subj, iss asn1.RawValue
	if _, err := asn1.Unmarshal(cert.RawSubject, &subj); err != nil {
		return false
	}
	if _, err := asn1.Unmarshal(issuer.RawSubject, &iss); err != nil {
		return false
	}
	if !bytes.HasPrefix(subj.Bytes, iss.Bytes) {
		return false
	}
	var last pkix.RelativeDistinguishedNameSET
	if rest, err := asn1.UnmarshalWithParams(subj.Bytes[len(iss.Bytes):], &last, "set"); err != nil || len(rest) > 0 {
		return false
	}
	if len(last) != 1 || !last[0].Type.Equal(oidCommonName) {
		return false
	}

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidProxyCertInfo) || ext.Id.Equal(oidProxyCertInfoDraft) {
			return true
		}
	}
	cn, _ := last[0].Value.(string)
	return cn == "proxy" || cn == "limited proxy" // legacy Globus proxies
}

// VerifyChain verifies a client certificate chain (leaf first) that may start with
// one or more proxy certificates, and returns the end-entity certificate that
// identifies the user
func VerifyChain(chain []*x509.Certificate, roots *x509.CertPool, now time.Time) (eec *x509.Certificate, proxies int, err error) {
	if len(chain) == 0 {
		return nil, 0, errors.New("no client certificate")
	}
	if roots == nil {
		return nil, 0, errors.New("no CA certificates configured")
	}

	i := 0
	for i+1 < len(chain) && IsProxyOf(chain[i], chain[i+1]) {
		proxy, issuer := chain[i], chain[i+1]
		if now.Before(proxy.NotBefore) || now.After(proxy.NotAfter) {
			return nil, 0, fmt.Errorf("proxy certificate %q expired or not yet valid (valid from %v to %v)",
				GetDNParts(proxy), proxy.NotBefore, proxy.NotAfter)
		}
		// CheckSignatureFrom would reject the issuer for not being a CA, which is
		// exactly what a proxy issuer is not; check the signature directly
		if err := issuer.CheckSignature(proxy.SignatureAlgorithm, proxy.RawTBSCertificate, proxy.Signature); err != nil {
			return nil, 0, fmt.Errorf("proxy certificate %q has an invalid signature: %w", GetDNParts(proxy), err)
		}
		i++
	}

	eec = chain[i]
	intermediates := x509.NewCertPool()
	for _, c := range chain[i+1:] {
		intermediates.AddCert(c)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := eec.Verify(opts); err != nil {
		return nil, 0, fmt.Errorf("certificate verification failed: %w", err)
	}
	return eec, i, nil
}
