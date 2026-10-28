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

	// Proxy policy languages (RFC 3820 section 3.8.2, and the Globus limited proxy)
	oidPolicyInheritAll  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 21, 1}
	oidPolicyIndependent = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 21, 2}
	oidPolicyLimited     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3536, 1, 1, 1, 9}
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
	return VerifyChainCRL(chain, roots, nil, now)
}

// VerifyChainCRL is VerifyChain with revocation checks of the end-entity certificate
// and its CAs against crls (nil disables them). Proxies are short-lived and not
// covered by CRLs, but a proxy of a revoked certificate is rejected with it.
func VerifyChainCRL(chain []*x509.Certificate, roots *x509.CertPool, crls *CRLSet, now time.Time) (eec *x509.Certificate, proxies int, err error) {
	if len(chain) == 0 {
		return nil, 0, errors.New("no client certificate")
	}
	if roots == nil {
		return nil, 0, errors.New("no CA certificates configured")
	}

	i := 0
	var infos []proxyInfo // infos[j] is chain[j], issued by chain[j+1]
	for i+1 < len(chain) && IsProxyOf(chain[i], chain[i+1]) {
		proxy, issuer := chain[i], chain[i+1]
		dn := GetDNParts(proxy)
		if now.Before(proxy.NotBefore) || now.After(proxy.NotAfter) {
			return nil, 0, fmt.Errorf("proxy certificate %q expired or not yet valid (valid from %v to %v)",
				dn, proxy.NotBefore, proxy.NotAfter)
		}
		if issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return nil, 0, fmt.Errorf("proxy certificate %q was issued by a certificate that may not sign", dn)
		}
		// CheckSignatureFrom would reject the issuer for not being a CA, which is
		// exactly what a proxy issuer is not; check the signature directly
		if err := issuer.CheckSignature(proxy.SignatureAlgorithm, proxy.RawTBSCertificate, proxy.Signature); err != nil {
			return nil, 0, fmt.Errorf("proxy certificate %q has an invalid signature: %w", dn, err)
		}
		info, err := parseProxyInfo(proxy)
		if err != nil {
			return nil, 0, fmt.Errorf("proxy certificate %q: %w", dn, err)
		}
		// i proxies follow this one in the chain
		if info.pathLen >= 0 && i > info.pathLen {
			return nil, 0, fmt.Errorf("proxy certificate %q allows %d further proxies, but %d follow", dn, info.pathLen, i)
		}
		infos = append(infos, info)
		i++
	}
	for j := 0; j+1 < len(infos); j++ {
		if infos[j].legacy != infos[j+1].legacy {
			return nil, 0, errors.New("proxy chain mixes legacy and RFC 3820 proxies")
		}
		if infos[j+1].limited && !infos[j].limited {
			return nil, 0, fmt.Errorf("limited proxy issued unrestricted proxy %q", GetDNParts(chain[j]))
		}
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
	chains, err := eec.Verify(opts)
	if err != nil {
		return nil, 0, fmt.Errorf("certificate verification failed: %w", err)
	}
	if crls != nil {
		if err := crls.checkChains(chains, now); err != nil {
			return nil, 0, err
		}
	}
	return eec, i, nil
}

// proxyInfo is what a relying party must know about a proxy certificate
type proxyInfo struct {
	legacy  bool // Globus legacy proxy, identified by its CN only
	limited bool // Globus limited proxy: fine for data access, cannot issue unrestricted proxies
	pathLen int  // how many proxies may follow this one; -1 means no limit
}

// parseProxyInfo classifies a certificate already known to be a proxy (see IsProxyOf)
func parseProxyInfo(cert *x509.Certificate) (proxyInfo, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidProxyCertInfo) || ext.Id.Equal(oidProxyCertInfoDraft) {
			return parseProxyCertInfo(ext.Value)
		}
	}
	names := cert.Subject.Names
	cn, _ := names[len(names)-1].Value.(string)
	return proxyInfo{legacy: true, limited: cn == "limited proxy", pathLen: -1}, nil
}

// parseProxyCertInfo parses the ProxyCertInfo extension. RFC 3820 puts the optional
// path length first:
//
//	SEQUENCE { pCPathLenConstraint INTEGER OPTIONAL, proxyPolicy ProxyPolicy }
//
// while pre-RFC (GT3) proxies put it last, explicitly tagged:
//
//	SEQUENCE { proxyPolicy ProxyPolicy, pCPathLenConstraint [1] EXPLICIT INTEGER OPTIONAL }
func parseProxyCertInfo(der []byte) (proxyInfo, error) {
	info := proxyInfo{pathLen: -1}
	var elems []asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &elems); err != nil || len(rest) > 0 {
		return info, errors.New("malformed ProxyCertInfo extension")
	}
	var policy []byte
	for i, e := range elems {
		var err error
		switch {
		case i == 0 && e.Class == asn1.ClassUniversal && e.Tag == asn1.TagInteger:
			info.pathLen, err = parsePathLen(e.FullBytes)
		case policy == nil && e.Class == asn1.ClassUniversal && e.Tag == asn1.TagSequence:
			policy = e.FullBytes
		case policy != nil && i == len(elems)-1 && e.Class == asn1.ClassContextSpecific && e.Tag == 1 && e.IsCompound:
			info.pathLen, err = parsePathLen(e.Bytes)
		default:
			err = errors.New("malformed ProxyCertInfo extension")
		}
		if err != nil {
			return info, err
		}
	}
	if policy == nil {
		return info, errors.New("ProxyCertInfo extension has no proxy policy")
	}

	var p struct {
		Language asn1.ObjectIdentifier
		Policy   []byte `asn1:"optional"`
	}
	if rest, err := asn1.Unmarshal(policy, &p); err != nil || len(rest) > 0 {
		return info, errors.New("malformed proxy policy")
	}
	switch {
	case p.Language.Equal(oidPolicyInheritAll):
	case p.Language.Equal(oidPolicyLimited):
		info.limited = true
	case p.Language.Equal(oidPolicyIndependent):
		return info, errors.New("independent proxies do not carry the identity of their issuer")
	default:
		// A restricted proxy whose policy we cannot evaluate must not be accepted
		return info, fmt.Errorf("unsupported proxy policy language %s", p.Language)
	}
	return info, nil
}

func parsePathLen(der []byte) (int, error) {
	var n int
	if rest, err := asn1.Unmarshal(der, &n); err != nil || len(rest) > 0 || n < 0 {
		return 0, errors.New("malformed proxy path length constraint")
	}
	return n, nil
}
