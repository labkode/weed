package x509utils

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// certFile and crlFile match the names used in /etc/grid-security/certificates:
// <hash>.0 for CA certificates and <hash>.r0 for the CRLs written by fetch-crl
var (
	certFile = regexp.MustCompile(`(?i)(\.[0-9]|\.pem|\.crt)$`)
	crlFile  = regexp.MustCompile(`(?i)(\.r[0-9]|\.crl|\.pem|\.der)$`)
)

// LoadCertificates reads the PEM certificates in path, which is a file or a
// directory such as /etc/grid-security/certificates
func LoadCertificates(path string) ([]*x509.Certificate, error) {
	files, err := filesIn(path, certFile)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		for {
			var block *pem.Block
			block, data = pem.Decode(data)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			certs = append(certs, cert)
		}
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}
	return certs, nil
}

// SystemPoolWith builds a pool from the system roots plus the PEM certificates in
// path, which may be a file or a directory such as /etc/grid-security/certificates
func SystemPoolWith(path string) (*x509.CertPool, error) {
	certs, err := LoadCertificates(path)
	if err != nil {
		return nil, err
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool, nil
}

// filesIn returns path itself if it is a file, or the files in the directory path
// whose names match pattern
func filesIn(path string, pattern *regexp.Regexp) ([]string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return []string{path}, nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if pattern.MatchString(e.Name()) {
			p := filepath.Join(path, e.Name())
			if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() { // follows hash symlinks
				files = append(files, p)
			}
		}
	}
	return files, nil
}

// CRLSet holds certificate revocation lists, indexed by issuer
type CRLSet struct {
	// Require rejects a certificate unless a current CRL from its issuer is available,
	// so that a missing or expired CRL fails closed. Otherwise certificates are only
	// checked against the CRLs that are present and current.
	Require bool

	byIssuer map[string][]*crl
}

type crl struct {
	rawIssuer              []byte
	thisUpdate, nextUpdate time.Time
	revoked                map[string]bool // serial numbers
	checkSignatureFrom     func(issuer *x509.Certificate) error

	// verifiedBy caches successful signature checks by issuer certificate (SHA-256),
	// since CRLs of large CAs take a while to hash
	mu         sync.Mutex
	verifiedBy map[[32]byte]bool
}

// parseCRL parses a DER-encoded CRL, of version 2 or 1
func parseCRL(der []byte) (*crl, error) {
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		return parseCRLv1(der, err)
	}
	c := &crl{
		rawIssuer:          list.RawIssuer,
		thisUpdate:         list.ThisUpdate,
		nextUpdate:         list.NextUpdate,
		revoked:            make(map[string]bool, len(list.RevokedCertificateEntries)),
		checkSignatureFrom: list.CheckSignatureFrom,
	}
	for _, e := range list.RevokedCertificateEntries {
		c.revoked[e.SerialNumber.String()] = true
	}
	return c, nil
}

// parseCRLv1 parses a version 1 CRL, which x509.ParseRevocationList refused with
// errV2, "unsupported crl version": it has no version field. Some IGTF CAs still
// publish them (14 of the 128 CRLs of ca-policy-egi-core in November 2026: NIKHEF,
// NorduGrid, UK e-Science, ASGC, ArmeSFo). crypto/x509 reads them only with
// ParseDERCRL and CheckCRLSignature, deprecated because they check less than
// ParseRevocationList and RevocationList.CheckSignatureFrom do: what they leave out,
// and what applies to version 1, is checked here. A CRL that is not of version 1
// gets errV2.
func parseCRLv1(der []byte, errV2 error) (*crl, error) {
	list, err := x509.ParseDERCRL(der) //nolint:staticcheck // the only parser of version 1 CRLs in crypto/x509
	if err != nil {
		return nil, errV2
	}
	// The issuer and the signature algorithms as they are encoded, which pkix does not
	// keep. A TBSCertList that begins with a version, even 0, is not of version 1.
	var outer struct {
		TBSCertList        asn1.RawValue
		SignatureAlgorithm asn1.RawValue
	}
	var tbs struct {
		Signature asn1.RawValue
		Issuer    asn1.RawValue
	}
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		return nil, errV2
	}
	if _, err := asn1.Unmarshal(outer.TBSCertList.FullBytes, &tbs); err != nil || tbs.Signature.Tag != asn1.TagSequence {
		return nil, errV2
	}
	if !bytes.Equal(tbs.Signature.FullBytes, outer.SignatureAlgorithm.FullBytes) {
		return nil, errors.New("x509: inner and outer signature algorithm identifiers don't match")
	}
	// Only version 2 may have extensions (RFC 5280, 5.1.2.1). Those of a CRL that
	// claims to be of version 1, such as one that is a delta CRL or covers only some
	// certificates, would be ignored: refuse it instead.
	if len(list.TBSCertList.Extensions) > 0 {
		return nil, errors.New("x509: version 1 CRL with extensions, which only version 2 may have")
	}
	c := &crl{
		rawIssuer:  tbs.Issuer.FullBytes,
		thisUpdate: list.TBSCertList.ThisUpdate,
		nextUpdate: list.TBSCertList.NextUpdate,
		revoked:    make(map[string]bool, len(list.TBSCertList.RevokedCertificates)),
		// The checks of RevocationList.CheckSignatureFrom on the issuer, which
		// CheckCRLSignature does not make
		checkSignatureFrom: func(issuer *x509.Certificate) error {
			if issuer.Version == 3 && !issuer.BasicConstraintsValid || issuer.BasicConstraintsValid && !issuer.IsCA {
				return x509.ConstraintViolationError{}
			}
			if issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageCRLSign == 0 {
				return x509.ConstraintViolationError{}
			}
			if issuer.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
				return x509.ErrUnsupportedAlgorithm
			}
			return issuer.CheckCRLSignature(list) //nolint:staticcheck // see above
		},
	}
	for _, e := range list.TBSCertList.RevokedCertificates {
		if len(e.Extensions) > 0 {
			return nil, errors.New("x509: version 1 CRL with entry extensions, which only version 2 may have")
		}
		c.revoked[e.SerialNumber.String()] = true
	}
	return c, nil
}

// LoadCRLs reads the CRLs (PEM or DER) in path, a file or a directory such as
// /etc/grid-security/certificates
func LoadCRLs(path string, require bool) (*CRLSet, error) {
	files, err := filesIn(path, crlFile)
	if err != nil {
		return nil, err
	}
	set := &CRLSet{Require: require, byIssuer: make(map[string][]*crl)}
	n := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var ders [][]byte
		if strings.Contains(string(data[:min(len(data), 1024)]), "-----BEGIN") {
			for {
				var block *pem.Block
				block, data = pem.Decode(data)
				if block == nil {
					break
				}
				if block.Type == "X509 CRL" {
					ders = append(ders, block.Bytes)
				}
			}
		} else {
			ders = append(ders, data)
		}
		for _, der := range ders {
			c, err := parseCRL(der)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			set.byIssuer[string(c.rawIssuer)] = append(set.byIssuer[string(c.rawIssuer)], c)
			n++
		}
	}
	if n == 0 {
		return nil, fmt.Errorf("no CRLs found in %s", path)
	}
	return set, nil
}

// Expiry returns when the first issuer runs out of current CRLs: the earliest, over
// all issuers, of the latest NextUpdate of their CRLs (zero if none has one). With
// Require, certificates of that issuer are rejected from then on.
func (s *CRLSet) Expiry() time.Time {
	var earliest time.Time
	for _, list := range s.byIssuer {
		var latest time.Time
		for _, c := range list {
			if c.nextUpdate.After(latest) {
				latest = c.nextUpdate
			}
		}
		if !latest.IsZero() && (earliest.IsZero() || latest.Before(earliest)) {
			earliest = latest
		}
	}
	return earliest
}

// Len returns the number of CRLs in the set
func (s *CRLSet) Len() int {
	n := 0
	for _, l := range s.byIssuer {
		n += len(l)
	}
	return n
}

func (c *crl) signedBy(issuer *x509.Certificate) bool {
	key := sha256.Sum256(issuer.Raw)
	c.mu.Lock()
	defer c.mu.Unlock()
	if ok, done := c.verifiedBy[key]; done {
		return ok
	}
	ok := c.checkSignatureFrom(issuer) == nil
	if c.verifiedBy == nil {
		c.verifiedBy = make(map[[32]byte]bool)
	}
	c.verifiedBy[key] = ok
	return ok
}

// Check returns an error if cert, issued by issuer, is revoked according to the
// newest current CRL signed by issuer, or if there is no such CRL and s.Require
func (s *CRLSet) Check(cert, issuer *x509.Certificate, now time.Time) error {
	var current *crl
	for _, c := range s.byIssuer[string(issuer.RawSubject)] {
		if now.Before(c.thisUpdate) || (!c.nextUpdate.IsZero() && now.After(c.nextUpdate)) {
			continue
		}
		if !c.signedBy(issuer) {
			continue
		}
		if current == nil || c.thisUpdate.After(current.thisUpdate) {
			current = c
		}
	}
	if current == nil {
		if s.Require {
			return fmt.Errorf("no current CRL from %q to check %q against", GetDNParts(issuer), GetDNParts(cert))
		}
		return nil
	}
	if current.revoked[cert.SerialNumber.String()] {
		return fmt.Errorf("certificate %q (serial %s) has been revoked", GetDNParts(cert), cert.SerialNumber)
	}
	return nil
}

// checkChains returns nil if at least one of the verified chains (leaf first, root
// last) has no revoked certificate, and otherwise the error of the first chain
func (s *CRLSet) checkChains(chains [][]*x509.Certificate, now time.Time) error {
	var first error
	for _, chain := range chains {
		var err error
		for i := 0; i+1 < len(chain) && err == nil; i++ {
			err = s.Check(chain[i], chain[i+1], now)
		}
		if err == nil {
			return nil
		}
		if first == nil {
			first = err
		}
	}
	if first == nil {
		first = errors.New("no verified certificate chain")
	}
	return first
}
