package x509utils

import (
	"crypto/sha256"
	"crypto/x509"
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
	list    *x509.RevocationList
	revoked map[string]bool // serial numbers

	// verifiedBy caches successful signature checks by issuer certificate (SHA-256),
	// since CRLs of large CAs take a while to hash
	mu         sync.Mutex
	verifiedBy map[[32]byte]bool
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
			list, err := x509.ParseRevocationList(der)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			c := &crl{list: list, revoked: make(map[string]bool, len(list.RevokedCertificateEntries))}
			for _, e := range list.RevokedCertificateEntries {
				c.revoked[e.SerialNumber.String()] = true
			}
			set.byIssuer[string(list.RawIssuer)] = append(set.byIssuer[string(list.RawIssuer)], c)
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
			if c.list.NextUpdate.After(latest) {
				latest = c.list.NextUpdate
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
	ok := c.list.CheckSignatureFrom(issuer) == nil
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
		if now.Before(c.list.ThisUpdate) || (!c.list.NextUpdate.IsZero() && now.After(c.list.NextUpdate)) {
			continue
		}
		if !c.signedBy(issuer) {
			continue
		}
		if current == nil || c.list.ThisUpdate.After(current.list.ThisUpdate) {
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
