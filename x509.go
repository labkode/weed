package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
)

func getUserData(r *http.Request) []string {
	if r.TLS == nil {
		log.Printf("HTTP request does not support TLS, %+v", r)
		return []string{}
	}

	certs := r.TLS.PeerCertificates
	log.Printf("found %d peer certificates in HTTP request", len(certs))
	log.Printf("HTTP request %+v", r)
	log.Printf("HTTP request TLS %+v", r.TLS)

	for _, asn1Data := range certs {
		cert, err := x509.ParseCertificate(asn1Data.Raw)
		if err != nil {
			log.Println("x509RequestHandler tls: failed to parse certificate from server: " + err.Error())
			continue
		}

		if len(cert.UnhandledCriticalExtensions) > 0 {
			log.Println("cert.UnhandledCriticalExtensions equal to", len(cert.UnhandledCriticalExtensions))
			continue
		}

		dnParts := getDNParts(cert)
		log.Printf("cert exp: %v", cert.NotAfter.Unix())
		log.Printf("cerm email: %v", cert.EmailAddresses)
		log.Printf("cert subject name: %v", cert.Subject.CommonName)
		log.Printf("cert dump: %+v", *cert)
		log.Printf("dn parts: %+v", dnParts)
		continue
	}
	return []string{}
}

func getDNParts(cert *x509.Certificate) string {
	dnParts := []string{}
	parts := []string{}

	// loop over names
	for _, obj := range cert.Subject.Names {
		aType := attrDN(obj.Type.String())
		aValue := obj.Value
		part := fmt.Sprintf("%s=%s", aType, aValue)
		parts = append(parts, part)
	}
	for _, obj := range cert.Subject.ExtraNames {
		aType := attrDN(obj.Type.String())
		aValue := obj.Value
		part := fmt.Sprintf("%s=%s", aType, aValue)
		parts = append(parts, part)
	}
	// Extract all RDNs from the Subject field
	rdnSequence := cert.Subject.ToRDNSequence()
	for _, rdnSet := range rdnSequence {
		for _, rdn := range rdnSet {
			aType := attrDN(rdn.Type.String())
			aValue := rdn.Value.(string)
			part := fmt.Sprintf("%s=%s", aType, aValue)
			parts = append(parts, part)
		}
	}
	sort.Strings(parts)
	for _, value := range parts {
		if !contains(dnParts, value) {
			dnParts = append(dnParts, value)
		}
	}
	dn := "/" + strings.Join(dnParts, "/")
	dn = strings.Replace(dn, "//", "/", -1)
	return dn
}

// contains checks if a slice contains a specific value
func contains(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}

// helper function to convert attr ANS.1 to human readable form
// https://cs.opensource.google/go/go/+/master:src/crypto/x509/pkix/pkix.go;l=26
// crypto/x509/pkix/pkix.go
// https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772812(v=ws.10)?redirectedfrom=MSDN
// https://stackoverflow.com/questions/6465454/table-of-oids-for-certificates-subject
func attrDN(attr string) string {
	switch attr {
	case "2.5.4.3": // CN (Common Name)
		return "CN"
	case "2.5.4.11": // OU (Organizational Unit)
		return "OU"
	case "0.9.2342.19200300.100.1.25": // DC (Domain Component)
		return "DC"
	case "2.5.4.6":
		return "C"
	case "2.5.4.10":
		return "O"
	case "2.5.4.5":
		return "SERIALNUMBER"
	case "2.5.4.7":
		return "L"
	case "2.5.4.8":
		return "ST"
	case "2.5.4.17":
		return "POSTALCODE"
	case "2.5.4.12":
		return "T" // Title
	case "2.5.4.42":
		return "GN" // GivenName
	case "2.5.4.43":
		return "I" // Initials
	case "2.5.4.4":
		return "SN" // SurName
	case "1.2.840.113549.1.9.1":
		return "EMail" // EMail
	}
	return attr

}

// helper function to extract CN from given subject
func findCN(subject string) (string, error) {
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
