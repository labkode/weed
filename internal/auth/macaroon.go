package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/labkode/weed/internal/davreq"
	"gopkg.in/macaroon.v2"
)

// Activities a macaroon can grant, as used by dCache, XRootD and FTS
const (
	ActivityDownload       = "DOWNLOAD"
	ActivityUpload         = "UPLOAD"
	ActivityList           = "LIST"
	ActivityManage         = "MANAGE"
	ActivityDelete         = "DELETE"
	ActivityReadMetadata   = "READ_METADATA"
	ActivityUpdateMetadata = "UPDATE_METADATA"
	// activityReadLegacy was minted by earlier versions of weed for HEAD
	activityReadLegacy = "READ"
)

var validActivities = map[string]bool{
	ActivityDownload:       true,
	ActivityUpload:         true,
	ActivityList:           true,
	ActivityManage:         true,
	ActivityDelete:         true,
	ActivityReadMetadata:   true,
	ActivityUpdateMetadata: true,
	activityReadLegacy:     true,
}

// AccessRequest describes what a request wants to do, for evaluating macaroon caveats
type AccessRequest struct {
	// Paths are the URL paths the request touches
	Paths []string
	// Activities lists requirements; each one is met by any of its activities
	Activities [][]string
	// ClientIP is the address the request came from
	ClientIP net.IP
}

// RequestAccess derives the access a request needs from its method and headers
func RequestAccess(r *http.Request) (AccessRequest, error) {
	ar := AccessRequest{ClientIP: remoteIP(r)}
	// Outside the WebDAV namespace (e.g. /proc/whoami) a macaroon only proves identity
	if !davreq.InNamespace(r.URL.Path) {
		return ar, nil
	}
	if !davreq.IsClean(r.URL.Path) {
		return ar, fmt.Errorf("non-canonical path %q", r.URL.Path)
	}
	ar.Paths = []string{r.URL.Path}
	need := func(activities ...string) { ar.Activities = append(ar.Activities, activities) }

	switch r.Method {
	case http.MethodGet:
		need(ActivityDownload)
	case http.MethodHead:
		need(ActivityDownload, ActivityList, ActivityReadMetadata, activityReadLegacy)
	case http.MethodPost:
		if davreq.IsMacaroonRequest(r) {
			break // minting with a macaroon attenuates it, which cannot add rights
		}
		need(ActivityDownload) // the WebDAV handler serves POST like GET
	case http.MethodOptions:
		// capability discovery only
	case "PROPFIND":
		if r.Header.Get("Depth") == "0" {
			// Only the resource's own metadata, as with HEAD; clients such as davix
			// stat a file this way before downloading it
			need(ActivityDownload, ActivityList, ActivityReadMetadata, activityReadLegacy)
		} else {
			need(ActivityList, ActivityReadMetadata)
		}
	case http.MethodPut:
		need(ActivityUpload)
	case "MKCOL":
		need(ActivityManage, ActivityUpload)
	case http.MethodDelete:
		need(ActivityDelete)
	case "PROPPATCH":
		need(ActivityUpdateMetadata, ActivityManage)
	case "LOCK", "UNLOCK":
		need(ActivityUpload, ActivityManage)
	case "COPY", "MOVE":
		t, err := davreq.ParseTarget(r)
		if err != nil {
			return ar, err
		}
		switch t.Kind {
		case davreq.CopyPull: // writes the local file
			need(ActivityUpload)
		case davreq.CopyPush: // reads the local file
			need(ActivityDownload)
		default:
			ar.Paths = append(ar.Paths, t.Local)
			if r.Method == "MOVE" {
				need(ActivityManage)
			} else {
				need(ActivityDownload)
				need(ActivityUpload)
			}
		}
	default:
		return ar, fmt.Errorf("method %s cannot be used with a macaroon", r.Method)
	}
	return ar, nil
}

func remoteIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}

// InitializeMacaroon initializes the macaroon configuration
func (as *AuthStore) InitializeMacaroon(secretKey, location string) error {
	if len(secretKey) < 32 {
		return fmt.Errorf("macaroon secret key must be at least 32 characters long")
	}

	as.MacaroonSecretKey = []byte(secretKey)
	as.MacaroonLocation = location
	return nil
}

// ValidateCaveat checks a caveat requested by a client. Identity caveats are always
// set by the server and are rejected here.
func ValidateCaveat(caveat string) error {
	key, value, ok := strings.Cut(caveat, ":")
	if !ok || value == "" {
		return fmt.Errorf("invalid caveat format: %q", caveat)
	}
	switch key {
	case "before":
		if _, err := time.Parse(time.RFC3339, value); err != nil {
			return fmt.Errorf("invalid before caveat timestamp: %q", value)
		}
	case "activity":
		for _, a := range strings.Split(value, ",") {
			if !validActivities[strings.ToUpper(strings.TrimSpace(a))] {
				return fmt.Errorf("invalid activity: %q", a)
			}
		}
	case "path":
		if !strings.HasPrefix(value, "/") {
			return fmt.Errorf("invalid path caveat: %q", value)
		}
	case "ip":
		if _, err := parseIPList(value); err != nil {
			return err
		}
	case "id":
		return errors.New("id caveats are set by the server")
	default:
		return fmt.Errorf("unsupported caveat: %q", key)
	}
	return nil
}

// CreateMacaroon creates a new macaroon with the specified caveats
func (as *AuthStore) CreateMacaroon(caveats []string) (string, error) {
	if len(as.MacaroonSecretKey) == 0 {
		return "", errors.New("macaroons are not enabled")
	}
	mac, err := macaroon.New(as.MacaroonSecretKey, []byte(randomString(16)), as.MacaroonLocation, macaroon.LatestVersion)
	if err != nil {
		return "", fmt.Errorf("failed to create macaroon: %w", err)
	}
	return as.AttenuateMacaroon(mac, caveats)
}

// AttenuateMacaroon returns a copy of mac with additional caveats. Caveats only ever
// restrict, so the result never grants more than mac.
func (as *AuthStore) AttenuateMacaroon(mac *macaroon.Macaroon, caveats []string) (string, error) {
	mac = mac.Clone()
	for _, caveat := range caveats {
		if err := mac.AddFirstPartyCaveat([]byte(caveat)); err != nil {
			return "", fmt.Errorf("failed to add caveat %s: %w", caveat, err)
		}
	}

	// Serialize the macaroon
	macBytes, err := mac.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("failed to marshal macaroon: %w", err)
	}

	// Encode as base64
	return base64.StdEncoding.EncodeToString(macBytes), nil
}

// decodeToken accepts both standard and URL-safe base64, padded or not
func decodeToken(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("invalid macaroon encoding")
}

// VerifyMacaroon verifies a macaroon token and checks every caveat against the request
func (as *AuthStore) VerifyMacaroon(tokenString string, access AccessRequest) (*AuthInfo, error) {
	if len(as.MacaroonSecretKey) == 0 {
		return nil, errors.New("macaroons are not enabled")
	}
	macBytes, err := decodeToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Deserialize the received macaroon
	mac := &macaroon.Macaroon{}
	if err := mac.UnmarshalBinary(macBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal macaroon: %w", err)
	}

	// Verify the signature first; caveats are then evaluated here, so that a valid
	// token that does not allow this request can be told apart from a bad token
	conditions, err := mac.VerifySignature(as.MacaroonSecretKey, nil)
	if err != nil {
		return nil, fmt.Errorf("macaroon verification failed: %w", err)
	}

	info := &AuthInfo{
		Method:   "macaroon",
		Details:  map[string]interface{}{"macaroon_id": string(mac.Id())},
		Macaroon: mac,
	}
	now := time.Now()
	for _, c := range conditions {
		if err := checkCaveat(c, access, info, now); err != nil {
			return nil, refusedAs(mintedFor(conditions), err)
		}
	}
	if info.Username == "" {
		return nil, errors.New("no id caveat found in macaroon")
	}
	return info, nil
}

// mintedFor returns the user of the first id caveat of a verified macaroon, the one
// it was minted with (holders can only append caveats), or "" if it has none
func mintedFor(conditions []string) string {
	for _, c := range conditions {
		if user, ok := strings.CutPrefix(c, "id:"); ok {
			return user
		}
	}
	return ""
}

// checkCaveat evaluates one first-party caveat. Unknown caveats fail: a restriction
// the server does not understand must not be silently ignored.
func checkCaveat(caveat string, access AccessRequest, info *AuthInfo, now time.Time) error {
	key, value, ok := strings.Cut(caveat, ":")
	if !ok {
		return fmt.Errorf("invalid caveat format: %s", caveat)
	}

	switch key {
	case "before":
		expiry, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return fmt.Errorf("invalid before caveat timestamp: %s", value)
		}
		if now.After(expiry) {
			return fmt.Errorf("macaroon expired at %s", value)
		}
		if prev, ok := info.Details["expires"].(time.Time); !ok || expiry.Before(prev) {
			info.Details["expires"] = expiry
		}
	case "id":
		if value == "" {
			return fmt.Errorf("empty id caveat")
		}
		// A holder can append caveats; an identity can be stated more than once but never changed
		if info.Username != "" && info.Username != value {
			return fmt.Errorf("%w: conflicting id caveats", errForbidden)
		}
		info.Username = value
	case "activity":
		var granted []string
		for _, a := range strings.Split(value, ",") {
			a = strings.ToUpper(strings.TrimSpace(a))
			if !validActivities[a] {
				return fmt.Errorf("invalid activity: %s", a)
			}
			granted = append(granted, a)
		}
		for _, required := range access.Activities {
			if !anyIn(required, granted) {
				return fmt.Errorf("%w: activity caveat %s does not allow %s", errForbidden, value, strings.Join(required, " or "))
			}
		}
		info.Details["activities"] = intersect(info.Details["activities"], granted)
	case "path":
		if !strings.HasPrefix(value, "/") {
			return fmt.Errorf("invalid path caveat: %s", value)
		}
		for _, p := range access.Paths {
			if !pathMatches(p, value) {
				return fmt.Errorf("%w: path %s not allowed by caveat path:%s", errForbidden, p, value)
			}
		}
		paths, _ := info.Details["path"].([]string)
		info.Details["path"] = append(paths, value)
	case "ip":
		nets, err := parseIPList(value)
		if err != nil {
			return err
		}
		allowed := false
		for _, n := range nets {
			if access.ClientIP != nil && n.Contains(access.ClientIP) {
				allowed = true
			}
		}
		if !allowed {
			return fmt.Errorf("%w: client address %v not allowed by caveat ip:%s", errForbidden, access.ClientIP, value)
		}
		info.Details["allowed_ips"] = value
	default:
		return fmt.Errorf("%w: unsupported caveat %s", errForbidden, key)
	}
	return nil
}

// pathMatches checks if a request path is allowed by a path caveat: the caveat
// path itself and everything below it ("/a" and "/a/" both allow "/a/b", not "/ab")
func pathMatches(requestPath, caveatPath string) bool {
	if !davreq.IsClean(requestPath) {
		return false // a prefix test on "/a/../b" would wrongly succeed for "/a"
	}
	caveat := strings.TrimSuffix(caveatPath, "/")
	if caveat == "" {
		return true
	}
	return requestPath == caveat || strings.HasPrefix(requestPath, caveat+"/")
}

// parseIPList parses a comma-separated list of addresses and CIDR ranges
func parseIPList(value string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, s := range strings.Split(value, ",") {
		s = strings.TrimSpace(s)
		if !strings.Contains(s, "/") {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, fmt.Errorf("invalid ip caveat: %q", s)
			}
			bits := 8 * net.IPv6len
			if ip.To4() != nil {
				ip, bits = ip.To4(), 8*net.IPv4len
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid ip caveat: %q", s)
		}
		nets = append(nets, n)
	}
	return nets, nil
}

func anyIn(candidates, set []string) bool {
	for _, c := range candidates {
		for _, s := range set {
			if c == s {
				return true
			}
		}
	}
	return false
}

// intersect narrows the effective activities when several activity caveats are present
func intersect(prev interface{}, granted []string) []string {
	p, ok := prev.([]string)
	if !ok {
		return granted
	}
	var out []string
	for _, a := range p {
		if anyIn([]string{a}, granted) {
			out = append(out, a)
		}
	}
	return out
}
