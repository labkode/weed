// Package davreq classifies WebDAV requests. Authorization (macaroon caveats) and the
// handlers both use it, so a request is always authorized as the operation it is served as.
package davreq

import (
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
)

// Prefix is the URL path under which the WebDAV namespace is served
const Prefix = "/webdav"

// InNamespace reports whether the URL path p is inside the WebDAV namespace
func InNamespace(p string) bool {
	return p == Prefix || strings.HasPrefix(p, Prefix+"/")
}

// IsClean reports whether the (decoded) URL path p is canonical: no "." or ".."
// segments and no empty segments, except for one trailing slash. ServeMux only
// cleans the escaped path, so "/a/%2e%2e/b" reaches handlers as "/a/../b"; such
// paths must be rejected before any path-based authorization.
func IsClean(p string) bool {
	c := path.Clean(p)
	return p == c || p == c+"/"
}

// Strip returns the namespace-relative name of a URL path ("/webdav/a" -> "/a")
func Strip(p string) (string, bool) {
	if !InNamespace(p) {
		return "", false
	}
	name := p[len(Prefix):]
	if name == "" {
		name = "/"
	}
	return name, true
}

// IsMacaroonRequest reports whether r asks for a new macaroon
func IsMacaroonRequest(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/macaroon-request"
}

// CopyKind says what a COPY or MOVE request does
type CopyKind int

const (
	// CopyLocal is a plain WebDAV COPY/MOVE within this server
	CopyLocal CopyKind = iota
	// CopyPull is a WLCG third-party copy where this server GETs from Source
	CopyPull
	// CopyPush is a WLCG third-party copy where this server PUTs to Destination
	CopyPush
)

// Target describes where a COPY or MOVE request points
type Target struct {
	Kind   CopyKind
	Local  string   // cleaned URL path of the destination (CopyLocal)
	Remote *url.URL // the other endpoint (CopyPull: source, CopyPush: destination)
}

// ParseTarget interprets the Source and Destination headers of a COPY or MOVE request
func ParseTarget(r *http.Request) (Target, error) {
	src, dst := r.Header.Get("Source"), r.Header.Get("Destination")
	if src != "" {
		if r.Method != "COPY" {
			return Target{}, errors.New("Source header is only valid on COPY")
		}
		if dst != "" {
			return Target{}, errors.New("Source and Destination headers are mutually exclusive")
		}
		u, err := parseRemote(src)
		if err != nil {
			return Target{}, fmt.Errorf("invalid Source header: %w", err)
		}
		return Target{Kind: CopyPull, Remote: u}, nil
	}

	if dst == "" {
		return Target{}, errors.New("missing Destination header")
	}
	u, err := url.Parse(dst)
	if err != nil {
		return Target{}, fmt.Errorf("invalid Destination header: %w", err)
	}
	if u.Host == "" || SameHost(r, u) {
		if !strings.HasPrefix(u.Path, "/") {
			return Target{}, errors.New("invalid Destination header: path must be absolute")
		}
		p := path.Clean(u.Path)
		if !InNamespace(p) {
			return Target{}, errors.New("Destination is outside the WebDAV namespace")
		}
		return Target{Kind: CopyLocal, Local: p}, nil
	}

	if r.Method != "COPY" {
		return Target{}, errors.New("MOVE to another server is not supported")
	}
	u, err = parseRemote(dst)
	if err != nil {
		return Target{}, fmt.Errorf("invalid Destination header: %w", err)
	}
	return Target{Kind: CopyPush, Remote: u}, nil
}

// parseRemote validates a remote endpoint URL; dav(s):// is accepted as an alias of http(s)://
func parseRemote(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(u.Scheme) {
	case "https", "davs":
		u.Scheme = "https"
	case "http", "dav":
		u.Scheme = "http"
	default:
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("missing host")
	}
	u.Fragment = ""
	return u, nil
}

// SameHost reports whether u names the server that received r
func SameHost(r *http.Request, u *url.URL) bool {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return hostPort(u.Host, u.Scheme) == hostPort(r.Host, scheme)
}

// hostPort normalizes a host for comparison, filling in the scheme's default port
func hostPort(host, scheme string) string {
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		h = strings.Trim(host, "[]")
		switch strings.ToLower(scheme) {
		case "https", "davs":
			p = "443"
		default:
			p = "80"
		}
	}
	return strings.ToLower(h) + ":" + p
}
