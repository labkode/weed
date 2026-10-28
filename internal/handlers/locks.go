package handlers

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/labkode/weed/internal/davreq"
	"golang.org/x/net/webdav"
)

// ifList is one parenthesized list of an If header (RFC 4918 section 10.4): a
// conjunction of conditions, optionally tagged with the resource it applies to
type ifList struct {
	tag        string
	conditions []webdav.Condition
}

// parseIfHeader parses an If header into its lists (a disjunction)
func parseIfHeader(s string) ([]ifList, bool) {
	var lists []ifList
	tag, tagged := "", false
	s = strings.TrimSpace(s)
	for first := true; s != ""; first = false {
		switch s[0] {
		case '<':
			if !first && !tagged {
				return nil, false // tagged and untagged lists cannot be mixed
			}
			end := strings.IndexByte(s, '>')
			if end < 0 {
				return nil, false
			}
			tag, tagged, s = s[1:end], true, strings.TrimLeft(s[end+1:], " \t")
			if !strings.HasPrefix(s, "(") {
				return nil, false // a resource tag must be followed by a list
			}
		case '(':
			l, rest, ok := parseIfList(s[1:])
			if !ok {
				return nil, false
			}
			l.tag = tag
			lists = append(lists, l)
			s = rest
		default:
			return nil, false
		}
		s = strings.TrimLeft(s, " \t")
	}
	return lists, len(lists) > 0
}

// parseIfList parses conditions up to the closing parenthesis
func parseIfList(s string) (l ifList, rest string, ok bool) {
	not := false
	for {
		s = strings.TrimLeft(s, " \t")
		switch {
		case s == "":
			return ifList{}, "", false
		case s[0] == ')':
			if not || len(l.conditions) == 0 {
				return ifList{}, "", false
			}
			return l, s[1:], true
		case strings.HasPrefix(s, "Not") && len(s) > 3 && strings.ContainsRune(" \t<[", rune(s[3])):
			if not {
				return ifList{}, "", false
			}
			not, s = true, s[3:]
		case s[0] == '<' || s[0] == '[':
			closer := byte('>')
			if s[0] == '[' {
				closer = ']'
			}
			end := strings.IndexByte(s, closer)
			if end < 0 {
				return ifList{}, "", false
			}
			c := webdav.Condition{Not: not}
			if s[0] == '<' {
				c.Token = s[1:end]
			} else {
				c.ETag = s[1:end]
			}
			l.conditions = append(l.conditions, c)
			not, s = false, s[end+1:]
		default:
			return ifList{}, "", false
		}
	}
}

// covers reports whether a lock rooted at root can apply to name
func covers(root, name string) bool {
	return root == name || root == "/" || strings.HasPrefix(name, strings.TrimSuffix(root, "/")+"/")
}

// confirmLocks makes sure name may be written by this request and holds it for the
// duration of the request. It mirrors x/net/webdav's (unexported) logic so LOCKs taken
// through the WebDAV handler are honoured by the methods we serve ourselves, with one
// difference: a tagged If list only counts when its resource covers name, so a token
// for some other resource cannot be used to write to a resource locked by someone else.
func (h *WebDAVHandler) confirmLocks(r *http.Request, name string) (release func(), status int, err error) {
	ls := h.Handler.LockSystem
	hdr := r.Header.Get("If")
	if hdr == "" {
		// No lock tokens: take a temporary lock so the request conflicts with other clients' locks
		now := time.Now()
		token, err := ls.Create(now, webdav.LockDetails{Root: name, Duration: -1, ZeroDepth: true})
		if err != nil {
			if errors.Is(err, webdav.ErrLocked) {
				return nil, webdav.StatusLocked, err
			}
			return nil, http.StatusInternalServerError, err
		}
		return func() { ls.Unlock(time.Now(), token) }, 0, nil
	}

	lists, ok := parseIfHeader(hdr)
	if !ok {
		return nil, http.StatusBadRequest, errors.New("invalid If header")
	}
	for _, l := range lists {
		if l.tag != "" {
			u, err := url.Parse(l.tag)
			if err != nil || (u.Host != "" && !davreq.SameHost(r, u)) {
				continue
			}
			tagName, ok := davreq.Strip(path.Clean(u.Path))
			if !ok || !covers(tagName, name) {
				continue
			}
		}
		release, err := ls.Confirm(time.Now(), name, "", l.conditions...)
		if errors.Is(err, webdav.ErrConfirmationFailed) {
			continue
		}
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}
		return release, 0, nil
	}
	// RFC 4918 section 10.4.1: if all state lists fail, the request fails with 412
	return nil, http.StatusPreconditionFailed, webdav.ErrLocked
}

// lockCovers reports whether the lock identified by token applies to name
func (h *WebDAVHandler) lockCovers(name, token string) bool {
	release, err := h.Handler.LockSystem.Confirm(time.Now(), name, "", webdav.Condition{Token: token})
	if err != nil {
		return false
	}
	release()
	return true
}

// lockTokenInScope checks UNLOCK and LOCK refresh requests, which x/net/webdav applies
// to whatever lock the token names: the lock must cover the request URI, so that a
// client authorized for one path cannot release or extend locks elsewhere
func (h *WebDAVHandler) lockTokenInScope(w http.ResponseWriter, r *http.Request) bool {
	name, ok := davreq.Strip(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return false
	}

	if r.Method == "UNLOCK" {
		token := strings.TrimSpace(r.Header.Get("Lock-Token"))
		token = strings.TrimSuffix(strings.TrimPrefix(token, "<"), ">")
		if token != "" && !h.lockCovers(name, token) {
			http.Error(w, "Lock token does not apply to the request URI", http.StatusConflict)
			return false
		}
		return true
	}

	// A LOCK with an empty body is a refresh of the lock named in the If header
	if r.Header.Get("If") == "" {
		return true
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "Cannot read request body", http.StatusBadRequest)
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if len(bytes.TrimSpace(body)) > 0 {
		return true
	}
	lists, ok := parseIfHeader(r.Header.Get("If"))
	if !ok {
		http.Error(w, "Invalid If header", http.StatusBadRequest)
		return false
	}
	for _, l := range lists {
		for _, c := range l.conditions {
			if c.Token != "" && !c.Not && !h.lockCovers(name, c.Token) {
				http.Error(w, "Lock token does not apply to the request URI", http.StatusPreconditionFailed)
				return false
			}
		}
	}
	return true
}
