package handlers

// PROPFIND, served here rather than by x/net/webdav. Every property comes from the
// metadata of a stat, or of a listing (getdents64, then a statx of each name in the
// directory: see davfs.Tree.List), and no file is opened, nor read: x/net/webdav
// opens each entry of a listing three times, once to read its first 512 bytes and
// guess its content type. Nothing is allocated for each entry of a listing
// (TestPropfindAllocations): its names, dates and numbers go from reused buffers to
// the answer's. The answer is x/net/webdav's (TestPropfindAsXNetWebDAV) but for
// getcontenttype, from the name's extension alone, and for include (RFC 4918 9.1),
// which x/net/webdav ignores.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"sync"

	"github.com/labkode/weed/internal/davfs"
	"github.com/labkode/weed/internal/davreq"
	"golang.org/x/net/webdav"
)

const maxPropfindBody = 1 << 20

// listBatch is how many entries of a directory are listed at a time
const listBatch = 1024

// propfind is what a PROPFIND body asks for
type propfind struct {
	allprop, propname bool
	prop, include     []xml.Name
}

func davName(local string) xml.Name { return xml.Name{Space: "DAV:", Local: local} }

// parsePropfind reads a PROPFIND body, as x/net/webdav does: an empty body asks for
// all properties, and a body asks for allprop (with include), propname or prop,
// alone. Unlike x/net/webdav, it ignores the content of a requested property, which
// davix and gfal2 send, such as <D:resourcetype><D:collection/></D:resourcetype>.
func parsePropfind(body io.Reader) (propfind, error) {
	b, err := io.ReadAll(io.LimitReader(body, maxPropfindBody+1))
	if err != nil {
		return propfind{}, err
	}
	if len(b) > maxPropfindBody {
		return propfind{}, errors.New("PROPFIND body too large")
	}
	if len(b) == 0 {
		return propfind{allprop: true}, nil
	}
	d := xml.NewDecoder(bytes.NewReader(b))
	root, err := nextStart(d)
	if err != nil {
		return propfind{}, err
	}
	if root.Name != davName("propfind") {
		return propfind{}, errors.New("not a DAV:propfind")
	}
	var pf propfind
	var hasProp, hasInclude bool
	for {
		tok, err := d.Token()
		if err != nil {
			return propfind{}, err
		}
		if _, ok := tok.(xml.EndElement); ok {
			break
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name {
		case davName("allprop"):
			pf.allprop = true
			err = d.Skip()
		case davName("propname"):
			pf.propname = true
			err = d.Skip()
		case davName("prop"):
			hasProp = true
			pf.prop, err = appendChildren(d, pf.prop)
		case davName("include"):
			hasInclude = true
			pf.include, err = appendChildren(d, pf.include)
		default:
			err = d.Skip()
		}
		if err != nil {
			return propfind{}, err
		}
	}
	switch {
	case hasProp && len(pf.prop) == 0:
		return propfind{}, errors.New("prop must not be empty")
	case hasInclude && len(pf.include) == 0:
		return propfind{}, errors.New("include must not be empty")
	case hasInclude && !pf.allprop,
		pf.allprop && (hasProp || pf.propname),
		hasProp && pf.propname,
		!hasProp && !pf.allprop && !pf.propname:
		return propfind{}, errors.New("invalid propfind")
	}
	return pf, nil
}

// nextStart returns the next start element of d
func nextStart(d *xml.Decoder) (xml.StartElement, error) {
	for {
		tok, err := d.Token()
		if err != nil {
			return xml.StartElement{}, err
		}
		if start, ok := tok.(xml.StartElement); ok {
			return start, nil
		}
	}
}

// appendChildren appends the names of the child elements of the element just
// started in d, to its end, skipping what is in them
func appendChildren(d *xml.Decoder, names []xml.Name) ([]xml.Name, error) {
	for {
		tok, err := d.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			names = append(names, t.Name)
			if err := d.Skip(); err != nil {
				return nil, err
			}
		case xml.EndElement:
			return names, nil
		}
	}
}

// liveProps are the properties of files and directories (dir), as x/net/webdav has
// them, in the order that allprop and propname give them
var liveProps = []struct {
	name string // in DAV:
	dir  bool
}{
	{"resourcetype", true},
	{"displayname", true},
	{"getcontentlength", false},
	{"getlastmodified", true},
	{"getcontenttype", false},
	{"getetag", false},
	{"supportedlock", true},
}

// live reports whether a file, or a directory, has the property n
func live(n xml.Name, dir bool) bool {
	if n.Space != "DAV:" {
		return false
	}
	for _, p := range liveProps {
		if p.name == n.Local {
			return p.dir || !dir
		}
	}
	return false
}

// contentType is the content type of a file, from its name's extension alone:
// weed does not read files to guess it
func contentType(name string) string {
	if t := mime.TypeByExtension(path.Ext(name)); t != "" {
		return t
	}
	return "application/octet-stream"
}

// handlePropfind answers PROPFIND, of Depth 0 or 1 (ServeHTTP refuses infinity)
func (h *WebDAVHandler) handlePropfind(w http.ResponseWriter, r *http.Request, tree *davfs.Tree) {
	ctx := r.Context()
	name, ok := davreq.Strip(r.URL.Path)
	if !ok {
		h.davError(w, r, http.StatusNotFound, errors.New("outside the WebDAV namespace"))
		return
	}
	fi, err := tree.Stat(ctx, name)
	if err != nil {
		h.fsError(w, r, err, http.StatusMethodNotAllowed)
		return
	}
	var depth int
	switch r.Header.Get("Depth") {
	case "0":
	case "1":
		depth = 1
	default:
		h.davError(w, r, http.StatusBadRequest, errors.New("invalid depth"))
		return
	}
	pf, err := parsePropfind(r.Body)
	if err != nil {
		h.davError(w, r, http.StatusBadRequest, err)
		return
	}

	// A directory is opened before anything is answered: one that cannot be listed,
	// such as another account's private directory, gets 403, not an empty listing
	var l *davfs.Lister
	if depth == 1 && fi.IsDir() {
		if l, err = tree.List(ctx, name); err != nil {
			h.fsError(w, r, err, http.StatusInternalServerError)
			return
		}
		defer l.Close()
	}

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.WriteHeader(webdav.StatusMulti)
	m := multistatuses.Get().(*multistatus)
	m.w.Reset(w)
	m.pf = &pf
	defer m.release()
	m.w.WriteString(`<?xml version="1.0" encoding="UTF-8"?><D:multistatus xmlns:D="DAV:">`)

	// The href of name, and the start of those of its entries
	m.dir = appendHref(m.dir[:0], path.Join(davreq.Prefix, name))
	m.href = append(m.href[:0], m.dir...)
	if fi.IsDir() && !bytes.HasSuffix(m.href, slash) {
		m.href = append(m.href, '/')
	}
	if !bytes.HasSuffix(m.dir, slash) {
		m.dir = append(m.dir, '/')
	}
	mt := fi.ModTime()
	res := resource{href: m.href, dir: fi.IsDir(), size: fi.Size(), sec: mt.Unix(), nsec: int64(mt.Nanosecond()),
		ctype: contentType(name)}
	if path.Clean("/"+name) != "/" { // the root's displayname is left out, as x/net/webdav does
		res.name = []byte(fi.Name())
	}
	m.response(&res)

	// Leaves out in-progress uploads and symbolic links (see davfs). An error once
	// answering cannot change the status: the listing ends there, and is logged.
	for l != nil {
		entries, err := l.Next()
		for i := range entries {
			e := &entries[i]
			m.href = appendHrefBytes(append(m.href[:0], m.dir...), e.Name)
			if e.Dir {
				m.href = append(m.href, '/')
			}
			res = resource{href: m.href, name: e.Name, dir: e.Dir, size: e.Size, sec: e.MtimeSec, nsec: e.MtimeNsec}
			m.response(&res)
		}
		if err != nil {
			if err != io.EOF && h.Handler.Logger != nil {
				h.Handler.Logger(r, err)
			}
			break
		}
	}
	m.w.WriteString(`</D:multistatus>`)
	m.w.Flush()
}

var slash = []byte("/")

// multistatus writes the body of a 207 answer to PROPFIND. They are reused, with
// their buffers.
type multistatus struct {
	w      *bufio.Writer
	pf     *propfind
	all    [2][]xml.Name // what allprop asks of files [0] and directories [1]
	allSet [2]bool
	dir    []byte // the href of the directory listed, ending with a slash
	href   []byte
}

var multistatuses = sync.Pool{New: func() any { return &multistatus{w: bufio.NewWriterSize(nil, 32<<10)} }}

func (m *multistatus) release() {
	m.w.Reset(nil)
	m.pf = nil
	m.all[0], m.all[1] = m.all[0][:0], m.all[1][:0]
	m.allSet = [2]bool{}
	multistatuses.Put(m)
}

// resource is what an answer says of a file or a directory
type resource struct {
	href      []byte // escaped, as XML text
	name      []byte // the displayname; nil for the namespace's root
	ctype     string // the content type; "" for that of name's extension
	dir       bool
	size      int64
	sec, nsec int64 // the modification time, since the epoch
}

const supportedLock = `<D:lockentry xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry>`

// response writes the response of res
func (m *multistatus) response(res *resource) {
	w, dir := m.w, res.dir
	w.WriteString(`<D:response><D:href>`)
	w.Write(res.href)
	w.WriteString(`</D:href>`)

	if m.pf.propname {
		w.WriteString(`<D:propstat><D:prop>`)
		for _, p := range liveProps {
			if p.dir || !dir {
				tag(w, p.name, false)
				tag(w, p.name, true)
			}
		}
		w.WriteString(`</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>`)
		return
	}

	names := m.pf.prop
	if m.pf.allprop {
		k := 0
		if dir {
			k = 1
		}
		if !m.allSet[k] {
			for _, p := range liveProps {
				if p.dir || !dir {
					m.all[k] = append(m.all[k], davName(p.name))
				}
			}
			for _, n := range m.pf.include {
				if !live(n, dir) {
					m.all[k] = append(m.all[k], n)
				}
			}
			m.allSet[k] = true
		}
		names = m.all[k]
	}
	found, missing := 0, 0
	for _, n := range names {
		if live(n, dir) {
			found++
		} else {
			missing++
		}
	}
	if found > 0 || missing == 0 {
		w.WriteString(`<D:propstat><D:prop>`)
		for _, n := range names {
			if live(n, dir) {
				m.property(n.Local, res)
			}
		}
		w.WriteString(`</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>`)
	}
	if missing > 0 {
		w.WriteString(`<D:propstat><D:prop>`)
		for _, n := range names {
			if !live(n, dir) {
				emptyElement(w, n)
			}
		}
		w.WriteString(`</D:prop><D:status>HTTP/1.1 404 Not Found</D:status></D:propstat>`)
	}
	w.WriteString(`</D:response>`)
}

// property writes the live property local (in DAV:) of res. Numbers and dates are
// formatted in the writer's buffer (room), without allocating.
func (m *multistatus) property(local string, res *resource) {
	w := m.w
	tag(w, local, false)
	switch local {
	case "resourcetype":
		if res.dir {
			w.WriteString(`<D:collection xmlns:D="DAV:"/>`)
		}
	case "displayname":
		escapeBytes(w, res.name)
	case "getcontentlength":
		w.Write(strconv.AppendInt(room(w), res.size, 10))
	case "getlastmodified":
		w.Write(appendHTTPDate(room(w), res.sec))
	case "getcontenttype":
		t := res.ctype
		if t == "" {
			t = typeOfName(res.name)
		}
		escapeText(w, t)
	case "getetag":
		w.Write(appendETag(room(w), res.sec, res.nsec, res.size))
	case "supportedlock":
		w.WriteString(supportedLock)
	}
	tag(w, local, true)
}

// room returns the free space of w's buffer to append to (AvailableBuffer), flushed
// first if it is too little for a date, a number or an ETag: an append beyond would
// allocate
func room(w *bufio.Writer) []byte {
	if w.Available() < 64 {
		w.Flush()
	}
	return w.AvailableBuffer()
}

// tag writes the start, or the end, of the element local in DAV:, prefixed D:.
// Without concatenating: a string given to bufio.Writer escapes to the heap.
func tag(w *bufio.Writer, local string, end bool) {
	if end {
		w.WriteString(`</D:`)
	} else {
		w.WriteString(`<D:`)
	}
	w.WriteString(local)
	w.WriteByte('>')
}

// emptyElement writes an element of the name n, empty: prefixed D: in DAV:, as
// x/net/webdav writes them
func emptyElement(w *bufio.Writer, n xml.Name) {
	if n.Space == "DAV:" {
		tag(w, n.Local, false)
		tag(w, n.Local, true)
		return
	}
	w.WriteByte('<')
	w.WriteString(n.Local)
	if n.Space != "" {
		w.WriteString(` xmlns="`)
		escapeText(w, n.Space)
		w.WriteByte('"')
	}
	w.WriteString(`></`)
	w.WriteString(n.Local)
	w.WriteByte('>')
}

// escapeText writes s as XML text, as xml.EscapeText does, but without a copy of s
// when nothing in it needs escaping
func escapeText(w *bufio.Writer, s string) {
	for i := 0; i < len(s); i++ {
		if !xmlSafe(s[i]) {
			xml.EscapeText(w, []byte(s))
			return
		}
	}
	w.WriteString(s)
}

// escapeBytes is escapeText of b
func escapeBytes(w *bufio.Writer, b []byte) {
	for _, c := range b {
		if !xmlSafe(c) {
			xml.EscapeText(w, b)
			return
		}
	}
	w.Write(b)
}

// xmlSafe reports whether xml.EscapeText writes c, alone, as it is
func xmlSafe(c byte) bool {
	return c >= 0x20 && c < 0x80 && c != '&' && c != '<' && c != '>' && c != '"' && c != '\''
}

// clientGone reports whether err is that of a request that ended, its client gone,
// before it could call the storage: it waited for davfs.Gate
func clientGone(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// davError answers as x/net/webdav does when it fails: the status, and its text
func (h *WebDAVHandler) davError(w http.ResponseWriter, r *http.Request, status int, err error) {
	w.WriteHeader(status)
	w.Write([]byte(webdav.StatusText(status)))
	if h.Handler.Logger != nil {
		h.Handler.Logger(r, err)
	}
}

// fsError answers err of the filesystem: 403 if it is a permission error, 404 if
// the file does not exist, 503 if the request ended before the storage could be
// called (its client went while it waited for davfs.Gate), otherwise status
func (h *WebDAVHandler) fsError(w http.ResponseWriter, r *http.Request, err error, status int) {
	switch {
	case clientGone(err):
		h.davError(w, r, http.StatusServiceUnavailable, err)
	case errors.Is(err, fs.ErrPermission):
		http.Error(w, "Permission denied", http.StatusForbidden)
		if h.Handler.Logger != nil {
			h.Handler.Logger(r, err)
		}
	case errors.Is(err, fs.ErrNotExist):
		h.davError(w, r, http.StatusNotFound, err)
	default:
		h.davError(w, r, status, err)
	}
}
