package handlers

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/davfs"
	"golang.org/x/net/webdav"
)

// The body davix 0.8 and gfal2 2.23 send to list a directory
const davixPropfind = `<?xml version="1.0" encoding="utf-8" ?><D:propfind xmlns:D="DAV:" xmlns:L="LCGDM:"><D:prop><D:displayname/><D:getlastmodified/><D:creationdate/><D:getcontentlength/><D:quota-used-bytes/><D:resourcetype><D:collection/></D:resourcetype><L:mode/><D:owner></D:owner><D:group></D:group></D:prop></D:propfind>`

// The same, as x/net/webdav accepts it: every property empty
const davixPropfindEmpty = `<?xml version="1.0" encoding="utf-8" ?><D:propfind xmlns:D="DAV:" xmlns:L="LCGDM:"><D:prop><D:displayname/><D:getlastmodified/><D:creationdate/><D:getcontentlength/><D:quota-used-bytes/><D:resourcetype/><L:mode/><D:owner/><D:group/></D:prop></D:propfind>`

func TestParsePropfind(t *testing.T) {
	pf, err := parsePropfind(strings.NewReader(davixPropfind))
	dav := davName
	want := []xml.Name{dav("displayname"), dav("getlastmodified"), dav("creationdate"), dav("getcontentlength"),
		dav("quota-used-bytes"), dav("resourcetype"), {Space: "LCGDM:", Local: "mode"}, dav("owner"), dav("group")}
	if err != nil || pf.allprop || pf.propname || !reflect.DeepEqual(pf.prop, want) {
		t.Errorf("davix's body: %+v, %v", pf, err)
	}
	for body, want := range map[string]propfind{
		"": {allprop: true},
		`<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>`:                                     {allprop: true},
		`<D:propfind xmlns:D="DAV:"><D:allprop/><D:include><D:x/></D:include></D:propfind>`:        {allprop: true, include: []xml.Name{dav("x")}},
		`<D:propfind xmlns:D="DAV:"><D:propname/></D:propfind>`:                                    {propname: true},
		`<?xml version="1.0"?><!-- c --><propfind xmlns="DAV:"><prop><getetag/></prop></propfind>`: {prop: []xml.Name{dav("getetag")}},
		`<D:propfind xmlns:D="DAV:"><D:prop><a/></D:prop><D:prop><D:b>text</D:b></D:prop><x:other xmlns:x="X:"/></D:propfind>`: {
			prop: []xml.Name{{Local: "a"}, dav("b")}},
	} {
		if got, err := parsePropfind(strings.NewReader(body)); err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %+v, %v; want %+v", body, got, err, want)
		}
	}
	for _, body := range []string{
		" ", "<", "not xml", `<propfind/>`, `<D:other xmlns:D="DAV:"/>`,
		`<D:propfind xmlns:D="DAV:"></D:propfind>`,
		`<D:propfind xmlns:D="DAV:"><D:prop></D:prop></D:propfind>`,
		`<D:propfind xmlns:D="DAV:"><D:allprop/><D:prop><D:x/></D:prop></D:propfind>`,
		`<D:propfind xmlns:D="DAV:"><D:allprop/><D:propname/></D:propfind>`,
		`<D:propfind xmlns:D="DAV:"><D:propname/><D:prop><D:x/></D:prop></D:propfind>`,
		`<D:propfind xmlns:D="DAV:"><D:prop><D:x/></D:prop><D:include><D:y/></D:include></D:propfind>`,
		`<D:propfind xmlns:D="DAV:"><D:allprop/><D:include></D:include></D:propfind>`,
		`<D:propfind xmlns:D="DAV:"><D:prop><D:x/>`,
		strings.Repeat(" ", maxPropfindBody+1),
	} {
		if pf, err := parsePropfind(strings.NewReader(body)); err == nil {
			t.Errorf("%.80q: %+v, want an error", body, pf)
		}
	}
}

// xnetFS is a davfs.Tree for x/net/webdav, whose files tell their content type as
// weed does, from their name's extension alone
type xnetFS struct{ *davfs.Tree }

type typedInfo struct {
	os.FileInfo
	name string
}

func (t typedInfo) ContentType(context.Context) (string, error) { return contentType(t.name), nil }

type typedFile struct {
	webdav.File
	name string
}

func (f typedFile) Stat() (os.FileInfo, error) {
	fi, err := f.File.Stat()
	if err != nil {
		return nil, err
	}
	return typedInfo{fi, f.name}, nil
}

func (x xnetFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	f, err := x.Tree.OpenFile(ctx, name, flag, perm)
	if err != nil {
		return nil, err
	}
	return typedFile{f, name}, nil
}

func (x xnetFS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	fi, err := x.Tree.Stat(ctx, name)
	if err != nil {
		return nil, err
	}
	return typedInfo{fi, name}, nil
}

// multistatusOf is a 207 body as a map of each href to each status to each
// property to its value: what a client reads of it, in whatever order it comes
func multistatusOf(t *testing.T, body string) map[string]map[string]map[xml.Name]string {
	t.Helper()
	var ms struct {
		Responses []struct {
			Href      string `xml:"DAV: href"`
			Propstats []struct {
				Props struct {
					Any []struct {
						XMLName xml.Name
						Inner   string `xml:",innerxml"`
					} `xml:",any"`
				} `xml:"DAV: prop"`
				Status string `xml:"DAV: status"`
			} `xml:"DAV: propstat"`
		} `xml:"DAV: response"`
	}
	if err := xml.Unmarshal([]byte(body), &ms); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	out := map[string]map[string]map[xml.Name]string{}
	for _, r := range ms.Responses {
		if out[r.Href] != nil {
			t.Errorf("%s twice", r.Href)
		}
		out[r.Href] = map[string]map[xml.Name]string{}
		for _, ps := range r.Propstats {
			props := map[xml.Name]string{}
			for _, p := range ps.Props.Any {
				props[p.XMLName] = p.Inner
			}
			out[r.Href][ps.Status] = props
		}
	}
	return out
}

// weed answers PROPFIND as x/net/webdav does, given the same content types
func TestPropfindAsXNetWebDAV(t *testing.T) {
	dir := t.TempDir()
	u := filepath.Join(dir, "u")
	os.MkdirAll(filepath.Join(u, "sub dir"), 0o755)
	for name, content := range map[string]string{
		"a&b.txt": "hello", "f": "text, without an extension", "x.html": "<p>", `q"'<>.json`: "{}",
		"é ü.pdf": "%PDF", "new\nline": "", "\xff\xfe": "bad UTF-8", davfs.TempPrefix + "1": "uploading",
	} {
		os.WriteFile(filepath.Join(u, name), []byte(content), 0o644)
	}
	os.Symlink("f", filepath.Join(u, "link"))

	h := NewWebDAVHandler(dir, &config.Config{}, nil)
	propfind := func(xnet bool, target, depth, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("PROPFIND", target, strings.NewReader(body))
		if body == "" {
			r = httptest.NewRequest("PROPFIND", target, nil)
		}
		r.Header.Set("Depth", depth)
		w := httptest.NewRecorder()
		if !xnet {
			h.ServeHTTP(w, r)
			return w
		}
		tree, err := davfs.FS{Root: dir}.Open(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer tree.Close()
		(&webdav.Handler{Prefix: "/webdav", FileSystem: xnetFS{tree}, LockSystem: webdav.NewMemLS()}).ServeHTTP(w, r)
		return w
	}

	bodies := []struct{ weed, xnet string }{
		{"", ""},
		{`<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>`, ""},
		{`<D:propfind xmlns:D="DAV:"><D:propname/></D:propfind>`, ""},
		{`<D:propfind xmlns:D="DAV:" xmlns:X="urn:x"><D:prop><D:getetag/><D:getcontentlength/><X:foo/><nons xmlns=""/><D:resourcetype/><D:getcontenttype/><D:displayname/><D:getlastmodified/><D:supportedlock/><D:lockdiscovery/></D:prop></D:propfind>`, ""},
		{`<D:propfind xmlns:D="DAV:"><D:prop><D:creationdate/></D:prop></D:propfind>`, ""},
		{davixPropfind, davixPropfindEmpty},
	}
	for _, target := range []string{"/webdav", "/webdav/", "/webdav/u/", "/webdav/u", "/webdav/u/f", "/webdav/u/a&b.txt", "/webdav/u/sub%20dir/"} {
		for _, depth := range []string{"0", "1"} {
			for _, b := range bodies {
				xnetBody := b.xnet
				if xnetBody == "" {
					xnetBody = b.weed
				}
				got, want := propfind(false, target, depth, b.weed), propfind(true, target, depth, xnetBody)
				if got.Code != want.Code || got.Header().Get("Content-Type") != want.Header().Get("Content-Type") {
					t.Fatalf("%s Depth %s %.60q: %d %q, want %d %q", target, depth, b.weed,
						got.Code, got.Header().Get("Content-Type"), want.Code, want.Header().Get("Content-Type"))
				}
				if g, w := multistatusOf(t, got.Body.String()), multistatusOf(t, want.Body.String()); !reflect.DeepEqual(g, w) {
					t.Errorf("%s Depth %s %.60q:\n got %v\nwant %v", target, depth, b.weed, g, w)
				}
			}
		}
	}

	// Refused alike
	for _, c := range []struct{ target, depth, body string }{
		{"/webdav/missing", "0", ""},
		{"/webdav/u/", "2", ""},
		{"/webdav/u/", "0", `<D:propfind xmlns:D="DAV:"><D:prop></D:prop></D:propfind>`},
		{"/webdav/u/", "0", `<D:propfind xmlns:D="DAV:"><D:allprop/><D:propname/></D:propfind>`},
		{"/webdav/u/", "0", `not xml`},
	} {
		got, want := propfind(false, c.target, c.depth, c.body), propfind(true, c.target, c.depth, c.body)
		if got.Code != want.Code || got.Body.String() != want.Body.String() {
			t.Errorf("%s Depth %s %q: %d %q, want %d %q", c.target, c.depth, c.body, got.Code, got.Body, want.Code, want.Body)
		}
	}
}

// A directory that the account may not read, such as another account's private one,
// cannot be listed: 403, not an empty listing. Its own properties can be had.
func TestPropfindUnreadableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "p")
	os.Mkdir(p, 0o755)
	os.WriteFile(filepath.Join(p, "f"), []byte("f"), 0o644)
	os.Chmod(p, 0o300)
	t.Cleanup(func() { os.Chmod(p, 0o755) })
	h := NewWebDAVHandler(dir, &config.Config{}, nil)
	for depth, want := range map[string]int{"0": http.StatusMultiStatus, "1": http.StatusForbidden} {
		r := httptest.NewRequest("PROPFIND", "/webdav/p/", nil)
		r.Header.Set("Depth", depth)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("Depth %s: %d %q, want %d", depth, w.Code, w.Body, want)
		}
	}
}

// include asks for more than allprop, which x/net/webdav ignores
func TestPropfindInclude(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "f"), []byte("f"), 0o644)
	h := NewWebDAVHandler(dir, &config.Config{}, nil)
	r := httptest.NewRequest("PROPFIND", "/webdav/f", strings.NewReader(
		`<D:propfind xmlns:D="DAV:"><D:allprop/><D:include><D:creationdate/><D:getetag/></D:include></D:propfind>`))
	r.Header.Set("Depth", "0")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	ms := multistatusOf(t, w.Body.String())["/webdav/f"]
	if _, ok := ms["HTTP/1.1 404 Not Found"][davName("creationdate")]; !ok || len(ms["HTTP/1.1 404 Not Found"]) != 1 {
		t.Errorf("include: %v, want creationdate not found", ms)
	}
	if len(ms["HTTP/1.1 200 OK"]) != len(liveProps) {
		t.Errorf("allprop with include: %v", ms)
	}
}

// GET tells a file's content type from its name alone, and serves what
// http.ServeContent does: ranges, conditional requests, HEAD
func TestGetContentTypeFromName(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "f"), []byte("plain text, which a sniffer would call text/plain"), 0o644)
	os.WriteFile(filepath.Join(dir, "a.html"), []byte("0123456789"), 0o644)
	os.Mkdir(filepath.Join(dir, "d"), 0o755)
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := NewWebDAVHandler(dir, &config.Config{}, nil)
	get := func(method, target string, headers ...string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, nil)
		for i := 0; i+1 < len(headers); i += 2 {
			r.Header.Set(headers[i], headers[i+1])
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	if w := get("GET", "/webdav/f"); w.Code != 200 || w.Header().Get("Content-Type") != "application/octet-stream" {
		t.Errorf("GET f: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	w := get("GET", "/webdav/a.html")
	if w.Code != 200 || w.Header().Get("Content-Type") != "text/html; charset=utf-8" || w.Body.String() != "0123456789" {
		t.Errorf("GET a.html: %d %q %q", w.Code, w.Header().Get("Content-Type"), w.Body)
	}
	etag := w.Header().Get("ETag")
	if fi, _ := os.Stat(filepath.Join(dir, "a.html")); etag == "" || etag != etagFor(fi) {
		t.Errorf("ETag %q", etag)
	}
	if w := get("GET", "/webdav/a.html", "Range", "bytes=2-4"); w.Code != http.StatusPartialContent || w.Body.String() != "234" {
		t.Errorf("Range: %d %q", w.Code, w.Body)
	}
	if w := get("GET", "/webdav/a.html", "If-None-Match", etag); w.Code != http.StatusNotModified {
		t.Errorf("If-None-Match: %d", w.Code)
	}
	if w := get("HEAD", "/webdav/a.html"); w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("Content-Length") != "10" {
		t.Errorf("HEAD: %d %q %q", w.Code, w.Body, w.Header().Get("Content-Length"))
	}
	if w := get("POST", "/webdav/a.html"); w.Code != 200 || w.Body.String() != "0123456789" {
		t.Errorf("POST: %d %q", w.Code, w.Body)
	}
	for _, target := range []string{"/webdav/d", "/webdav/d/", "/webdav/fifo"} {
		if w := get("GET", target); w.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s: %d, want 405", target, w.Code)
		}
	}
	if w := get("GET", "/webdav/missing"); w.Code != http.StatusNotFound {
		t.Errorf("GET of a missing file: %d", w.Code)
	}

	// Nothing opens the FIFO, which would wait for a writer
	done := make(chan struct{})
	go func() {
		defer close(done)
		if w := get("GET", "/webdav/fifo", "Want-Digest", "adler32"); w.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET of a FIFO, with Want-Digest: %d, want 405", w.Code)
		}
		if w := get("COPY", "/webdav/fifo", "Destination", "http://example.com/webdav/copy"); w.Code != http.StatusForbidden {
			t.Errorf("COPY of a FIFO: %d, want 403", w.Code)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a request of a FIFO waits for a writer")
	}
}

// Storage that does not answer holds all the slots of davfs.Gate: the requests
// beyond wait for one, and end with 503 when their clients go, rather than wait with
// a thread each
func TestStuckStorage(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "f"), []byte("cached"), 0o644)
	h := NewWebDAVHandler(dir, &config.Config{WorkerMaxStorageCalls: 1}, nil)

	// Opening a FIFO for writing waits in the kernel for a reader, as a call to a hung
	// NFS server waits for it, holding the only slot
	stuck := make(chan error, 1)
	go func() {
		tree, err := h.FS.Open(context.Background())
		if err != nil {
			stuck <- err
			return
		}
		defer tree.Close()
		f, err := tree.OpenFile(context.Background(), "/fifo", os.O_WRONLY, 0)
		if err == nil {
			f.Close()
		}
		stuck <- err
	}()
	request := func(method, target string, wait time.Duration) int {
		ctx, cancel := context.WithTimeout(context.Background(), wait)
		defer cancel()
		r := httptest.NewRequest(method, target, nil).WithContext(ctx)
		r.Header.Set("Depth", "1")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	deadline := time.Now().Add(10 * time.Second)
	for request("PROPFIND", "/webdav/", 20*time.Millisecond) != http.StatusServiceUnavailable {
		if time.Now().After(deadline) {
			t.Fatal("the FIFO's open does not hold the slot")
		}
	}
	start := time.Now()
	for _, method := range []string{"PROPFIND", "GET", "HEAD", "PUT", "DELETE"} {
		if code := request(method, "/webdav/f", 50*time.Millisecond); code != http.StatusServiceUnavailable {
			t.Errorf("%s while the storage does not answer, the client gone: %d, want 503", method, code)
		}
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("the requests whose clients went took %v", d)
	}

	// The storage answers again
	r, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := <-stuck; err != nil {
		t.Fatal(err)
	}
	if code := request("PROPFIND", "/webdav/", 10*time.Second); code != webdav.StatusMulti {
		t.Errorf("PROPFIND once the storage answers: %d", code)
	}
	if code := request("GET", "/webdav/f", 10*time.Second); code != http.StatusOK {
		t.Errorf("GET once the storage answers: %d", code)
	}
}
