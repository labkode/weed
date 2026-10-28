package server

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"hash/adler32"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labkode/weed/internal/davfs"
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func adler(s string) []byte {
	h := adler32.New()
	h.Write([]byte(s))
	return h.Sum(nil)
}

func md5sum(s string) []byte {
	m := md5.Sum([]byte(s))
	return m[:]
}

func TestPutCreateOverwriteAndGet(t *testing.T) {
	n := newNode(t, nil)
	resp, _ := n.do("PUT", "/f.txt", "one")
	if resp.StatusCode != 201 || resp.Header.Get("ETag") == "" {
		t.Fatalf("create: %d etag=%q", resp.StatusCode, resp.Header.Get("ETag"))
	}
	if got := resp.Header.Get("Repr-Digest"); got != "adler=:"+b64(adler("one"))+":" {
		t.Fatalf("PUT response Repr-Digest = %q", got)
	}
	if code := n.status("PUT", "/f.txt", "two"); code != 204 {
		t.Fatalf("overwrite: %d", code)
	}
	if resp, body := n.do("GET", "/f.txt", ""); resp.StatusCode != 200 || body != "two" {
		t.Fatalf("GET: %d %q", resp.StatusCode, body)
	}
}

func TestPutErrors(t *testing.T) {
	n := newNode(t, nil)
	os.Mkdir(filepath.Join(n.dir, "dir"), 0755)
	for _, c := range []struct {
		name    string
		path    string
		headers []string
		want    int
	}{
		{"missing parent", "/nope/f", nil, 409},
		{"onto a collection", "/dir", nil, 405},
		{"partial PUT", "/f", []string{"Content-Range", "bytes 0-3/10"}, 400},
		{"create-only on existing", "/dir/x", nil, 201},
		{"If-None-Match on existing", "/dir/x", []string{"If-None-Match", "*"}, 412},
		{"If-Match on missing", "/dir/y", []string{"If-Match", "*"}, 412},
		{"temporary file names", "/" + davfs.TempPrefix + "x", nil, 404},
	} {
		if code := n.status("PUT", c.path, "data", c.headers...); code != c.want {
			t.Errorf("%s: PUT %s = %d, want %d", c.name, c.path, code, c.want)
		}
	}
}

func TestPutReprDigest(t *testing.T) {
	n := newNode(t, nil)
	good := "adler=:" + b64(adler("payload")) + ":"

	if code := n.status("PUT", "/ok", "payload", "Repr-Digest", good); code != 201 {
		t.Fatalf("matching digest: %d", code)
	}
	if code := n.status("PUT", "/alias", "payload", "Repr-Digest", "adler32=:"+b64(adler("payload"))+":, md5=:"+b64(md5sum("payload"))+":"); code != 201 {
		t.Fatalf("adler32 alias + md5: %d", code)
	}

	resp, body := n.do("PUT", "/bad", "payload", "Repr-Digest", "md5=:"+b64(md5sum("something else"))+":")
	if resp.StatusCode != 412 || !strings.Contains(body, "checksum mismatch") {
		t.Fatalf("mismatch: %d %q", resp.StatusCode, body)
	}
	if _, ok := n.read("/bad"); ok {
		t.Fatal("file with mismatching digest was stored")
	}

	// A failed overwrite keeps the previous version intact
	n.status("PUT", "/ok", "corrupt", "Repr-Digest", good)
	if content, _ := n.read("/ok"); content != "payload" {
		t.Fatalf("previous version lost: %q", content)
	}

	if code := n.status("PUT", "/u", "payload", "Repr-Digest", "unixsum=:AAAA:"); code != 406 {
		t.Fatalf("unsupported algorithm: %d", code)
	}
	if code := n.status("PUT", "/m", "payload", "Repr-Digest", "adler=1234"); code != 400 {
		t.Fatalf("malformed digest: %d", code)
	}
	if code := n.status("PUT", "/e", "payload", "Repr-Digest", ""); code != 406 {
		t.Fatalf("empty Repr-Digest: %d", code)
	}
}

func TestGetDigests(t *testing.T) {
	n := newNode(t, nil)
	n.write("/f", "digest me")
	for _, method := range []string{"GET", "HEAD"} {
		resp, _ := n.do(method, "/f", "", "Want-Repr-Digest", "sha-256=1, md5=9", "Want-Digest", "adler32")
		if got, want := resp.Header.Get("Repr-Digest"), "md5=:"+b64(md5sum("digest me"))+":"; got != want {
			t.Errorf("%s Repr-Digest = %q, want %q", method, got, want)
		}
		if got, want := resp.Header.Get("Digest"), fmt.Sprintf("adler32=%x", adler("digest me")); got != want {
			t.Errorf("%s Digest = %q, want %q", method, got, want)
		}
	}
	if resp, _ := n.do("GET", "/f", ""); resp.Header.Get("Repr-Digest") != "" {
		t.Error("digest sent without being asked for")
	}
}

func TestPropfindDepth(t *testing.T) {
	n := newNode(t, nil)
	n.write("/d/f", "x")
	if code := n.status("PROPFIND", "/d/", ""); code != 403 {
		t.Fatalf("PROPFIND without Depth: %d", code)
	}
	if code := n.status("PROPFIND", "/d/", "", "Depth", "infinity"); code != 403 {
		t.Fatalf("PROPFIND Depth infinity: %d", code)
	}
	if resp, body := n.do("PROPFIND", "/d/", "", "Depth", "1"); resp.StatusCode != 207 || !strings.Contains(body, "/webdav/d/f") {
		t.Fatalf("PROPFIND Depth 1: %d %s", resp.StatusCode, body)
	}
}

// TestInterruptedUploadLeavesNothing sends half a body and drops the connection
func TestInterruptedUploadLeavesNothing(t *testing.T) {
	n := newNode(t, nil)
	n.write("/existing", "old content")

	conn, err := net.Dial("tcp", n.ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "PUT /webdav/existing HTTP/1.1\r\nHost: x\r\nAuthorization: Basic %s\r\nContent-Length: 1000\r\n\r\npartial",
		b64([]byte(basicUser+":"+basicPass)))

	temps := func() []string {
		m, _ := filepath.Glob(filepath.Join(n.dir, davfs.TempPrefix+"*"))
		return m
	}
	waitFor(t, "upload to start", func() bool { return len(temps()) == 1 })

	// While the upload is in flight, its temporary file is invisible
	if resp, body := n.do("PROPFIND", "/", "", "Depth", "1"); resp.StatusCode != 207 || strings.Contains(body, davfs.TempPrefix) {
		t.Fatalf("listing during upload: %d %s", resp.StatusCode, body)
	}
	if content, _ := n.read("/existing"); content != "old content" {
		t.Fatalf("readers see a partial file: %q", content)
	}

	conn.Close()
	waitFor(t, "temporary file cleanup", func() bool { return len(temps()) == 0 })
	if content, _ := n.read("/existing"); content != "old content" {
		t.Fatalf("interrupted upload replaced the file: %q", content)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

const lockBody = `<?xml version="1.0" encoding="utf-8"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner>test</D:owner></D:lockinfo>`

func TestLocksAreHonouredByPut(t *testing.T) {
	n := newNode(t, nil)
	n.write("/locked", "v1")
	resp, _ := n.do("LOCK", "/locked", lockBody, "Timeout", "Second-600", "Content-Type", "application/xml")
	token := strings.Trim(resp.Header.Get("Lock-Token"), "<>")
	if resp.StatusCode != 200 || token == "" {
		t.Fatalf("LOCK: %d token=%q", resp.StatusCode, token)
	}

	if code := n.status("PUT", "/locked", "v2"); code != 423 {
		t.Fatalf("PUT without the lock token: %d", code)
	}
	// A tagged list for another resource must not unlock this one
	if code := n.status("PUT", "/locked", "v2", "If", "</webdav/other> (<"+token+">)"); code != 412 {
		t.Fatalf("PUT with a token tagged for another resource: %d", code)
	}
	if code := n.status("PUT", "/locked", "v2", "If", "(<"+token+">)"); code != 204 {
		t.Fatalf("PUT with the lock token: %d", code)
	}
	if code := n.status("PUT", "/locked", "v3", "If", "<"+n.url("/locked")+"> (<"+token+">)"); code != 204 {
		t.Fatalf("PUT with a correctly tagged token: %d", code)
	}
}

func TestCopyMoveSafety(t *testing.T) {
	n := newNode(t, nil)
	n.write("/d/f", "keep me")

	// "/d/" and "/d" are the same collection: this must not delete it
	if code := n.status("COPY", "/d/", "", "Destination", n.url("/d")); code != 403 {
		t.Fatalf("COPY onto itself: %d", code)
	}
	if code := n.status("COPY", "/d", "", "Destination", "/webdav/d/sub"); code != 403 {
		t.Fatalf("COPY into itself: %d", code)
	}
	if content, ok := n.read("/d/f"); !ok || content != "keep me" {
		t.Fatal("source damaged")
	}

	// Overwrite defaults to T for MOVE (RFC 4918 section 10.6)
	n.write("/a", "A")
	n.write("/b", "B")
	if code := n.status("MOVE", "/a", "", "Destination", n.url("/b")); code != 204 {
		t.Fatalf("MOVE onto existing without Overwrite: %d", code)
	}
	if content, _ := n.read("/b"); content != "A" {
		t.Fatalf("MOVE result: %q", content)
	}

	// Local COPY is atomic like PUT and works with an equivalent host spelling
	host := strings.TrimPrefix(n.ts.URL, "http://")
	if code := n.status("COPY", "/b", "", "Destination", "http://"+strings.ToUpper(host)+"/webdav/c"); code != 201 {
		t.Fatalf("COPY: %d", code)
	}
	if code := n.status("MOVE", "/b", "", "Destination", "https://elsewhere.example/webdav/x"); code != 400 {
		t.Fatalf("MOVE to another server: %d", code)
	}
}

func TestUnlockMustTargetTheLockedResource(t *testing.T) {
	n := newNode(t, nil)
	n.write("/a/f", "x")
	n.write("/b/g", "y")
	resp, _ := n.do("LOCK", "/b/g", lockBody, "Content-Type", "application/xml")
	token := resp.Header.Get("Lock-Token")
	if resp.StatusCode != 200 || token == "" {
		t.Fatalf("LOCK: %d", resp.StatusCode)
	}

	// From a path the lock does not cover, the token can be neither released nor refreshed
	if code := n.status("UNLOCK", "/a/f", "", "Lock-Token", token); code != 409 {
		t.Fatalf("UNLOCK through another path: %d", code)
	}
	if code := n.status("LOCK", "/a/f", "", "If", "("+token+")", "Timeout", "Second-60"); code != 412 {
		t.Fatalf("LOCK refresh through another path: %d", code)
	}
	if code := n.status("LOCK", "/b/g", "", "If", "("+token+")", "Timeout", "Second-60"); code != 200 {
		t.Fatalf("LOCK refresh: %d", code)
	}
	if code := n.status("UNLOCK", "/b/g", "", "Lock-Token", token); code != 204 {
		t.Fatalf("UNLOCK: %d", code)
	}
}

func TestPropfindWithDavixBody(t *testing.T) {
	n := newNode(t, nil)
	n.write("/d/f", "x")
	os.Mkdir(filepath.Join(n.dir, "d", "sub"), 0755)
	body := `<?xml version="1.0" encoding="utf-8" ?><D:propfind xmlns:D="DAV:" xmlns:L="LCGDM:"><D:prop><D:displayname/><D:getlastmodified/><D:creationdate/><D:getcontentlength/><D:quota-used-bytes/><D:resourcetype><D:collection/></D:resourcetype><L:mode/><D:owner></D:owner><D:group></D:group></D:prop></D:propfind>`
	resp, out := n.do("PROPFIND", "/d/", body, "Depth", "1")
	if resp.StatusCode != 207 || !strings.Contains(out, "/webdav/d/f") || !strings.Contains(out, "<D:collection") {
		t.Fatalf("PROPFIND with davix body: %d %s", resp.StatusCode, out)
	}
}
