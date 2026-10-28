package server

import (
	"bufio"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/labkode/weed/internal/config"
)

// finalLine returns the last line of a performance marker stream
func finalLine(body string) string {
	lines := strings.Split(strings.TrimSpace(body), "\n")
	return lines[len(lines)-1]
}

// copyTPC sends a TPC COPY to the active node and returns status and marker stream
func copyTPC(t *testing.T, active *node, p string, headers ...string) (int, string) {
	t.Helper()
	resp, body := active.do("COPY", p, "", headers...)
	if resp.StatusCode == http.StatusAccepted && resp.Header.Get("Content-Type") != "text/perf-marker-stream" {
		t.Fatalf("Content-Type = %q", resp.Header.Get("Content-Type"))
	}
	return resp.StatusCode, body
}

func expectSuccess(t *testing.T, code int, body string) {
	t.Helper()
	if code != 202 || finalLine(body) != "success: Created" {
		t.Fatalf("TPC: %d %q", code, body)
	}
}

func expectFailure(t *testing.T, code int, body, contains string) {
	t.Helper()
	last := finalLine(body)
	if code != 202 || !strings.HasPrefix(last, "failure: ") || !strings.Contains(last, contains) {
		t.Fatalf("TPC: want failure containing %q, got %d %q", contains, code, body)
	}
}

func TestTPCPullWithMacaroons(t *testing.T) {
	active, passive := newNode(t, nil), newNode(t, nil)
	passive.write("/src/event.root", "event data")
	mac, _ := passive.mint("/src/event.root", `{"caveats":["activity:DOWNLOAD"]}`)

	code, body := copyTPC(t, active, "/event.root",
		"Source", passive.url("/src/event.root"),
		"TransferHeaderAuthorization", "Bearer "+mac,
		"Credential", "none",
		"Repr-Digest", "adler=:"+b64(adler("event data"))+":")
	expectSuccess(t, code, body)
	if content, _ := active.read("/event.root"); content != "event data" {
		t.Fatalf("pulled content = %q", content)
	}

	// The stored file's checksum was cached while it was written
	resp, _ := active.do("HEAD", "/event.root", "", "Want-Digest", "adler32")
	if got := resp.Header.Get("Digest"); got != fmt.Sprintf("adler32=%x", adler("event data")) {
		t.Fatalf("Digest after pull = %q", got)
	}

	// Without the transfer credential the source refuses
	code, body = copyTPC(t, active, "/event2.root", "Source", passive.url("/src/event.root"))
	expectFailure(t, code, body, "401")
}

func TestTPCPullChecksumMismatch(t *testing.T) {
	active, passive := newNode(t, nil), newNode(t, nil)
	passive.write("/f", "real data")

	code, body := copyTPC(t, active, "/f",
		"Source", passive.url("/f"),
		"TransferHeaderAuthorization", "Basic "+b64([]byte(basicUser+":"+basicPass)),
		"Repr-Digest", "adler=:"+b64(adler("expected data"))+":")
	expectFailure(t, code, body, "checksum mismatch")
	if _, ok := active.read("/f"); ok {
		t.Fatal("file with mismatching checksum was stored")
	}
}

// fakeSource serves fixed content with an optional Repr-Digest header, and counts
// how much of the body was actually read by the client
func fakeSource(t *testing.T, content, reprDigest string, wantSeen *string) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wantSeen != nil {
			*wantSeen = r.Header.Get("Want-Repr-Digest")
		}
		if reprDigest != "" {
			w.Header().Set("Repr-Digest", reprDigest)
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		io.WriteString(w, content)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestTPCPullDataIntegrityScenarios(t *testing.T) {
	active := newNode(t, nil)
	client := "adler=:" + b64(adler("good")) + ":"

	// (a) the source states a digest that contradicts the client: fail without the data
	var want string
	src := fakeSource(t, "good", "adler=:"+b64(adler("other"))+":", &want)
	code, body := copyTPC(t, active, "/a", "Source", src.URL+"/f", "Repr-Digest", client)
	expectFailure(t, code, body, "source reports adler")
	if want != "adler=9" {
		t.Fatalf("Want-Repr-Digest sent to source = %q", want)
	}

	// (b) the source states the right digest but the data is corrupted: the active
	// side must verify the bytes it received
	src = fakeSource(t, "gooD", client, nil)
	code, body = copyTPC(t, active, "/b", "Source", src.URL+"/f", "Repr-Digest", client)
	expectFailure(t, code, body, "received data has adler")

	// (c) the source gives no digest: verify locally
	src = fakeSource(t, "good", "", nil)
	code, body = copyTPC(t, active, "/c", "Source", src.URL+"/f", "Repr-Digest", client)
	expectSuccess(t, code, body)
	src = fakeSource(t, "bad!", "", nil)
	code, body = copyTPC(t, active, "/c2", "Source", src.URL+"/f", "Repr-Digest", client)
	expectFailure(t, code, body, "checksum mismatch")
}

func TestTPCPerfMarkers(t *testing.T) {
	active := newNode(t, nil)
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "50")
		for i := 0; i < 5; i++ {
			io.WriteString(w, "0123456789")
			w.(http.Flusher).Flush()
			time.Sleep(60 * time.Millisecond)
		}
	}))
	defer src.Close()

	code, body := copyTPC(t, active, "/slow", "Source", src.URL+"/f")
	expectSuccess(t, code, body)
	markers := regexp.MustCompile(`Perf Marker\n\tTimestamp: \d+\n\tStripe Index: 0\n\tStripe Bytes Transferred: (\d+)\n\tTotal Stripe Count: 1\n\tRemoteConnections: tcp:127\.0\.0\.1:\d+\nEnd\n`).FindAllStringSubmatch(body, -1)
	if len(markers) < 3 {
		t.Fatalf("expected several performance markers, got:\n%s", body)
	}
	prev := -1
	for _, m := range markers {
		n, _ := strconv.Atoi(m[1])
		if n < prev || n > 50 {
			t.Fatalf("bytes transferred not monotonic: %v", markers)
		}
		prev = n
	}
}

func TestTPCPullStallAndErrors(t *testing.T) {
	active := newNode(t, func(cfg *config.Config, _ string) { cfg.TPCStallTimeout = 200 * time.Millisecond })

	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		io.WriteString(w, "a few bytes")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer hang.Close()
	code, body := copyTPC(t, active, "/stalled", "Source", hang.URL+"/f")
	expectFailure(t, code, body, "stalled")
	if _, ok := active.read("/stalled"); ok {
		t.Fatal("partial file stored after stall")
	}

	gzipped := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		io.WriteString(w, "\x1f\x8b not really gzip")
	}))
	defer gzipped.Close()
	code, body = copyTPC(t, active, "/gz", "Source", gzipped.URL+"/f")
	expectFailure(t, code, body, "Content-Encoding")

	missing := httptest.NewServer(http.NotFoundHandler())
	defer missing.Close()
	code, body = copyTPC(t, active, "/missing", "Source", missing.URL+"/f?authz=SECRET")
	expectFailure(t, code, body, "404")
	if strings.Contains(body, "SECRET") {
		t.Fatal("URL query (may hold credentials) leaked into the marker stream")
	}
}

func TestTPCPreflightChecks(t *testing.T) {
	active := newNode(t, nil)
	active.write("/exists", "x")
	active.write("/dir/f", "x")
	src := fakeSource(t, "data", "", nil).URL + "/f"

	for _, c := range []struct {
		name    string
		path    string
		headers []string
		want    int
	}{
		{"Overwrite F on existing", "/exists", []string{"Source", src, "Overwrite", "F"}, 412},
		{"onto a collection", "/dir", []string{"Source", src}, 405},
		{"missing parent", "/nope/f", []string{"Source", src}, 409},
		{"credential delegation", "/new", []string{"Source", src, "Credential", "gridsite"}, 501},
		{"unsupported scheme", "/new", []string{"Source", "ftp://host/f"}, 400},
		{"Source and Destination", "/new", []string{"Source", src, "Destination", src}, 400},
		{"unsupported digest", "/new", []string{"Source", src, "Repr-Digest", "unixsum=:AAAA:"}, 406},
		{"push missing file", "/absent", []string{"Destination", "https://remote.example/f"}, 404},
		{"push a collection", "/dir", []string{"Destination", "https://remote.example/f"}, 405},
	} {
		if code, body := copyTPC(t, active, c.path, c.headers...); code != c.want {
			t.Errorf("%s: %d %s, want %d", c.name, code, body, c.want)
		}
	}

	// A lock held by someone else blocks a pull onto the file
	resp, _ := active.do("LOCK", "/exists", lockBody, "Content-Type", "application/xml")
	if resp.StatusCode != 200 {
		t.Fatalf("LOCK: %d", resp.StatusCode)
	}
	if code, _ := copyTPC(t, active, "/exists", "Source", src); code != 423 {
		t.Errorf("pull onto locked file: %d", code)
	}
}

func TestTPCRestrictions(t *testing.T) {
	src := fakeSource(t, "data", "", nil).URL + "/f"

	disabled := newNode(t, func(cfg *config.Config, _ string) { cfg.TPC = false })
	if code, _ := copyTPC(t, disabled, "/x", "Source", src); code != 501 {
		t.Fatalf("TPC disabled: %d", code)
	}

	strict := newNode(t, func(cfg *config.Config, _ string) { cfg.TPCAllowHTTP, cfg.TPCAllowLocal = false, false })
	if code, _ := copyTPC(t, strict, "/x", "Source", src); code != 400 {
		t.Fatalf("plain http with -tpc-allow-http=false: %d", code)
	}
	noLocal := newNode(t, func(cfg *config.Config, _ string) { cfg.TPCAllowLocal = false })
	code, body := copyTPC(t, noLocal, "/x", "Source", src)
	expectFailure(t, code, body, "not allowed")

	// A macaroon that can only read cannot be used to pull (which writes)
	n := newNode(t, nil)
	ro, _ := n.mint("/", `{"caveats":["activity:DOWNLOAD,LIST"]}`)
	if code, _ := copyTPC(t, n, "/x", "Source", src, "Authorization", "Bearer "+ro); code != 403 {
		t.Fatalf("pull with a read-only macaroon: %d", code)
	}
}

func TestTPCPush(t *testing.T) {
	active, passive := newNode(t, nil), newNode(t, nil)
	active.write("/out/event.root", "pushed data")
	os.MkdirAll(passive.dir+"/in", 0755)
	mac, _ := passive.mint("/in/event.root", `{"caveats":["activity:UPLOAD"]}`)
	good := "adler=:" + b64(adler("pushed data")) + ":"

	code, body := copyTPC(t, active, "/out/event.root",
		"Destination", passive.url("/in/event.root"),
		"TransferHeaderAuthorization", "Bearer "+mac,
		"Repr-Digest", good)
	expectSuccess(t, code, body)
	if content, _ := passive.read("/in/event.root"); content != "pushed data" {
		t.Fatalf("pushed content = %q", content)
	}

	// The destination verifies the forwarded digest and answers 412 on mismatch
	mac2, _ := passive.mint("/in/bad.root", `{"caveats":["activity:UPLOAD"]}`)
	code, body = copyTPC(t, active, "/out/event.root",
		"Destination", passive.url("/in/bad.root"),
		"TransferHeaderAuthorization", "Bearer "+mac2,
		"Repr-Digest", "adler=:"+b64(adler("not the data"))+":")
	expectFailure(t, code, body, "checksum mismatch reported by destination")
	if _, ok := passive.read("/in/bad.root"); ok {
		t.Fatal("destination stored a file with a mismatching checksum")
	}

	// Errors from the destination are reported
	code, body = copyTPC(t, active, "/out/event.root", "Destination", passive.url("/in/noauth.root"))
	expectFailure(t, code, body, "401")
}

func TestTPCPushFollowsRedirects(t *testing.T) {
	// Like a dCache door, answer the PUT with a redirect to where the data goes. The
	// redirect stays on the same host so the Authorization header is kept.
	door := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/door/") {
				http.Redirect(w, r, "/webdav/"+strings.TrimPrefix(r.URL.Path, "/door/"), http.StatusTemporaryRedirect)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	active, passive := newNode(t, nil), newNode(t, nil, door)
	active.write("/f", "redirected data")
	mac, _ := passive.mint("/f", `{"caveats":["activity:UPLOAD"]}`)

	code, body := copyTPC(t, active, "/f",
		"Destination", passive.ts.URL+"/door/f",
		"TransferHeaderAuthorization", "Bearer "+mac,
		"Repr-Digest", "adler=:"+b64(adler("redirected data"))+":")
	expectSuccess(t, code, body)
	if content, _ := passive.read("/f"); content != "redirected data" {
		t.Fatalf("content after redirect = %q", content)
	}
}

func TestTPCRefusesUnsafeRemoteBehaviour(t *testing.T) {
	active := newNode(t, nil)

	// A body delimited only by connection close cannot be told apart from a truncated one
	raw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buf, _ := w.(http.Hijacker).Hijack()
		buf.WriteString("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nmaybe truncated")
		buf.Flush()
		conn.Close()
	}))
	defer raw.Close()
	code, body := copyTPC(t, active, "/unframed", "Source", raw.URL+"/f")
	expectFailure(t, code, body, "Content-Length")

	// A 302 turns PUT into GET; following it would report an upload that never happened
	active.write("/empty", "")
	moved := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		w.WriteHeader(200)
	}))
	defer moved.Close()
	code, body = copyTPC(t, active, "/empty", "Destination", moved.URL+"/f")
	expectFailure(t, code, body, "refusing redirect")
}

// With a destination that does not verify digests, weed checks the data it sent
// against the client's digests itself
func TestTPCPushVerifiesSourceDigests(t *testing.T) {
	active := newNode(t, nil)
	data := make([]byte, 4<<20-1) // several chunks, the last one big: hashed while it is sent
	rand.Read(data)
	os.WriteFile(filepath.Join(active.dir, "f"), data, 0644)
	dst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer dst.Close()
	md5sum := md5.Sum(data)
	sha := sha256.Sum256(data)
	good := fmt.Sprintf("md5=:%s:, sha-256=:%s:", b64(md5sum[:]), b64(sha[:]))

	code, body := copyTPC(t, active, "/f", "Destination", dst.URL+"/f", "Repr-Digest", good)
	expectSuccess(t, code, body)
	code, body = copyTPC(t, active, "/f", "Destination", dst.URL+"/f", "Repr-Digest", "md5=:"+b64(make([]byte, 16))+":")
	expectFailure(t, code, body, "source file does not match the client checksum")
}

// A destination that answers before reading the data, then stops reading, must not
// leave the push waiting forever
func TestTPCPushDestinationAnswersEarly(t *testing.T) {
	active := newNode(t, nil)
	data := make([]byte, 64<<20) // more than socket buffers hold
	os.WriteFile(filepath.Join(active.dir, "f"), data, 0644)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	defer close(stop)
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
			return
		}
		conn.Write([]byte("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n"))
		<-stop
	}()

	result := make(chan string, 1)
	go func() {
		code, body := copyTPC(t, active, "/f", "Destination", "http://"+ln.Addr().String()+"/f",
			"Repr-Digest", "adler=:"+b64(adler(string(data)))+":")
		result <- fmt.Sprintf("%d %s", code, finalLine(body))
	}()
	select {
	case got := <-result:
		if !strings.Contains(got, "failure: ") || !strings.Contains(got, "after") {
			t.Fatalf("got %q", got)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("push still waiting for the destination")
	}
}
