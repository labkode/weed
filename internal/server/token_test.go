package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/testutil"
)

const tokenAudience = "https://weed.test"

// newTokenNode starts a node that accepts tokens from iss, with scope paths relative
// to basePath
func newTokenNode(t *testing.T, iss *testutil.Issuer, basePath string) *node {
	issuers := iss.WriteIssuers(tokenAudience, basePath)
	return newNode(t, func(cfg *config.Config, _ string) {
		cfg.TokenIssuers = issuers
		cfg.TokenCAPath = iss.CAFile
	})
}

func bearer(token string) []string { return []string{"Authorization", "Bearer " + token} }

func TestTokenAccess(t *testing.T) {
	iss := testutil.NewIssuer(t)
	n := newTokenNode(t, iss, "/")
	n.write("/data/f", "original")
	read := bearer(iss.Token(tokenAudience, "storage.read:/data", nil))
	create := bearer(iss.Token(tokenAudience, "storage.create:/data", nil))
	modify := bearer(iss.Token(tokenAudience, "storage.modify:/data", nil))

	for _, c := range []struct {
		name         string
		method, path string
		headers      []string
		want         int
	}{
		{"read", "GET", "/data/f", read, 200},
		{"list", "PROPFIND", "/data", append([]string{"Depth", "1"}, read...), 207},
		{"read outside the scope", "GET", "/f", read, 403},
		{"write with a read token", "PUT", "/data/new", read, 403},
		{"create", "PUT", "/data/new", create, 201},
		{"create: overwrite", "PUT", "/data/f", create, 403},
		{"create: stat", "HEAD", "/data/f", create, 200},
		{"create: stat a missing file", "HEAD", "/data/missing", create, 404},
		{"create: list", "PROPFIND", "/data", append([]string{"Depth", "1"}, create...), 403},
		{"create: read", "GET", "/data/f", create, 403},
		{"create: mkdir", "MKCOL", "/data/dir", create, 201},
		{"create: delete", "DELETE", "/data/new", create, 403},
		{"create: copy onto a file", "COPY", "/data/new", append([]string{"Destination", "/webdav/data/f", "Overwrite", "T"},
			bearer(iss.Token(tokenAudience, "storage.read:/data storage.create:/data", nil))...), 403},
		{"create: move onto a file", "MOVE", "/data/new", append([]string{"Destination", "/webdav/data/f"}, create...), 403},
		{"create: move to a new name", "MOVE", "/data/new", append([]string{"Destination", "/webdav/data/renamed"}, create...), 201},
		{"modify: overwrite", "PUT", "/data/renamed", modify, 204},
		{"modify: delete", "DELETE", "/data/renamed", modify, 204},
		{"modify: overwrite", "PUT", "/data/f", modify, 204},
		{"macaroon request", "POST", "/data/f", append([]string{"Content-Type", "application/macaroon-request"},
			bearer(iss.Token(tokenAudience, "storage.read:/ storage.modify:/", nil))...), 403},
		{"wrong audience", "GET", "/data/f", bearer(iss.Token("https://other.test", "storage.read:/", nil)), 401},
	} {
		body := ""
		if c.method == "PUT" {
			body = "new data"
		}
		if resp, msg := n.do(c.method, c.path, body, c.headers...); resp.StatusCode != c.want {
			t.Errorf("%s: %s %s = %d %q, want %d", c.name, c.method, c.path, resp.StatusCode, msg, c.want)
		}
	}
	if content, _ := n.read("/data/f"); content != "new data" {
		t.Errorf("/data/f = %q", content)
	}

	// Outside the namespace a token proves identity
	resp, body := n.do("GET", n.ts.URL+"/proc/whoami", "", read...)
	if resp.StatusCode != 200 || !strings.Contains(body, "token-user") {
		t.Errorf("whoami: %d %q", resp.StatusCode, body)
	}
}

func TestTokenBasePath(t *testing.T) {
	iss := testutil.NewIssuer(t)
	n := newTokenNode(t, iss, "/vo")
	n.write("/vo/f", "vo data")
	n.write("/f", "other data")
	tok := bearer(iss.Token(tokenAudience, "storage.read:/", nil))
	if resp, body := n.do("GET", "/vo/f", "", tok...); resp.StatusCode != 200 || body != "vo data" {
		t.Errorf("inside the base path: %d %q", resp.StatusCode, body)
	}
	if code := n.status("GET", "/f", "", tok...); code != 403 {
		t.Errorf("outside the base path: %d", code)
	}
	escape := bearer(iss.Token(tokenAudience, "storage.read:/../f", nil))
	if code := n.status("GET", "/f", "", escape...); code != 403 {
		t.Errorf("scope with ..: %d", code)
	}
}

func TestTokenTPC(t *testing.T) {
	iss := testutil.NewIssuer(t)
	active, passive := newTokenNode(t, iss, "/"), newTokenNode(t, iss, "/")
	passive.write("/src/f", "event data")
	active.write("/out/f", "local data")
	os.Mkdir(filepath.Join(active.dir, "in"), 0755)
	os.Mkdir(filepath.Join(passive.dir, "dst"), 0755)
	readSrc := "Bearer " + iss.Token(tokenAudience, "storage.read:/src", nil)
	create := bearer(iss.Token(tokenAudience, "storage.create:/in storage.read:/out", nil))

	// Pull: the token for the source is passed on with TransferHeaderAuthorization
	code, body := copyTPC(t, active, "/in/f", append([]string{"Source", passive.url("/src/f"),
		"TransferHeaderAuthorization", readSrc, "Credential", "none"}, create...)...)
	expectSuccess(t, code, body)
	if content, _ := active.read("/in/f"); content != "event data" {
		t.Fatalf("pulled %q", content)
	}
	// storage.create does not allow replacing the file
	if code, body := copyTPC(t, active, "/in/f", append([]string{"Source", passive.url("/src/f"),
		"TransferHeaderAuthorization", readSrc}, create...)...); code != 403 {
		t.Fatalf("pull onto an existing file: %d %q", code, body)
	}

	// Push: the destination checks the passed-on token, and refuses to overwrite
	createDst := "Bearer " + iss.Token(tokenAudience, "storage.create:/dst", nil)
	code, body = copyTPC(t, active, "/out/f", append([]string{"Destination", passive.url("/dst/f"),
		"TransferHeaderAuthorization", createDst}, create...)...)
	expectSuccess(t, code, body)
	if content, _ := passive.read("/dst/f"); content != "local data" {
		t.Fatalf("pushed %q", content)
	}
	code, body = copyTPC(t, active, "/out/f", append([]string{"Destination", passive.url("/dst/f"),
		"TransferHeaderAuthorization", createDst}, create...)...)
	expectFailure(t, code, body, "403")
}

// A file that appears while a create-only pull is running is not replaced
func TestTokenPullDoesNotReplaceFileCreatedMeanwhile(t *testing.T) {
	iss := testutil.NewIssuer(t)
	n := newTokenNode(t, iss, "/")
	release := make(chan struct{})
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "8")
		w.Write([]byte("rem"))
		w.(http.Flusher).Flush()
		<-release
		w.Write([]byte("ote!!"))
	}))
	defer src.Close()

	go func() {
		// Wait until the transfer is running, then create the destination
		for {
			entries, _ := os.ReadDir(n.dir)
			if len(entries) > 0 {
				break
			}
			time.Sleep(time.Millisecond)
		}
		os.WriteFile(filepath.Join(n.dir, "f"), []byte("written meanwhile"), 0644)
		close(release)
	}()
	code, body := copyTPC(t, n, "/f", append([]string{"Source", src.URL + "/f"},
		bearer(iss.Token(tokenAudience, "storage.create:/", nil))...)...)
	expectFailure(t, code, body, "created during the transfer")
	if content, _ := n.read("/f"); content != "written meanwhile" {
		t.Fatalf("file replaced: %q", content)
	}
	if entries, _ := os.ReadDir(n.dir); len(entries) != 1 {
		t.Fatalf("leftover files: %v", entries)
	}
}

// readFlag records whether a request body was read
type readFlag struct {
	read bool
	r    io.Reader
}

func (f *readFlag) Read(p []byte) (int, error) { f.read = true; return f.r.Read(p) }

func TestTokenPutOverwriteRefusedBeforeUpload(t *testing.T) {
	iss := testutil.NewIssuer(t)
	n := newTokenNode(t, iss, "/")
	n.write("/f", "original")

	tr := n.ts.Client().Transport.(*http.Transport).Clone()
	tr.ExpectContinueTimeout = 10 * time.Second
	body := &readFlag{r: strings.NewReader("new data")}
	req, _ := http.NewRequest("PUT", n.url("/f"), body)
	req.ContentLength = 8
	req.Header.Set("Expect", "100-continue")
	req.Header.Set("Authorization", "Bearer "+iss.Token(tokenAudience, "storage.create:/", nil))
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 || body.read {
		t.Fatalf("%d, body sent: %t", resp.StatusCode, body.read)
	}
}

// A file that appears while a create-only PUT is being received is not replaced
func TestTokenPutDoesNotReplaceFileCreatedMeanwhile(t *testing.T) {
	iss := testutil.NewIssuer(t)
	n := newTokenNode(t, iss, "/")
	pr, pw := io.Pipe()
	req, _ := http.NewRequest("PUT", n.url("/f"), pr)
	req.Header.Set("Authorization", "Bearer "+iss.Token(tokenAudience, "storage.create:/", nil))
	go func() {
		pw.Write([]byte("new "))
		// The temporary file exists once the server has checked that f does not
		for {
			if entries, _ := os.ReadDir(n.dir); len(entries) > 0 {
				break
			}
			time.Sleep(time.Millisecond)
		}
		os.WriteFile(filepath.Join(n.dir, "f"), []byte("written meanwhile"), 0644)
		pw.Write([]byte("data"))
		pw.Close()
	}()
	resp, err := n.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("PUT: %d", resp.StatusCode)
	}
	if content, _ := n.read("/f"); content != "written meanwhile" {
		t.Fatalf("file replaced: %q", content)
	}
}
