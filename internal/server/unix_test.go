package server

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/testutil"
)

// Operations the filesystem refuses get 403, not the 404, 405 or 500 that
// x/net/webdav would answer
func TestPermissionDeniedIs403(t *testing.T) {
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("needs a user that file permissions apply to")
	}
	n := newNode(t, nil)
	n.write("/locked/f", "data")
	n.write("/ro", "read-only data")
	os.Chmod(filepath.Join(n.dir, "ro"), 0444)
	locked := filepath.Join(n.dir, "locked")
	os.Chmod(locked, 0)
	t.Cleanup(func() { os.Chmod(locked, 0755) })

	for _, c := range []struct {
		method, path, body string
		headers            []string
		want               int
	}{
		{"GET", "/locked/f", "", nil, 403},
		{"HEAD", "/locked/f", "", nil, 403},
		{"PROPFIND", "/locked/f", "", []string{"Depth", "0"}, 403},
		{"MKCOL", "/locked/d", "", nil, 403},
		{"DELETE", "/locked/f", "", nil, 403},
		{"PUT", "/locked/g", "data", nil, 403},
		{"MOVE", "/locked/f", "", []string{"Destination", "/webdav/moved"}, 403},
		{"COPY", "/ro", "", []string{"Destination", "/webdav/locked/c"}, 403},
		// Replacing a file needs write permission on it, not only on its directory
		{"PUT", "/ro", "new data", nil, 403},
		// Unrelated failures keep their status
		{"GET", "/missing", "", nil, 404},
		{"MKCOL", "/missing/d", "", nil, 409},
	} {
		if resp, body := n.do(c.method, c.path, c.body, c.headers...); resp.StatusCode != c.want {
			t.Errorf("%s %s: %d %q, want %d", c.method, c.path, resp.StatusCode, body, c.want)
		}
	}
	if content, _ := n.read("/ro"); content != "read-only data" {
		t.Errorf("read-only file replaced: %q", content)
	}

	// Third-party copies
	if code, body := copyTPC(t, n, "/locked/g", "Source", n.url("/ro")); code != 403 {
		t.Errorf("pull into an inaccessible directory: %d %q", code, body)
	}
	if code, body := copyTPC(t, n, "/locked/f", "Destination", n.url("/pushed")); code != 403 {
		t.Errorf("push from an inaccessible directory: %d %q", code, body)
	}
}

func TestTokenUserRules(t *testing.T) {
	iss := testutil.NewIssuer(t)
	issuers := iss.WriteIssuers(tokenAudience, "/", map[string]interface{}{"users": []map[string]string{
		{"sub": "robot", "user": "prod"},
		{"group": "/cms/production", "user": "prod"},
	}})
	n := newNode(t, func(cfg *config.Config, _ string) {
		cfg.TokenIssuers = issuers
		cfg.TokenCAPath = iss.CAFile
	})
	whoami := func(claims map[string]interface{}) (int, string) {
		resp, body := n.do("GET", n.ts.URL+"/proc/whoami", "", bearer(iss.Token(tokenAudience, "storage.read:/", claims))...)
		return resp.StatusCode, body
	}
	if code, body := whoami(map[string]interface{}{"sub": "robot"}); code != 200 || !strings.Contains(body, "Username: prod\n") {
		t.Errorf("by subject: %d %q", code, body)
	}
	if code, body := whoami(map[string]interface{}{"wlcg.groups": []string{"/cms", "/cms/production"}}); code != 200 || !strings.Contains(body, "Username: prod\n") {
		t.Errorf("by group: %d %q", code, body)
	}
	if code, _ := whoami(map[string]interface{}{"wlcg.groups": []string{"/cms"}}); code != 403 {
		t.Errorf("no matching rule: %d", code)
	}
	n.write("/f", "data")
	if code := n.status("GET", "/f", "", bearer(iss.Token(tokenAudience, "storage.read:/", nil))...); code != 403 {
		t.Errorf("GET with no matching rule: %d", code)
	}
}
