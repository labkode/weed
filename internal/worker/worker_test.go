package worker

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labkode/weed/internal/auth"
	"github.com/labkode/weed/internal/fsuser"
	"github.com/labkode/weed/internal/logger"
)

const confined = `Name:	weed
Umask:	0022
State:	S (sleeping)
Uid:	6001	6001	6001	6001
Gid:	6100	6100	6100	6100
FDSize:	64
Groups:	6100 6001
NStgid:	83
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000
NoNewPrivs:	1
Seccomp:	0
`

func TestCheckStatus(t *testing.T) {
	alice := &fsuser.User{Name: "alice", UID: 6001, GID: 6100, Groups: []int{6001, 6100}}
	if err := checkStatus(confined, alice); err != nil {
		t.Fatalf("confined thread refused: %v", err)
	}
	for _, c := range []struct{ name, from, to, err string }{
		{"saved uid", "Uid:	6001	6001	6001	6001", "Uid:	6001	6001	0	6001", "uid IDs are 6001 6001 0 6001"},
		{"filesystem gid", "Gid:	6100	6100	6100	6100", "Gid:	6100	6100	6100	0", "gid IDs"},
		{"extra group", "Groups:	6100 6001", "Groups:	0 6100 6001", "groups are"},
		{"missing group", "Groups:	6100 6001", "Groups:	6100", "groups are"},
		{"effective capability", "CapEff:	0000000000000000", "CapEff:	0000000000000002", "CapEff"},
		{"permitted capability", "CapPrm:	0000000000000000", "CapPrm:	0000000000000080", "CapPrm"},
		{"inheritable capability", "CapInh:	0000000000000000", "CapInh:	0000000000000040", "CapInh"},
		{"ambient capability", "CapAmb:	0000000000000000", "CapAmb:	0000000000000400", "CapAmb"},
		{"no_new_privs", "NoNewPrivs:	1", "NoNewPrivs:	0", "no_new_privs"},
		{"unreadable", "Uid:	6001	6001	6001	6001", "", "cannot read"},
	} {
		status := strings.Replace(confined, c.from, c.to, 1)
		if err := checkStatus(status, alice); err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("%s: %v, want %q", c.name, err, c.err)
		}
	}
	// Kernels before 4.3 have no ambient capabilities
	if err := checkStatus(strings.Replace(confined, "CapAmb:	0000000000000000\n", "", 1), alice); err != nil {
		t.Errorf("without CapAmb: %v", err)
	}
}

// The facts the front process states reach the worker's handler, and clients cannot
// state them
func TestHeaders(t *testing.T) {
	alice := &fsuser.User{Name: "alice", UID: 6001, GID: 6001, Groups: []int{6001}}
	var got *http.Request
	h := Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r }), alice)

	in := httptest.NewRequest("PUT", "https://weed.example/webdav/f", nil)
	in.RemoteAddr = "192.0.2.1:4242"
	in.Header.Set("X-Weed-Identity", `{"username":"root","method":"basic"}`)
	in.Header.Set("x-weed-tls", "")
	in.Header.Set("Authorization", "Bearer secret")
	ctx := logger.WithRequestID(in.Context(), "abcd1234")
	in = in.WithContext(auth.SetAuthInfoInContext(ctx, &auth.AuthInfo{Username: "alice", Method: "token", NoOverwrite: true}))

	out := httptest.NewRequest("PUT", "http://worker/webdav/f", nil)
	out.Header = in.Header.Clone()
	describe(out.Header, in)
	h.ServeHTTP(httptest.NewRecorder(), out)

	if got == nil {
		t.Fatal("not served")
	}
	info, ok := auth.GetAuthInfoFromContext(got.Context())
	if !ok || info.Username != "alice" || info.Method != "token" || !info.NoOverwrite || info.Unix != alice {
		t.Errorf("identity %+v", info)
	}
	if id := logger.GetRequestID(got.Context()); id != "abcd1234" {
		t.Errorf("request ID %q", id)
	}
	if got.RemoteAddr != "192.0.2.1:4242" || got.TLS == nil {
		t.Errorf("remote address %q, TLS %v", got.RemoteAddr, got.TLS != nil)
	}
	for k := range got.Header {
		if strings.HasPrefix(k, "X-Weed-") {
			t.Errorf("header %s reaches the handler", k)
		}
	}
	if got.Header.Get("Authorization") != "Bearer secret" {
		t.Error("other headers are not forwarded")
	}

	// A request received without TLS cannot claim it
	plain := httptest.NewRequest("GET", "http://weed.example/webdav/f", nil)
	plain.Header.Set("X-Weed-Tls", "1")
	plain = plain.WithContext(auth.SetAuthInfoInContext(logger.WithRequestID(plain.Context(), ""), &auth.AuthInfo{Username: "alice"}))
	out = httptest.NewRequest("GET", "http://worker/webdav/f", nil)
	out.Header = plain.Header.Clone()
	describe(out.Header, plain)
	h.ServeHTTP(httptest.NewRecorder(), out)
	if got.TLS != nil {
		t.Error("TLS stated by the client")
	}

	// Without the front process's statement there is no identity
	w := httptest.NewRecorder()
	got = nil
	h.ServeHTTP(w, httptest.NewRequest("GET", "http://worker/webdav/f", nil))
	if got != nil || w.Code != http.StatusInternalServerError {
		t.Errorf("request without an identity: %d", w.Code)
	}
}
