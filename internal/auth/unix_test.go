package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/labkode/weed/internal/fsuser"
	"golang.org/x/crypto/bcrypt"
)

func TestUnixUsers(t *testing.T) {
	as := macaroonStore(t)
	as.BasicEnabled = true
	as.PrepareBasicAuth()
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	as.SetCredentials(&Credentials{Htpasswd: map[string]string{"alice": string(hash), "ghost": string(hash)}})
	as.UnixUsers = true
	lookups := 0
	as.LookupUnixUser = func(name string) (*fsuser.User, error) {
		lookups++
		if name == "alice" {
			return &fsuser.User{Name: "alice", UID: 1001, GID: 1001, Groups: []int{1001}}, nil
		}
		return nil, errors.New("unknown user")
	}

	h := as.UnifiedAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, _ := GetAuthInfoFromContext(r.Context())
		w.Write([]byte(info.Unix.Name))
	}))
	serve := func(user string, headers ...string) *httptest.ResponseRecorder {
		r := request("GET", "/webdav/a", headers...)
		if user != "" {
			r.SetBasicAuth(user, "pw")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	if w := serve("alice"); w.Code != 200 || w.Body.String() != "alice" {
		t.Fatalf("alice: %d %s", w.Code, w.Body)
	}
	// Valid credentials without an account
	if w := serve("ghost"); w.Code != 403 {
		t.Fatalf("user without an account: %d", w.Code)
	}
	if w := serve("", "Authorization", "Bearer "+mint(t, as, "id:ghost")); w.Code != 403 {
		t.Fatalf("macaroon for a user without an account: %d", w.Code)
	}
	if w := serve("", "Authorization", "Bearer "+mint(t, as, "id:alice")); w.Code != 200 || w.Body.String() != "alice" {
		t.Fatalf("macaroon for alice: %d %s", w.Code, w.Body)
	}

	// Accounts are cached, and looked up again once forgotten
	if lookups != 2 {
		t.Errorf("%d lookups for 2 names", lookups)
	}
	as.ForgetUnixUsers()
	serve("alice")
	if lookups != 3 {
		t.Errorf("%d lookups after ForgetUnixUsers", lookups)
	}
}

func TestTokenIssuerUserRules(t *testing.T) {
	write := func(content string) string {
		p := filepath.Join(t.TempDir(), "issuers.json")
		os.WriteFile(p, []byte(content), 0600)
		return p
	}
	for _, c := range []struct{ name, content, err string }{
		{"rule without user", `[{"issuer": "https://iam.example", "users": [{"sub": "x"}]}]`, "names no user"},
		{"misspelled field", `[{"issuer": "https://iam.example", "users": [{"sub": "x", "usr": "y"}]}]`, "unknown field"},
	} {
		if _, err := LoadTokenIssuers(write(c.content)); err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("%s: %v", c.name, err)
		}
	}

	issuers, err := LoadTokenIssuers(write(`[{"issuer": "https://iam.example", "users": [
		{"sub": "robot", "user": "prod"},
		{"group": "cms/production", "user": "prod"},
		{"sub": "jdoe-id", "group": "/cms", "user": "jdoe"},
		{"group": "/atlas", "user": "atlas001"}]}]`))
	if err != nil {
		t.Fatal(err)
	}
	iss := issuers["https://iam.example"]
	for _, c := range []struct {
		sub    string
		groups []string
		want   string
	}{
		{"robot", nil, "prod"},
		{"someone", []string{"/cms", "/cms/production"}, "prod"},
		{"someone", []string{"cms/production"}, "prod"},
		{"jdoe-id", []string{"/cms"}, "jdoe"},
		{"jdoe-id", nil, ""},
		{"someone", []string{"/atlas"}, "atlas001"},
		{"someone", []string{"/atlas/production"}, ""}, // groups match exactly
		{"someone", nil, ""},
	} {
		got, err := iss.username(c.sub, c.groups)
		if got != c.want || (c.want == "") != errors.Is(err, errForbidden) {
			t.Errorf("sub %q, groups %q: %q, %v; want %q", c.sub, c.groups, got, err, c.want)
		}
	}
}
