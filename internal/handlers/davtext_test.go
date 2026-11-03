package handlers

import (
	"encoding/xml"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labkode/weed/internal/config"
)

func TestHref(t *testing.T) {
	want := func(p string) string {
		var b strings.Builder
		xml.EscapeText(&b, []byte((&url.URL{Path: p}).EscapedPath()))
		return b.String()
	}
	check := func(p string) {
		t.Helper()
		if got, w := string(appendHref(nil, p)), want(p); got != w {
			t.Fatalf("appendHref(%q) = %q, want %q", p, got, w)
		}
		if got, w := string(appendHrefBytes([]byte("x"), []byte(p))), "x"+want(p); got != w {
			t.Fatalf("appendHrefBytes(%q) = %q, want %q", p, got, w)
		}
	}
	for c := range 256 {
		check("/webdav/a" + string([]byte{byte(c)}) + "b")
	}
	for _, p := range []string{"/", "/webdav", "/webdav/", "/*", "/webdav/*", "/a b/é ü.pdf", "/a&b?c#d%e", "/\xff\xfe", "/new\nline", `/q"'<>.json`} {
		check(p)
	}
	r := rand.New(rand.NewPCG(1, 2))
	for range 10000 {
		b := make([]byte, r.IntN(20))
		for i := range b {
			b[i] = byte(r.IntN(256))
		}
		check("/" + string(b))
	}
}

func TestHTTPDate(t *testing.T) {
	check := func(sec int64) {
		t.Helper()
		want := time.Unix(sec, 0).UTC().Format(http.TimeFormat)
		if got := string(appendHTTPDate([]byte("x"), sec)); got != "x"+want {
			t.Fatalf("appendHTTPDate(%d) = %q, want %q", sec, got, want)
		}
	}
	day := int64(86400)
	for _, d := range []string{"1970-01-01", "1970-03-01", "1972-02-29", "1999-12-31", "2000-02-28", "2000-02-29",
		"2000-03-01", "2024-02-29", "2100-02-28", "2100-03-01", "2400-02-29", "9999-12-31"} {
		tm, err := time.Parse(time.DateOnly, d)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range []int64{0, 1, 59, 3599, 3600, day - 1} {
			check(tm.Unix() + s)
		}
	}
	for _, sec := range []int64{-1, -day, maxHTTPDate - 1, maxHTTPDate, maxHTTPDate + day, 1 << 40, -1 << 40} {
		check(sec)
	}
	for sec := int64(0); sec < maxHTTPDate; sec += 3*day + 4321 {
		check(sec)
	}
	r := rand.New(rand.NewPCG(3, 4))
	for range 100000 {
		check(r.Int64N(maxHTTPDate))
	}
}

func TestETag(t *testing.T) {
	for _, tm := range []time.Time{time.Unix(0, 0), time.Unix(1700000000, 123456789), time.Unix(-5, 7), time.Unix(1<<40, 1)} {
		for _, size := range []int64{0, 1, 4095, 1 << 40} {
			want := fmt.Sprintf(`"%x%x"`, tm.UnixNano(), size)
			if got := string(appendETag(nil, tm.Unix(), int64(tm.Nanosecond()), size)); got != want {
				t.Errorf("appendETag(%v, %d) = %s, want %s", tm, size, got, want)
			}
		}
	}
}

func TestTypeOfName(t *testing.T) {
	for range 2 { // and again, from the cache
		for _, name := range []string{"a.html", "a.HTML", "a.pdf", "f", ".bashrc", "a.", "a.b.json", "a.tar.gz", "é.ü", "x." + strings.Repeat("e", 40)} {
			if got, want := typeOfName([]byte(name)), contentType(name); got != want {
				t.Errorf("typeOfName(%q) = %q, want %q", name, got, want)
			}
		}
	}
	for i := range 2 * maxTypes {
		typeOfName(fmt.Appendf(nil, "f.e%d", i))
	}
	if n := len(*types.Load()); n > maxTypes {
		t.Errorf("%d types cached", n)
	}
}

// discard is a ResponseWriter that keeps nothing
type discard struct{ h http.Header }

func (d *discard) Header() http.Header         { return d.h }
func (d *discard) Write(b []byte) (int, error) { return len(b), nil }
func (d *discard) WriteHeader(int)             {}

// Listing a directory allocates nothing for each entry: the allocations of PROPFIND
// do not grow with the directory
func TestPropfindAllocations(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector drops what sync.Pool keeps")
	}
	dir := t.TempDir()
	for _, n := range []int{10, 1000} {
		d := filepath.Join(dir, fmt.Sprint(n))
		os.Mkdir(d, 0o755)
		for i := range n {
			os.WriteFile(filepath.Join(d, fmt.Sprintf("file %d.txt", i)), []byte("x"), 0o644)
		}
		os.Mkdir(filepath.Join(d, "sub"), 0o755)
	}
	h := NewWebDAVHandler(dir, &config.Config{WorkerMaxStorageCalls: 8}, nil)
	allocs := func(n int, body string) float64 {
		w := &discard{h: http.Header{}}
		return testing.AllocsPerRun(50, func() {
			r := httptest.NewRequest("PROPFIND", fmt.Sprintf("/webdav/%d/", n), nil)
			if body != "" {
				r.Body = nopCloser{strings.NewReader(body)}
			}
			r.Header.Set("Depth", "1")
			clear(w.h)
			h.ServeHTTP(w, r)
		})
	}
	for _, body := range []string{"", `<D:propfind xmlns:D="DAV:"><D:prop><D:getetag/><D:getcontentlength/><D:getlastmodified/><D:resourcetype/></D:prop></D:propfind>`} {
		small, large := allocs(10, body), allocs(1000, body)
		t.Logf("allocations of a PROPFIND: %.0f for 10 entries, %.0f for 1000", small, large)
		if perEntry := (large - small) / 990; perEntry > 0.002 {
			t.Errorf("%.3f allocations per entry listed (%.0f for 10 entries, %.0f for 1000)", perEntry, small, large)
		}
	}
}

type nopCloser struct{ *strings.Reader }

func (nopCloser) Close() error { return nil }
