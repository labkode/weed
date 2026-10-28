package handlers

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseISODuration(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"PT60M":    time.Hour,
		"PT1H30M":  90 * time.Minute,
		"PT2H":     2 * time.Hour,
		"PT45S":    45 * time.Second,
		"PT1.5S":   1500 * time.Millisecond,
		"P1D":      24 * time.Hour,
		"P1DT12H":  36 * time.Hour,
		"PT1H1M1S": time.Hour + time.Minute + time.Second,
	} {
		got, err := parseISODuration(in)
		if err != nil || got != want {
			t.Errorf("parseISODuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "P", "PT", "60M", "PT-5M", "P1Y", "P1W", "PT0S", "PTxyz", "P1DT"} {
		if d, err := parseISODuration(in); err == nil {
			t.Errorf("parseISODuration(%q) = %v, want error", in, d)
		}
	}
}

func TestParseIfHeader(t *testing.T) {
	lists, ok := parseIfHeader(`(<urn:uuid:1> ["etag"]) (Not <DAV:no-lock>)`)
	if !ok || len(lists) != 2 {
		t.Fatalf("untagged: %v %v", lists, ok)
	}
	if c := lists[0].conditions; len(c) != 2 || c[0].Token != "urn:uuid:1" || c[1].ETag != `"etag"` {
		t.Fatalf("first list: %+v", c)
	}
	if c := lists[1].conditions; len(c) != 1 || !c[0].Not || c[0].Token != "DAV:no-lock" {
		t.Fatalf("second list: %+v", c)
	}

	lists, ok = parseIfHeader(`<http://h/webdav/a> (<t1>) (<t2>) </webdav/b> (<t3>)`)
	if !ok || len(lists) != 3 || lists[0].tag != "http://h/webdav/a" || lists[1].tag != "http://h/webdav/a" || lists[2].tag != "/webdav/b" {
		t.Fatalf("tagged: %+v %v", lists, ok)
	}

	for _, bad := range []string{``, `<t>`, `(<t>) <r> (<t>)`, `()`, `(<t>`, `(Not)`, `(Not Not <t>)`, `(junk)`, `<r> junk`} {
		if _, ok := parseIfHeader(bad); ok {
			t.Errorf("parseIfHeader(%q) succeeded", bad)
		}
	}
}

func TestPutPreconditions(t *testing.T) {
	const etag = `"abc"`
	cases := []struct {
		header, value string
		exists        bool
		want          bool
	}{
		{"If-None-Match", "*", true, false},
		{"If-None-Match", "*", false, true},
		{"If-None-Match", `"abc"`, true, false},
		{"If-None-Match", `"other"`, true, true},
		{"If-Match", "*", false, false},
		{"If-Match", "*", true, true},
		{"If-Match", `"other", "abc"`, true, true},
		{"If-Match", `"other"`, true, false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("PUT", "/webdav/f", nil)
		r.Header.Set(c.header, c.value)
		if got := putPreconditionsHold(r, c.exists, etag); got != c.want {
			t.Errorf("%s: %s (exists=%v) = %v, want %v", c.header, c.value, c.exists, got, c.want)
		}
	}
}
