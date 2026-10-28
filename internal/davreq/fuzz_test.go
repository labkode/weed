package davreq

import (
	"net/http/httptest"
	"testing"
)

// FuzzParseTarget checks that whatever the Destination and Source headers hold, a
// local target is a canonical path inside the namespace
func FuzzParseTarget(f *testing.F) {
	for _, s := range [][3]string{
		{"COPY", "/webdav/b", ""}, {"MOVE", "http://example.com/webdav/../etc", ""}, {"COPY", "/webdav/a/%2e%2e/%2e%2e/x", ""},
		{"COPY", "", "https://remote/f"}, {"COPY", "https://remote/f", ""}, {"MOVE", "//example.com/webdav/x", ""},
		{"COPY", "/webdav", ""}, {"COPY", "dav://example.com/webdav/x", ""}, {"COPY", "http://EXAMPLE.com:80/webdav/x", ""},
	} {
		f.Add(s[0], s[1], s[2])
	}
	f.Fuzz(func(t *testing.T, method, dst, src string) {
		if method != "COPY" && method != "MOVE" {
			return
		}
		r := httptest.NewRequest(method, "http://example.com/webdav/a", nil)
		if dst != "" {
			r.Header.Set("Destination", dst)
		}
		if src != "" {
			r.Header.Set("Source", src)
		}
		target, err := ParseTarget(r)
		if err != nil {
			return
		}
		switch target.Kind {
		case CopyLocal:
			if !IsClean(target.Local) || !InNamespace(target.Local) {
				t.Fatalf("Destination %q gave local target %q", dst, target.Local)
			}
		case CopyPull, CopyPush:
			if target.Remote == nil || target.Remote.Host == "" || (target.Remote.Scheme != "http" && target.Remote.Scheme != "https") {
				t.Fatalf("dst=%q src=%q gave remote %v", dst, src, target.Remote)
			}
			if target.Kind == CopyPush && method == "MOVE" {
				t.Fatalf("MOVE to remote %v accepted", target.Remote)
			}
		}
	})
}
