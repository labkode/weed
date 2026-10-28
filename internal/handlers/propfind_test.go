package handlers

import (
	"encoding/xml"
	"reflect"
	"testing"
)

// The body davix 0.8 and gfal2 2.23 send to list a directory
const davixPropfind = `<?xml version="1.0" encoding="utf-8" ?><D:propfind xmlns:D="DAV:" xmlns:L="LCGDM:"><D:prop><D:displayname/><D:getlastmodified/><D:creationdate/><D:getcontentlength/><D:quota-used-bytes/><D:resourcetype><D:collection/></D:resourcetype><L:mode/><D:owner></D:owner><D:group></D:group></D:prop></D:propfind>`

func TestPropsWithContent(t *testing.T) {
	names, rewrite := propsWithContent([]byte(davixPropfind))
	dav := func(l string) xml.Name { return xml.Name{Space: "DAV:", Local: l} }
	want := []xml.Name{dav("displayname"), dav("getlastmodified"), dav("creationdate"), dav("getcontentlength"),
		dav("quota-used-bytes"), dav("resourcetype"), {Space: "LCGDM:", Local: "mode"}, dav("owner"), dav("group")}
	if !rewrite || !reflect.DeepEqual(names, want) {
		t.Fatalf("got %v %v", rewrite, names)
	}
	again, rewrite := propsWithContent(canonicalPropfind(append(names, xml.Name{Local: "nons"})))
	if rewrite || len(again) != len(names)+1 || again[len(again)-1] != (xml.Name{Local: "nons"}) {
		t.Fatalf("canonical form: %v %v", rewrite, again)
	}

	for _, body := range []string{
		`<D:propfind xmlns:D="DAV:"><D:prop><D:displayname/>  <D:resourcetype> </D:resourcetype></D:prop></D:propfind>`,
		`<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>`,
		`<D:propfind xmlns:D="DAV:"><D:propname/></D:propfind>`,
		`<x:other xmlns:x="X:"><D:prop xmlns:D="DAV:"><D:a><b/></D:a></D:prop></x:other>`,
		`<D:propfind xmlns:D="DAV:"><D:prop><D:a><b></D:prop>`,
	} {
		if _, rewrite := propsWithContent([]byte(body)); rewrite {
			t.Errorf("rewrote %s", body)
		}
	}
}
