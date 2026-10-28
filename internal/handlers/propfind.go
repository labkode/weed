package handlers

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const maxPropfindBody = 1 << 20

// lenientPropfind makes PROPFIND request bodies acceptable to x/net/webdav, which
// requires every requested property to be an empty element. davix and gfal2 send
// properties with content, such as <D:resourcetype><D:collection/></D:resourcetype>,
// which other servers ignore; such bodies are rewritten to request the same
// properties without content. Anything else is passed through unchanged.
func lenientPropfind(r *http.Request) error {
	if r.Body == nil || r.ContentLength == 0 {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxPropfindBody+1))
	if err != nil {
		return err
	}
	if len(body) > maxPropfindBody {
		return errors.New("PROPFIND body too large")
	}
	if names, ok := propsWithContent(body); ok {
		body = canonicalPropfind(names)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	return nil
}

// propsWithContent returns the properties requested by a <D:propfind><D:prop> body,
// and whether any of them has content (and so would be rejected by x/net/webdav)
func propsWithContent(body []byte) ([]xml.Name, bool) {
	d := xml.NewDecoder(bytes.NewReader(body))
	var names []xml.Name
	depth, inProp, withContent := 0, false, false
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return names, withContent && len(names) > 0
		}
		if err != nil {
			return nil, false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			switch {
			case depth == 1 && t.Name != xml.Name{Space: "DAV:", Local: "propfind"}:
				return nil, false
			case depth == 2:
				inProp = t.Name == xml.Name{Space: "DAV:", Local: "prop"}
			case depth == 3 && inProp:
				names = append(names, t.Name)
				empty, err := skipElement(d)
				if err != nil {
					return nil, false
				}
				withContent = withContent || !empty
				depth--
			}
		case xml.EndElement:
			depth--
		}
	}
}

// skipElement consumes the rest of the current element and reports whether it
// was empty (no child elements and no text other than whitespace)
func skipElement(d *xml.Decoder) (bool, error) {
	empty := true
	for depth := 1; depth > 0; {
		tok, err := d.Token()
		if err != nil {
			return false, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			empty = false
		case xml.EndElement:
			depth--
		case xml.CharData:
			if len(bytes.TrimSpace(t)) > 0 {
				empty = false
			}
		}
	}
	return empty, nil
}

func canonicalPropfind(names []xml.Name) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?><D:propfind xmlns:D="DAV:"><D:prop>`)
	for i, n := range names {
		if n.Space == "" {
			fmt.Fprintf(&b, `<%s xmlns=""/>`, n.Local)
			continue
		}
		var ns bytes.Buffer
		xml.EscapeText(&ns, []byte(n.Space))
		fmt.Fprintf(&b, `<p%d:%s xmlns:p%d="%s"/>`, i, n.Local, i, ns.String())
	}
	b.WriteString(`</D:prop></D:propfind>`)
	return []byte(b.String())
}
