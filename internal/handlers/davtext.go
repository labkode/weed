package handlers

// The text of PROPFIND answers that is formatted for each entry of a listing (hrefs,
// dates, ETags, content types), appended to a buffer without allocating. Each is
// what the standard library writes (TestHref, TestHTTPDate, TestTypeOfName).

import (
	"bytes"
	"encoding/xml"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// hrefBytes is how each byte of a path is written in an href: escaped as
// url.URL.EscapedPath escapes a path, byte by byte, then as XML text ('&'). Taken
// from the standard library itself, which escapes as RFC 3986 says for a path.
var (
	hrefBytes [256]string
	hrefSafe  [256]bool // the bytes written as they are
)

func init() {
	for c := range 256 {
		// "/" first: EscapedPath leaves the path "*" alone
		esc := strings.TrimPrefix((&url.URL{Path: "/" + string([]byte{byte(c)})}).EscapedPath(), "/")
		if c == '/' {
			esc = "/"
		}
		var b strings.Builder
		xml.EscapeText(&b, []byte(esc))
		hrefBytes[c] = b.String()
		hrefSafe[c] = b.String() == string([]byte{byte(c)})
	}
}

// appendHref appends the path p, escaped as an href in XML text:
// xml.EscapeText of (&url.URL{Path: p}).EscapedPath()
func appendHref(b []byte, p string) []byte {
	for i := 0; i < len(p); i++ {
		if c := p[i]; hrefSafe[c] {
			b = append(b, c)
		} else {
			b = append(b, hrefBytes[c]...)
		}
	}
	return b
}

// appendHrefBytes is appendHref of p
func appendHrefBytes(b []byte, p []byte) []byte {
	for _, c := range p {
		if hrefSafe[c] {
			b = append(b, c)
		} else {
			b = append(b, hrefBytes[c]...)
		}
	}
	return b
}

// maxHTTPDate is 10000-01-01T00:00:00Z: appendHTTPDate formats the years 1970 to
// 9999 itself, time.Time.AppendFormat the others
const maxHTTPDate = 253402300800

const (
	weekdays = "SunMonTueWedThuFriSat"
	months   = "JanFebMarAprMayJunJulAugSepOctNovDec"
)

// appendHTTPDate appends the time sec (since the epoch) as an HTTP date, in UTC:
// time.Unix(sec, 0).UTC().AppendFormat(b, http.TimeFormat)
func appendHTTPDate(b []byte, sec int64) []byte {
	if sec < 0 || sec >= maxHTTPDate {
		return time.Unix(sec, 0).UTC().AppendFormat(b, http.TimeFormat)
	}
	days, rem := sec/86400, sec%86400
	wd := (days + 4) % 7 // 1970-01-01 was a Thursday

	// The civil date of a day (H. Hinnant, chrono-Compatible Low-Level Date
	// Algorithms), in eras of 400 years from 0000-03-01
	z := days + 719468
	era := z / 146097
	doe := z - era*146097                                  // [0, 146096]
	yoe := (doe - doe/1460 + doe/36524 - doe/146096) / 365 // [0, 399]
	doy := doe - (365*yoe + yoe/4 - yoe/100)               // [0, 365], from March 1st
	mp := (5*doy + 2) / 153                                // [0, 11], from March
	d := doy - (153*mp+2)/5 + 1                            // [1, 31]
	m := mp + 3
	if m > 12 {
		m -= 12
	}
	y := yoe + era*400
	if m <= 2 {
		y++
	}

	b = append(b, weekdays[wd*3:wd*3+3]...)
	b = append(b, ',', ' ')
	b = append2(b, d)
	b = append(b, ' ')
	b = append(b, months[(m-1)*3:(m-1)*3+3]...)
	b = append(b, ' ')
	b = append2(b, y/100)
	b = append2(b, y%100)
	b = append(b, ' ')
	b = append2(b, rem/3600)
	b = append(b, ':')
	b = append2(b, rem/60%60)
	b = append(b, ':')
	b = append2(b, rem%60)
	return append(b, " GMT"...)
}

// append2 appends n, in [0, 99], as two digits
func append2(b []byte, n int64) []byte {
	return append(b, byte('0'+n/10), byte('0'+n%10))
}

// appendETag appends the ETag of a file modified at sec, nsec, of the given size,
// quoted: its modification time in nanoseconds, then its size, in hexadecimal (that
// of fmt.Sprintf(`"%x%x"`, fi.ModTime().UnixNano(), fi.Size()))
func appendETag(b []byte, sec, nsec, size int64) []byte {
	b = append(b, '"')
	b = strconv.AppendInt(b, sec*1e9+nsec, 16)
	b = strconv.AppendInt(b, size, 16)
	return append(b, '"')
}

// types caches the content types of extensions (typeOfName), which
// mime.TypeByExtension cannot find without allocating. It is replaced, never changed.
var types atomic.Pointer[map[string]string]

// Bounds of types: a directory of files of random extensions must not grow it
const (
	maxTypes   = 1024
	maxTypeExt = 32
)

// typeOfName is contentType of name, a file name (no slash)
func typeOfName(name []byte) string {
	var ext []byte
	if i := bytes.LastIndexByte(name, '.'); i >= 0 {
		ext = name[i:]
	}
	cached := types.Load()
	if cached != nil {
		if t, ok := (*cached)[string(ext)]; ok {
			return t
		}
	}
	t := contentType(string(ext))
	if len(ext) <= maxTypeExt && (cached == nil || len(*cached) < maxTypes) {
		// Two at once may each add theirs and lose the other's: it is found again
		m := make(map[string]string, 1+len(ptrMap(cached)))
		for k, v := range ptrMap(cached) {
			m[k] = v
		}
		m[string(ext)] = t
		types.Store(&m)
	}
	return t
}

func ptrMap(m *map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	return *m
}
