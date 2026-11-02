package docs

import (
	"bytes"
	"errors"
	"fmt"
	"html"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	nethtml "golang.org/x/net/html"

	"github.com/labkode/weed/internal/config"
)

// page is a page of the guide, as make docs made it
type page struct {
	text  string
	title string          // of <title>
	h1    string          // the text of the first h1
	ids   map[string]bool // the id attributes
	hrefs []string
}

const titlePrefix = "weed administration guide – " // pandoc --title-prefix

// pages reads and parses every page of the guide, by file name
func pages(t *testing.T) map[string]*page {
	t.Helper()
	files, err := filepath.Glob("html/*.html")
	if err != nil || len(files) == 0 {
		t.Fatalf("no pages in html (make docs makes them): %v", err)
	}
	all := map[string]*page{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		p, err := parse(b)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		all[filepath.Base(f)] = p
	}
	return all
}

// void elements have no end tag
var void = map[string]bool{"area": true, "base": true, "br": true, "col": true, "embed": true, "hr": true,
	"img": true, "input": true, "link": true, "meta": true, "source": true, "track": true, "wbr": true}

// blocks may not be inside a p, which they would end
var blocks = map[string]bool{"div": true, "dl": true, "h1": true, "h2": true, "h3": true, "ol": true,
	"p": true, "pre": true, "table": true, "ul": true}

// parse reads a page, and checks that every element is closed, in order, as pandoc
// writes them: so that header.html and footer.html, which pandoc copies, do too
func parse(b []byte) (*page, error) {
	p := &page{text: string(b), ids: map[string]bool{}}
	z := nethtml.NewTokenizer(bytes.NewReader(b))
	line := 1
	var open []string
	var in string // the element whose text is being collected: title or h1
	var text strings.Builder
	for {
		tt := z.Next()
		at := line
		line += bytes.Count(z.Raw(), []byte("\n"))
		switch tt {
		case nethtml.ErrorToken:
			if !errors.Is(z.Err(), io.EOF) {
				return nil, z.Err()
			}
			if len(open) > 0 {
				return nil, errors.New("<" + strings.Join(open, "> <") + "> not closed")
			}
			return p, nil
		case nethtml.StartTagToken, nethtml.SelfClosingTagToken:
			tok := z.Token()
			for _, a := range tok.Attr {
				switch a.Key {
				case "id":
					if p.ids[a.Val] {
						return nil, lineError(at, "id %q is used twice", a.Val)
					}
					p.ids[a.Val] = true
				case "href":
					p.hrefs = append(p.hrefs, a.Val)
				}
			}
			if blocks[tok.Data] && slices.Contains(open, "p") {
				return nil, lineError(at, "<%s> inside <p>", tok.Data)
			}
			if (tok.Data == "title" || tok.Data == "h1" && p.h1 == "") && in == "" {
				in = tok.Data
				text.Reset()
			}
			if !void[tok.Data] && tt == nethtml.StartTagToken {
				open = append(open, tok.Data)
			}
		case nethtml.EndTagToken:
			tok := z.Token()
			if len(open) == 0 || open[len(open)-1] != tok.Data {
				return nil, lineError(at, "</%s> closes <%s>", tok.Data, strings.Join(open, "> <"))
			}
			open = open[:len(open)-1]
			if tok.Data == in {
				switch in {
				case "title":
					p.title = text.String()
				case "h1":
					p.h1 = text.String()
				}
				in = ""
			}
		case nethtml.TextToken:
			if in != "" {
				text.WriteString(html.UnescapeString(string(z.Raw())))
			}
		}
	}
}

func lineError(line int, format string, args ...any) error {
	return fmt.Errorf("line %d: %s", line, fmt.Sprintf(format, args...))
}

// sources returns the pages that src/Makefile makes (SRC), and options.md and
// changelog.md, which it makes from weed config and from CHANGELOG.md
func sources(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("src/Makefile")
	if err != nil {
		t.Fatal(err)
	}
	var src []string
	for _, m := range regexp.MustCompile(`(?m)^SRC \+?= ([a-z-]+\.md)$`).FindAllStringSubmatch(string(b), -1) {
		src = append(src, m[1])
	}
	return append(src, "options.md", "changelog.md")
}

// TestPages checks that make docs makes every page in src, that each has its title
// in h1, and that the sidebar lists every page and only pages
func TestPages(t *testing.T) {
	all := pages(t)
	src := sources(t)
	written, err := filepath.Glob("src/*.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range written {
		if !slices.Contains(src, filepath.Base(f)) {
			t.Errorf("%s is not in SRC in src/Makefile: make docs leaves it out", f)
		}
	}
	for _, s := range src {
		name := strings.TrimSuffix(s, ".md") + ".html"
		p := all[name]
		if p == nil {
			t.Errorf("html has no %s, made from %s (make docs)", name, s)
			continue
		}
		if title, ok := strings.CutPrefix(p.title, titlePrefix); !ok {
			t.Errorf("%s: title %q does not start with %q", name, p.title, titlePrefix)
		} else if p.h1 != title {
			t.Errorf("%s: h1 %q differs from the title %q", name, p.h1, title)
		}
	}
	for name := range all {
		if !slices.Contains(src, strings.TrimSuffix(name, ".html")+".md") {
			t.Errorf("html/%s is not made from a page in src", name)
		}
	}

	b, err := os.ReadFile("src/header.html")
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, m := range regexp.MustCompile(`href="([^"#]+)`).FindAllStringSubmatch(string(b), -1) {
		listed[m[1]] = true
	}
	for name := range all {
		if !listed[name] {
			t.Errorf("%s is not in the sidebar (src/header.html)", name)
		}
	}
	for name := range listed {
		if all[name] == nil {
			t.Errorf("the sidebar (src/header.html) links to %s, which is not a page", name)
		}
	}
}

// TestLinks checks that every link within the guide leads to a page or file, and its
// anchor to an id there
func TestLinks(t *testing.T) {
	all := pages(t)
	for name, p := range all {
		for _, href := range p.hrefs {
			if strings.HasPrefix(href, "https://") || strings.HasPrefix(href, "http://") {
				continue
			}
			file, anchor, _ := strings.Cut(href, "#")
			if file == "" {
				file = name
			}
			target := all[file]
			if target == nil {
				if _, err := os.Stat(filepath.Join("html", file)); err != nil || anchor != "" {
					t.Errorf("%s: link to %s, which is not a page", name, href)
				}
				continue
			}
			if anchor != "" && !target.ids[anchor] {
				t.Errorf("%s: link to %s, but %s has no id %q", name, href, file, anchor)
			}
		}
	}
}

// options returns the default of every option, as section.key, in the TOML of
// config.Example
func options(t *testing.T) map[string]string {
	t.Helper()
	opts := map[string]string{}
	section := ""
	for _, line := range strings.Split(config.Example(), "\n") {
		switch {
		case strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			section = line[1 : len(line)-1]
		default:
			if key, value, ok := strings.Cut(line, " = "); ok {
				opts[section+"."+key] = value
			}
		}
	}
	settings := config.Default().Settings()
	for _, s := range settings {
		if _, ok := opts[s.Section+"."+s.Key]; !ok {
			t.Fatalf("option %s.%s is not in config.Example", s.Section, s.Key)
		}
	}
	if len(opts) != len(settings) {
		t.Fatalf("config.Example has %d options, config.Settings %d", len(opts), len(settings))
	}
	return opts
}

var optionRow = regexp.MustCompile(`<tr>\s*<td><span id="([^"]*)"><code>([^<]*)</code></span></td>\s*<td><code>(.*?)</code></td>\s*<td>.+?</td>\s*</tr>`)

// TestOptions checks that options.html, which make docs makes from weed config, has
// a row for every option, with its default, and that the pages mention only options
// that exist
func TestOptions(t *testing.T) {
	all := pages(t)
	opts := options(t)
	text := all["options.html"].text
	documented := map[string]bool{}
	for _, m := range optionRow.FindAllStringSubmatch(text, -1) {
		id, key, value := m[1], m[2], html.UnescapeString(m[3])
		want, ok := opts[id]
		switch {
		case !ok:
			t.Errorf("options.html: %s is not an option", id)
		case !strings.HasSuffix(id, "."+key):
			t.Errorf("options.html: the row of %s is about %s", id, key)
		case value != want:
			t.Errorf("options.html: the default of %s is %s, not %s (make docs)", id, want, value)
		}
		documented[id] = true
	}
	for id := range opts {
		if !documented[id] {
			t.Errorf("options.html has no row for %s (make docs)", id)
		}
	}
	if n := strings.Count(text, "<tr>") - strings.Count(text, "<thead>"); n != len(documented) {
		t.Errorf("options.html has %d rows of options, of which %d are well-formed", n, len(documented))
	}

	sections := map[string]bool{}
	for id := range opts {
		sections[strings.Split(id, ".")[0]] = true
	}
	mention := regexp.MustCompile(`<code>([a-z0-9_]+)\.([a-z_]+)`)
	for name, p := range all {
		for _, m := range mention.FindAllStringSubmatch(p.text, -1) {
			if id := m[1] + "." + m[2]; sections[m[1]] && opts[id] == "" {
				t.Errorf("%s mentions %s, which is not an option", name, id)
			}
		}
	}
}

// metricDefinitions returns the metrics that the code defines, with their labels
// when the code lists them in the definition (counters and gauges kept by weed)
func metricDefinitions(t *testing.T) map[string][]string {
	t.Helper()
	vec := regexp.MustCompile(`New(?:Counter|Gauge)\("([a-z_]+)",\s*"(?:[^"\\]|\\.)*"((?:,\s*"[a-z_]+")*)\)`)
	computed := regexp.MustCompile(`WriteGauge(?:Samples)?\(w,\s*"([a-z_]+)"`)
	label := regexp.MustCompile(`"([a-z_]+)"`)
	defined := map[string][]string{}
	err := filepath.WalkDir("..", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".") && path != "..") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range vec.FindAllStringSubmatch(string(b), -1) {
			var labels []string
			for _, l := range label.FindAllStringSubmatch(m[2], -1) {
				labels = append(labels, l[1])
			}
			defined[m[1]] = labels
		}
		for _, m := range computed.FindAllStringSubmatch(string(b), -1) {
			if _, ok := defined[m[1]]; !ok {
				defined[m[1]] = nil
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(defined) < 20 {
		t.Fatalf("found only %d metrics in the code: %v", len(defined), defined)
	}
	return defined
}

var metricRow = regexp.MustCompile(`<tr>\s*<td><span id="([^"]*)"><code>([^<]*)</code></span></td>\s*<td>(counter|gauge)</td>\s*<td>([^<]*)</td>\s*<td>.+?</td>\s*</tr>`)

// TestMetrics checks that metrics.html has a row for every metric, with its labels,
// and that the pages mention only metrics that exist, but the changelog, which names
// those of earlier versions
func TestMetrics(t *testing.T) {
	all := pages(t)
	defined := metricDefinitions(t)
	text := all["metrics.html"].text
	documented := map[string]bool{}
	for _, m := range metricRow.FindAllStringSubmatch(text, -1) {
		name := m[1]
		if m[2] != name {
			t.Errorf("metrics.html: the row of %s is about %s", name, m[2])
		}
		labels, ok := defined[name]
		if !ok {
			t.Errorf("metrics.html: %s is not a metric of weed", name)
			continue
		}
		if labels != nil {
			if got := strings.Join(labels, ", "); got != m[4] {
				t.Errorf("metrics.html: %s has the labels %q, not %q", name, got, m[4])
			}
		}
		documented[name] = true
	}
	for name := range defined {
		if !documented[name] {
			t.Errorf("metrics.html has no row for %s", name)
		}
	}
	if n := strings.Count(text, "<td><span id="); n != len(documented) {
		t.Errorf("metrics.html has %d rows of metrics, of which %d are well-formed", n, len(documented))
	}

	mention := regexp.MustCompile(`\bweed_[a-z_]+`)
	for name, p := range all {
		if name == "changelog.html" {
			continue
		}
		for _, m := range mention.FindAllString(p.text, -1) {
			if _, ok := defined[m]; !ok {
				t.Errorf("%s mentions %s, which is not a metric of weed", name, m)
			}
		}
	}
}

// TestMade checks that html is what make docs makes from src, so that the pages are
// not edited by hand, nor left behind by a change of src or of the options. It needs
// make and the pandoc that made html (PANDOC_VERSION in src/Makefile): others write
// other HTML.
func TestMade(t *testing.T) {
	b, err := os.ReadFile("src/Makefile")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^PANDOC_VERSION = (.+)$`).FindSubmatch(b)
	if m == nil {
		t.Fatal("src/Makefile sets no PANDOC_VERSION")
	}
	want := "pandoc " + string(m[1])
	out, err := exec.Command("pandoc", "--version").Output()
	if err != nil {
		t.Skipf("no pandoc: %v", err)
	}
	if got, _, _ := strings.Cut(string(out), "\n"); got != want {
		t.Skipf("html was made with %s, not %s", want, got)
	}
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("no make")
	}

	dir := t.TempDir()
	weed := filepath.Join(dir, "weed")
	if out, err := exec.Command("go", "build", "-o", weed, "..").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	build := filepath.Join(dir, "build")
	cmd := exec.Command("make", "-C", "src", "doc", "BUILD="+build, "WEED="+weed)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("make: %v\n%s", err, out)
	}

	made, err := filepath.Glob(filepath.Join(build, "*.html"))
	if err != nil {
		t.Fatal(err)
	}
	made = append(made, filepath.Join(build, "weed.css"))
	kept, err := filepath.Glob("html/*")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range kept {
		if !slices.Contains(made, filepath.Join(build, filepath.Base(f))) {
			t.Errorf("%s is not made from src: make docs removes it", f)
		}
	}
	for _, f := range made {
		got, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		have, err := os.ReadFile(filepath.Join("html", filepath.Base(f)))
		if err != nil || !bytes.Equal(have, got) {
			t.Errorf("html/%s is not what make docs makes from src: run make docs", filepath.Base(f))
		}
	}
}
