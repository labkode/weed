package findlimits

import (
	"fmt"
	"strconv"
	"strings"
)

// The configuration file that weed limits suggests: weed's own, with the lines it
// changes, each under a comment that says why and what it was, and nothing else
// changed (comments, order, spacing)

// tomlChange sets key of section to value, a TOML value as written
type tomlChange struct {
	Section, Key, Value string
	Reason              string
}

// editTOML applies changes to the TOML text src, a configuration of weed: sections
// of keys and values, a value over several lines being an array
func editTOML(src string, changes []tomlChange) string {
	lines := strings.Split(src, "\n")
	for _, ch := range changes {
		lines = applyChange(lines, ch)
	}
	return strings.Join(lines, "\n")
}

func applyChange(lines []string, ch tomlChange) []string {
	start, end := sectionLines(lines, ch.Section)
	comment := func(indent string, was []string) []string {
		var out []string
		for _, l := range wrap("weed limits: "+ch.Reason, 76) {
			out = append(out, indent+"# "+l)
		}
		for i, w := range was {
			if i == 0 {
				out = append(out, indent+"# was: "+strings.TrimPrefix(w, indent))
			} else {
				out = append(out, indent+"#      "+strings.TrimPrefix(w, indent))
			}
		}
		return out
	}
	if start < 0 {
		// A section of its own, at the end
		for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
			lines = lines[:len(lines)-1]
		}
		if len(lines) > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, "["+ch.Section+"]")
		lines = append(lines, comment("", nil)...)
		return append(lines, ch.Key+" = "+ch.Value, "")
	}
	for i := start + 1; i < end; i++ {
		indent, key, value, ok := keyLine(lines[i])
		if !ok || key != ch.Key {
			continue
		}
		last := i + valueLines(value, lines[i+1:end])
		repl := append(comment(indent, lines[i:last+1]), indent+ch.Key+" = "+ch.Value)
		return append(lines[:i], append(repl, lines[last+1:]...)...)
	}
	// The key is not set: after the section's last line that is not blank
	at := end
	for at > start+1 && strings.TrimSpace(lines[at-1]) == "" {
		at--
	}
	add := append(comment("", nil), ch.Key+" = "+ch.Value)
	return append(lines[:at], append(add, lines[at:]...)...)
}

// sectionLines is the line of the header of section, and the line after its last
// (the next header, or the end); -1 if there is none
func sectionLines(lines []string, section string) (start, end int) {
	start = -1
	for i, l := range lines {
		name, ok := headerLine(l)
		if !ok {
			continue
		}
		if start >= 0 {
			return start, i
		}
		if name == section {
			start = i
		}
	}
	return start, len(lines)
}

// headerLine reads "[name]", with a comment after it or not
func headerLine(l string) (string, bool) {
	t := strings.TrimSpace(stripComment(l))
	if !strings.HasPrefix(t, "[") || strings.HasPrefix(t, "[[") || !strings.HasSuffix(t, "]") {
		return "", false
	}
	return strings.TrimSpace(t[1 : len(t)-1]), true
}

// keyLine reads "key = value"
func keyLine(l string) (indent, key, value string, ok bool) {
	t := strings.TrimLeft(l, " \t")
	if t == "" || t[0] == '#' || t[0] == '[' {
		return "", "", "", false
	}
	k, v, ok := strings.Cut(t, "=")
	if !ok {
		return "", "", "", false
	}
	return l[:len(l)-len(t)], strings.Trim(strings.TrimSpace(k), `"`), strings.TrimSpace(v), true
}

// valueLines is how many of the lines after a key's line its value goes on over:
// those of an array whose brackets close later, or of a multi-line string
func valueLines(value string, next []string) int {
	if q := value[:min(3, len(value))]; q == `"""` || q == "'''" {
		if strings.Count(value, q) >= 2 {
			return 0
		}
		for i, l := range next {
			if strings.Contains(l, q) {
				return i + 1
			}
		}
		return len(next)
	}
	depth := bracketDepth(value)
	for i := 0; depth > 0 && i < len(next); i++ {
		depth += bracketDepth(next[i])
		if depth <= 0 {
			return i + 1
		}
	}
	return 0
}

// bracketDepth is the brackets that s opens, less those it closes, outside strings
// and comments
func bracketDepth(s string) int {
	depth := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' && quote == '"' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '#':
			return depth
		case c == '[':
			depth++
		case c == ']':
			depth--
		}
	}
	return depth
}

// stripComment is l without a comment after it, outside strings
func stripComment(l string) string {
	var quote byte
	for i := 0; i < len(l); i++ {
		c := l[i]
		switch {
		case quote != 0:
			if c == '\\' && quote == '"' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '#':
			return l[:i]
		}
	}
	return l
}

// tomlString writes s as a TOML basic string
func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func tomlStrings(list []string) string {
	q := make([]string, len(list))
	for i, s := range list {
		q[i] = tomlString(s)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

func tomlInt(n int) string { return strconv.Itoa(n) }

// wrap breaks text into lines of at most width, between words
func wrap(text string, width int) []string {
	var lines []string
	line := ""
	for _, w := range strings.Fields(text) {
		if line != "" && len(line)+1+len(w) > width {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += w
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}
