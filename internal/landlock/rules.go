package landlock

import (
	"debug/elf"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Access is what a Rule allows
type Access uint8

const (
	Read   Access = iota + 1 // read files, list directories
	Exec                     // Read, and execute files
	Write                    // Read, and write, create, rename and remove files and directories
	Socket                   // Write, and make Unix sockets
)

// Rule allows Access beneath Path, a directory, or to Path, a file
type Rule struct {
	Path   string
	Access Access
	// File, if set, is Path open (O_PATH is enough): the rule names it, rather than
	// what Path names when New opens it
	File *os.File
}

// String is the rule as weed logs it, e.g. "write /data"
func (r Rule) String() string {
	return [...]string{Read: "read ", Exec: "execute ", Write: "write ", Socket: "write and make sockets in "}[r.Access] + r.Path
}

// allows says whether r allows access to p
func (r Rule) allows(p string, access Access) bool {
	rel, err := filepath.Rel(r.Path, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../") &&
		(r.Access == access || access == Read || r.Access == Socket && access == Write)
}

// Add adds to rules one of access for each of paths that they do not allow already:
// beneath it, for a directory; for a file, beneath its directory, as a rule names an
// inode, and a file that replaces another is a new one (but to the file itself, in
// /). Symbolic links are followed; "" is left out.
func Add(rules []Rule, access Access, paths ...string) []Rule {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if real, err := filepath.EvalSymlinks(p); err == nil {
			p = real
		}
		if fi, err := os.Stat(p); (err != nil || !fi.IsDir()) && filepath.Dir(p) != "/" {
			p = filepath.Dir(p)
		}
		allowed := false
		for _, r := range rules {
			allowed = allowed || r.allows(p, access)
		}
		if !allowed {
			rules = append(rules, Rule{Path: p, Access: access})
		}
	}
	return rules
}

// Interpreter is the dynamic loader that executing exe needs, which a rule must allow
// executing too, "" if it needs none (a Go program built without cgo)
func Interpreter(exe string) string {
	f, err := elf.Open(exe)
	if err != nil {
		return ""
	}
	defer f.Close()
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_INTERP {
			b, err := io.ReadAll(prog.Open())
			if err != nil {
				return ""
			}
			return strings.TrimRight(string(b), "\x00")
		}
	}
	return ""
}

// MinABI is the version of Landlock that New needs: before it, Landlock refuses to
// rename or link files from one directory to another, whatever the rules
const MinABI = 2

// TCPABI is the version of Landlock that confines TCP (Linux 6.7): before it, New
// leaves TCP alone
const TCPABI = 4

// Net is what a ruleset allows of the network. From TCPABI on, Landlock confines bind
// and connect, of TCP alone: not UDP, nor listen on a socket that is not bound, which
// takes a port of the kernel's choosing. From ABI 6 on, it confines connecting and
// sending to abstract Unix sockets made outside the ruleset's confinement.
type Net struct {
	Bind         bool     // bind TCP sockets to any port
	Ports        []uint16 // bind TCP sockets to these ports
	Connect      bool     // connect TCP sockets to any port
	AbstractUnix bool     // connect to abstract Unix sockets made outside
}
