package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestSetPassword(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, ".htpasswd")
	if replaced, err := SetPassword(file, "alice", "one"); err != nil || replaced {
		t.Fatalf("new file: %v %v", replaced, err)
	}
	fi, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if m := fi.Mode().Perm(); m != 0o600 && m != 0o640 {
		t.Errorf("a new file is %o", m)
	}

	// Comments and other users stay, in their places; the file keeps its mode
	b, _ := os.ReadFile(file)
	os.WriteFile(file, append([]byte("# users\n"), append(b, "bob:$2y$04$x\n"...)...), 0o644)
	os.Chmod(file, 0o604)
	if replaced, err := SetPassword(file, "alice", "two"); err != nil || !replaced {
		t.Fatalf("replace: %v %v", replaced, err)
	}
	b, _ = os.ReadFile(file)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 3 || lines[0] != "# users" || !strings.HasPrefix(lines[1], "alice:") || lines[2] != "bob:$2y$04$x" {
		t.Fatalf("file:\n%s", b)
	}
	if bcrypt.CompareHashAndPassword([]byte(strings.TrimPrefix(lines[1], "alice:")), []byte("two")) != nil {
		t.Error("alice's new password does not match")
	}
	if fi, _ := os.Stat(file); fi.Mode().Perm() != 0o604 {
		t.Errorf("mode %o, not kept", fi.Mode().Perm())
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*.new-*")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}

	if found, err := RemoveUser(file, "alice"); err != nil || !found {
		t.Fatalf("remove: %v %v", found, err)
	}
	if found, err := RemoveUser(file, "alice"); err != nil || found {
		t.Fatalf("remove again: %v %v", found, err)
	}
	if b, _ := os.ReadFile(file); string(b) != "# users\nbob:$2y$04$x\n" {
		t.Errorf("after remove:\n%s", b)
	}

	for _, bad := range []string{"", "a:b", "a b", "a\nb"} {
		if _, err := SetPassword(file, bad, "x"); err == nil {
			t.Errorf("user %q accepted", bad)
		}
	}
	if _, err := SetPassword(file, "carol", ""); err == nil {
		t.Error("empty password accepted")
	}
}

// A symbolic link stays one: the file it names changes
func TestSetPasswordLink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	os.WriteFile(real, nil, 0o640)
	os.Symlink(real, link)
	if _, err := SetPassword(link, "alice", "pw"); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link was replaced")
	}
	if b, _ := os.ReadFile(real); !strings.HasPrefix(string(b), "alice:") {
		t.Errorf("real file: %q", b)
	}
}

func TestAddToken(t *testing.T) {
	file := filepath.Join(t.TempDir(), ".app-tokens")
	if err := AddToken(file, "bob", "t1"); err != nil {
		t.Fatal(err)
	}
	if err := AddToken(file, "bob", "t2"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(file); string(b) != "t1:bob\nt2:bob\n" {
		t.Errorf("file: %q", b)
	}
}
