package landlock

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Add allows a directory beneath it, a file beneath its directory (in /, the file
// itself), and leaves out what rules allow already
func TestAdd(t *testing.T) {
	dir := t.TempDir()
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real // TMPDIR may be a symbolic link
	}
	sub := filepath.Join(dir, "sub")
	os.Mkdir(sub, 0o755)
	file := filepath.Join(sub, "f")
	os.WriteFile(file, nil, 0o644)
	os.Symlink(file, filepath.Join(dir, "link"))

	rules := Add(nil, Read, file, filepath.Join(dir, "link"), "", filepath.Join(dir, "missing"))
	want := []Rule{{Path: sub, Access: Read}, {Path: dir, Access: Read}}
	if !slices.Equal(rules, want) {
		t.Errorf("Add = %v, want %v", rules, want)
	}
	// Read beneath a rule of Write, or of Read, is allowed already; Write is not
	rules = Add([]Rule{{Path: dir, Access: Write}}, Read, file)
	if len(rules) != 1 {
		t.Errorf("Read beneath Write: %v", rules)
	}
	rules = Add([]Rule{{Path: dir, Access: Read}}, Write, sub)
	if want := (Rule{Path: sub, Access: Write}); len(rules) != 2 || rules[1] != want {
		t.Errorf("Write beneath Read: %v", rules)
	}
	// Socket allows Write, not the other way round
	if rules := Add([]Rule{{Path: dir, Access: Socket}}, Write, sub); len(rules) != 1 {
		t.Errorf("Write beneath Socket: %v", rules)
	}
	if rules := Add([]Rule{{Path: dir, Access: Write}}, Socket, sub); len(rules) != 2 {
		t.Errorf("Socket beneath Write: %v", rules)
	}
	if rules := Add(nil, Read, "/weed-landlock-missing"); len(rules) != 1 || rules[0].Path != "/weed-landlock-missing" {
		t.Errorf("a file in /: %v", rules)
	}
	if s := (Rule{Path: "/data", Access: Write}).String(); s != "write /data" {
		t.Errorf("String = %q", s)
	}
}
