package bans

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "bans.json")
	l, err := Load(path)
	if err != nil || len(l.All()) != 0 {
		t.Fatalf("no file: %v, %v", l.All(), err)
	}
	since := time.Date(2026, 10, 29, 1, 2, 3, 0, time.UTC)
	if added, err := l.Add(Ban{User: "alice", Since: since, Reason: "compromised", By: "uid 0"}); !added || err != nil {
		t.Fatalf("ban alice: %v, %v", added, err)
	}
	if added, err := l.Add(Ban{User: "alice", Reason: "again"}); added || err != nil {
		t.Errorf("ban alice twice: %v, %v", added, err)
	}
	l.Add(Ban{User: "bob", Since: since})
	if b, ok := l.Get("alice"); !ok || b.Reason != "compromised" || !b.Since.Equal(since) {
		t.Errorf("alice: %+v, %v", b, ok)
	}
	if _, ok := l.Get("carol"); ok {
		t.Error("carol is banned")
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("saved: %v, %v", fi, err)
	}

	// Saved for the next start
	again, err := Load(path)
	if err != nil || len(again.All()) != 2 || again.All()[0].User != "alice" || again.All()[1].User != "bob" {
		t.Fatalf("reloaded: %+v, %v", again.All(), err)
	}
	if removed, err := l.Remove("alice"); !removed || err != nil {
		t.Errorf("unban alice: %v, %v", removed, err)
	}
	if removed, _ := l.Remove("alice"); removed {
		t.Error("alice unbanned twice")
	}
	if again, err := Load(path); err != nil || again.Len() != 1 {
		t.Errorf("after unbanning alice: %+v, %v", again.All(), err)
	}

	os.WriteFile(path, []byte("[{"), 0o600)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), path) {
		t.Errorf("invalid file: %v", err)
	}
	os.WriteFile(path, []byte(`[{"reason": "x"}]`), 0o600)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "without a user") {
		t.Errorf("a ban without a user: %v", err)
	}
}

// Bans that cannot be saved apply anyway, and say so
func TestUnsaved(t *testing.T) {
	dir := t.TempDir()
	l, _ := Load(filepath.Join(dir, "bans.json"))
	os.Chmod(dir, 0o500)
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	if os.Geteuid() == 0 {
		t.Skip("root writes anyway")
	}
	if added, err := l.Add(Ban{User: "alice"}); !added || err == nil {
		t.Errorf("unsaved ban: %v, %v", added, err)
	}
	if _, ok := l.Get("alice"); !ok {
		t.Error("an unsaved ban does not apply")
	}
}

func TestInMemoryAndNil(t *testing.T) {
	l, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if added, err := l.Add(Ban{User: "alice"}); !added || err != nil {
		t.Errorf("in memory: %v, %v", added, err)
	}
	var none *List
	if _, ok := none.Get("alice"); ok || none.All() != nil {
		t.Error("a nil list bans someone")
	}
}
