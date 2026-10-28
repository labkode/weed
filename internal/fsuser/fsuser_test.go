package fsuser

import "testing"

func TestLookupRefusesSuperuser(t *testing.T) {
	if _, err := Lookup("root"); err == nil {
		t.Fatal("root accepted")
	}
}

func TestLookupMissingAccount(t *testing.T) {
	if _, err := Lookup("no-such-account-weed-test"); err == nil {
		t.Fatal("missing account accepted")
	}
}
