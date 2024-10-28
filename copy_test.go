package main

import (
	"net/http"
	"testing"
)

func TestExtractHeaders(t *testing.T) {
	from, _ := http.NewRequest("GET", "example.org", nil)
	from.Header.Add("TransferHeaderAuthorization", "dummy")
	to, _ := http.NewRequest("GET", "example.org", nil)
	copyTransferHeaders(from, to)
	if to.Header.Get("Authorization") != "dummy" {
		t.Fatalf("Authorization header not found")
		return
	}
}

func TestGetTCPMode(t *testing.T) {
	tests := map[string]TPCMode{
		"Source":      TPCModePull,
		"Destination": TPCModePush,
	}

	for k, v := range tests {
		r, _ := http.NewRequest("GET", "example.org", nil)
		r.Header.Set(k, "dummy")
		got, err := getTPCMode(r)
		if err != nil {
			t.Fatalf("not expecting an error: %v", err)
			return
		}

		if got != v {
			t.Fatalf("got=%s expected=%s", got, v)
			return
		}
	}

	// test for failure modes where both headers are set or not
	r, _ := http.NewRequest("GET", "example.org", nil)
	_, err := getTPCMode(r)
	if err == nil {
		t.Fatal("expecting error when not setting the TPC mode")
	}

	r, _ = http.NewRequest("GET", "example.org", nil)
	r.Header.Set("Source", "dummy")
	r.Header.Set("Destination", "dummy")
	_, err = getTPCMode(r)
	if err == nil {
		t.Fatal("expecting error when setting both Source and Destination headers")
	}
}
