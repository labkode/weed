package main

import (
	"net/http"
	"reflect"
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

func TestParsingReprDigest(t *testing.T) {
	inputs := map[string]map[digestAlgo]*digest{
		"adler=:123=:": {
			digestAdler: &digest{Algo: string(digestAdler), Value: "123="},
		},
		"adler=:123=:,md5=:333=:": {
			digestAdler: &digest{Algo: string(digestAdler), Value: "123="},
			digestMD5:   &digest{Algo: string(digestMD5), Value: "333="},
		},
		"md5=:333=:,adler=:123=:": {
			digestAdler: &digest{Algo: string(digestAdler), Value: "123="},
			digestMD5:   &digest{Algo: string(digestMD5), Value: "333="},
		},
		"malformed":              {},
		"malformed=abc":          {},
		"malformed=:zzz=":        {}, // missing trailing colon
		"md5=:!notvalidbase64-:": {},
		"":                       {},
	}

	for input, expected := range inputs {
		got := parseReprDigest(input)
		if !reflect.DeepEqual(expected, got) {
			t.Fatalf("error: expected=%v got=%v", expected, got)
		}
	}
}
