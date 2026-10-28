package handlers

import "testing"

func FuzzParseIfHeader(f *testing.F) {
	for _, s := range []string{
		"(<opaquelocktoken:a>)", `</webdav/a> (<t> ["etag"]) (Not <t2>)`, "<http://h/a> (<t>) </b> ([e])",
		"(", "<", "(Not)", "(Not Not <t>)", "() ", "<a>", "(<t>) <a> (<u>)",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		lists, ok := parseIfHeader(s)
		if !ok {
			return
		}
		if len(lists) == 0 {
			t.Fatalf("%q: accepted without lists", s)
		}
		tagged := lists[0].tag != ""
		for _, l := range lists {
			if len(l.conditions) == 0 {
				t.Fatalf("%q: accepted an empty list", s)
			}
			if (l.tag != "") != tagged {
				t.Fatalf("%q: accepted tagged and untagged lists together", s)
			}
			for _, c := range l.conditions {
				if (c.Token == "") == (c.ETag == "") {
					t.Fatalf("%q: condition %+v needs exactly one of token and entity tag", s, c)
				}
			}
		}
	})
}

func FuzzParseISODuration(f *testing.F) {
	for _, s := range []string{"PT1H", "P1D", "PT0.5S", "P", "PT", "P1DT2H3M4.5S", "PT99999999999999999999H", "P100000D", "PT1e9S", "PT-1S"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, err := parseISODuration(s)
		if err == nil && d <= 0 {
			t.Fatalf("%q: non-positive duration %v accepted", s, d)
		}
	})
}
