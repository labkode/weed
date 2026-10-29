package tpc

import (
	"log/slog"
	"net/netip"
	"strings"
	"testing"
)

func TestAddressPolicy(t *testing.T) {
	cases := []struct {
		addr           string
		local, private bool // which allow flag makes it reachable; neither means always allowed
	}{
		{"188.184.21.108", false, false}, // a public address (CERN)
		{"2001:1458:201:e4::100:b", false, false},
		{"127.0.0.1", true, false},
		{"::1", true, false},
		{"169.254.169.254", true, false}, // cloud metadata
		{"fe80::1", true, false},
		{"224.0.0.1", true, false},
		{"::ffff:127.0.0.1", true, false}, // IPv4-mapped
		{"10.1.2.3", false, true},
		{"172.16.0.1", false, true},
		{"192.168.1.1", false, true},
		{"::ffff:192.168.1.1", false, true},
		{"fd00::1", false, true},
		{"100.64.0.1", false, true},
		{"0.1.2.3", true, false},
		{"255.255.255.255", false, true},
		{"64:ff9b::a00:1", false, true}, // NAT64 for 10.0.0.1
		{"2002:a00:1::", false, true},   // 6to4 for 10.0.0.1
	}
	for _, c := range cases {
		ip := netip.MustParseAddr(c.addr)
		for _, p := range []addressPolicy{{}, {allowLocal: true}, {allowPrivate: true}, {true, true}} {
			want := (!c.local && !c.private) || (c.local && p.allowLocal) || (c.private && p.allowPrivate)
			if got := p.allowed(ip); got != want {
				t.Errorf("%+v allowed(%s) = %t, want %t", p, c.addr, got, want)
			}
		}
	}
	for _, p := range []addressPolicy{{}, {true, true}} {
		if p.allowed(netip.MustParseAddr("0.0.0.0")) || p.allowed(netip.MustParseAddr("::")) {
			t.Errorf("%+v allows the unspecified address", p)
		}
	}
	if err := (addressPolicy{}).control("tcp", "[::ffff:10.0.0.1]:443", nil); err == nil {
		t.Error("control allowed a mapped private address")
	}
}

func TestModeLogged(t *testing.T) {
	var b strings.Builder
	slog.New(slog.NewJSONHandler(&b, nil)).Info("x", "pull", Pull, "push", Push)
	if !strings.Contains(b.String(), `"pull":"pull","push":"push"`) {
		t.Errorf("logged as %s", b.String())
	}
}
