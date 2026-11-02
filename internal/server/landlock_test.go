package server

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/landlock"
)

// weed's own rules: those of workers, the files that its configuration names, of what
// it enables, and where it writes; and its ports
func TestProcessRules(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir()) // TMPDIR may be a symbolic link
	for _, d := range []string{"etc", "log", "run", "state"} {
		os.Mkdir(filepath.Join(dir, d), 0o755)
	}
	path := func(p string) string { return filepath.Join(dir, p) }
	os.WriteFile(path("etc/weed.toml"), nil, 0o600)
	os.WriteFile(path("etc/htpasswd"), nil, 0o600)
	c := config.QuickStart()
	c.Directory = t.TempDir()
	c.BasicAuth, c.HtpasswdFile, c.AppTokensFile = true, path("etc/htpasswd"), ""
	c.TLS, c.TLSCert, c.TLSKey = false, "/elsewhere/server.crt", "/elsewhere/server.key"
	c.LogFile, c.AdminSocket, c.BansFile = path("log/weed.log"), path("run/admin.sock"), path("state/bans.json")

	rules := processRules(c, config.Source{Path: path("etc/weed.toml")})
	for _, want := range []landlock.Rule{{Path: path("etc"), Access: landlock.Read}, {Path: path("log"), Access: landlock.Write},
		{Path: path("run"), Access: landlock.Socket}, {Path: path("state"), Access: landlock.Write}} {
		if !slices.Contains(rules, want) {
			t.Errorf("no %v in %v", want, rules)
		}
	}
	if slices.ContainsFunc(rules, func(r landlock.Rule) bool { return strings.HasPrefix(r.Path, "/elsewhere") }) {
		t.Errorf("the files of TLS, which is not enabled: %v", rules)
	}

	c.Port, c.MetricsAddress = 8443, "localhost:9100"
	if nw := processNet(c); !slices.Equal(nw.Ports, []uint16{8443, 9100}) || nw.Bind || nw.Connect {
		t.Errorf("ports 8443 and 9100, no connect: %+v", nw)
	}
	c.Port, c.TPC = 0, true
	if nw := processNet(c); !nw.Bind || !nw.Connect {
		t.Errorf("port 0, tpc: %+v", nw)
	}
}
