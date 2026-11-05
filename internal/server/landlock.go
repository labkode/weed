package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/landlock"
	"github.com/labkode/weed/internal/seccomp"
	"github.com/labkode/weed/internal/systemd"
	"github.com/labkode/weed/internal/worker"
	"golang.org/x/sys/unix"
)

// confinedEnv is in the environment of weed that Confine executes again, confined
const confinedEnv = "WEED_LANDLOCK"

// starter starts the workers, once Confine has started it
var starter *worker.Starter

// Confine gives up weed's privileges, and confines it. First it starts the starter of
// workers, which keeps the capabilities that starting workers as their accounts needs
// (see worker.Starter); weed keeps none, but CAP_NET_BIND_SERVICE to listen on its
// ports below 1024. It confines weed's own process with Landlock, and with seccomp to
// the sockets that Landlock confines, or does not need to: Unix, netlink, TCP and UDP.
// Capabilities and both confinements are those of a thread, and what it executes:
// Confine executes weed again, from a thread that has them, and returns in weed so
// executed, once it has checked them. weed does not serve unconfined: without
// Landlock in the kernel, Confine fails.
func Confine(c *config.Config, src config.Source) error {
	again := os.Getenv(confinedEnv) != ""
	os.Unsetenv(confinedEnv)
	if again {
		// No rule allows / itself
		if f, err := os.Open("/"); err == nil {
			f.Close()
			return errors.New("weed was executed again to be confined with Landlock, and is not")
		}
		if !seccomp.Filtered(seccomp.TCPUDP) {
			return fmt.Errorf("weed was executed again to open %s sockets alone (seccomp), and opens others", seccomp.TCPUDP)
		}
		if more, err := worker.HasCapabilities(1 << unix.CAP_NET_BIND_SERVICE); err != nil || more != 0 {
			return fmt.Errorf("weed was executed again without capabilities, but CAP_NET_BIND_SERVICE, and has some (%#x)", more)
		}
		st, err := worker.StarterFromEnv()
		if err != nil {
			return err
		}
		if st == nil {
			return errors.New("weed was executed again with the starter of its workers, and has none")
		}
		starter = st
		return nil
	}
	abi := landlock.ABI()
	if abi < landlock.MinABI {
		return fmt.Errorf("weed confines itself and its workers with Landlock, which this kernel does not have (Landlock ABI %d, and %d is needed: Linux 5.19 or later, with landlock in lsm=)",
			abi, landlock.MinABI)
	}
	// weed makes these once it needs them, and rules can only name what exists
	for _, p := range []string{c.AdminSocket, c.BansFile} {
		if p != "" {
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				return err
			}
		}
	}
	rules, nw := processRules(c, src), processNet(c)
	var desc []string
	for _, r := range rules {
		if abs, _ := filepath.Abs(r.Path); abs == "/" {
			return fmt.Errorf("confined with Landlock to %s, weed would reach everything: it does not export /, nor keep its files there", r)
		}
		desc = append(desc, r.String())
	}
	rs, err := landlock.New(rules, nw)
	if err != nil {
		return err
	}
	defer rs.Close()
	paths := append([]string{src.Path, "/proc/self/exe", c.LogFile, c.LimitsFile, c.TPCCAPath}, opened(c)...)
	path, err := rs.Unreachable(slices.DeleteFunc(paths, func(p string) bool { return p == "" })...)
	if err != nil {
		return err
	}
	if path != "" {
		if exe, err := os.Readlink(path); err == nil && path == "/proc/self/exe" {
			path = "its executable, " + exe + ","
		}
		return fmt.Errorf("confined with Landlock, weed could not open %s which it opens without: it is on a file system that Landlock cannot follow (such as Docker Desktop's mounts of the host): move it", path)
	}
	tcp := "not confined (Linux 6.7 or later)"
	if abi >= landlock.TCPABI {
		var bind []string
		for _, p := range nw.Ports {
			bind = append(bind, strconv.Itoa(int(p)))
		}
		tcp = "bind " + strings.Join(bind, " ")
		if len(bind) == 0 {
			tcp = "no bind"
		}
		if nw.Bind {
			tcp = "bind any port"
		}
		if nw.Connect {
			tcp += ", connect (token issuers, tpc.enabled)"
		} else {
			tcp += ", no connect"
		}
	}
	// The starter of workers, which keeps the privileges that weed gives up
	env, err := worker.LaunchStarter(os.Args[1:], worker.Sockets(c))
	if err != nil {
		return err
	}
	var keep uint64
	if bindsPrivileged(nw) {
		keep = 1 << unix.CAP_NET_BIND_SERVICE
	}
	slog.Info("weed confines itself with Landlock, and executes itself again confined, without privileges",
		"landlock_abi", abi, "rules", desc, "tcp", tcp, "sockets", seccomp.TCPUDP.String(),
		"capabilities", map[bool]string{true: "CAP_NET_BIND_SERVICE", false: "none"}[keep != 0])
	runtime.LockOSThread() // never unlocked: the thread is confined, and executes weed again (rs.Exec)
	if err := worker.KeepCapabilities(keep); err != nil {
		return err
	}
	if err := seccomp.Restrict(seccomp.TCPUDP); err != nil {
		return err
	}
	return rs.Exec(os.Args, append(slices.DeleteFunc(os.Environ(), func(e string) bool { return strings.HasPrefix(e, "WEED_") }),
		confinedEnv+"=1", env))
}

// bindsPrivileged says whether weed binds a port below 1024 (CAP_NET_BIND_SERVICE),
// or one that it does not know yet
func bindsPrivileged(nw landlock.Net) bool {
	return nw.Bind || slices.ContainsFunc(nw.Ports, func(p uint16) bool { return p < 1024 })
}

// processRules are what weed's own process may reach: the system's files, as its
// workers (but not the exported directory, which its workers reach and it does not),
// and the files of its configuration
func processRules(c *config.Config, src config.Source) []landlock.Rule {
	rules := worker.SystemRules(c)
	exe, _ := os.Executable()
	rules = landlock.Add(rules, landlock.Read, src.Path, exe, c.LimitsFile)
	rules = landlock.Add(rules, landlock.Read, opened(c)...)
	rules = landlock.Add(rules, landlock.Socket, c.AdminSocket)
	rules = landlock.Add(rules, landlock.Write, c.LogFile, c.BansFile)
	// The caches of SSSD, which a build with cgo reads to look accounts up
	rules = append(rules, landlock.Rule{Path: "/var/lib/sss", Access: landlock.Read})
	return rules
}

// opened are the files of the credentials that weed reads, of what c enables
func opened(c *config.Config) []string {
	var paths []string
	if c.TLS {
		paths = append(paths, c.TLSCert, c.TLSKey)
	}
	if c.X509Auth {
		paths = append(paths, c.CACert, c.CRLPath, c.GridmapFile)
	}
	if c.BasicAuth {
		paths = append(paths, c.HtpasswdFile, c.AppTokensFile)
	}
	if c.TokenIssuers != "" {
		paths = append(paths, c.TokenIssuers, c.TokenCAPath)
	}
	return slices.DeleteFunc(paths, func(p string) bool { return p == "" })
}

// processNet is what weed's own process may do of TCP: bind its ports, and connect to
// token issuers, and for the third-party copies that workers make through it
func processNet(c *config.Config) landlock.Net {
	nw := landlock.Net{
		Connect: c.TPC || c.TokenIssuers != "" || c.OIDCAuth,
		// systemd's notification socket, in some containers
		AbstractUnix: strings.HasPrefix(os.Getenv("NOTIFY_SOCKET"), "@"),
	}
	ports := []string{strconv.Itoa(c.Port)}
	if c.MetricsAddress != "" {
		_, port, _ := net.SplitHostPort(c.MetricsAddress)
		ports = append(ports, port)
	}
	// systemd listens on the ports of the sockets that it passed (socket activation)
	passed := systemd.ListenPorts()
	ports = slices.DeleteFunc(ports, func(p string) bool {
		n, err := strconv.Atoi(p)
		return err == nil && slices.Contains(passed, n)
	})
	for _, p := range ports {
		if n, err := strconv.ParseUint(p, 10, 16); err == nil && n != 0 {
			nw.Ports = append(nw.Ports, uint16(n))
		} else {
			nw.Bind = true // a port of the kernel's choosing, or a name
		}
	}
	return nw
}
