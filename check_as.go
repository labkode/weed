package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/labkode/weed/internal/fsuser"
)

// weed check run by root checks the configuration again as the account that weed runs
// as (-as, or User= of weed.service), with the capabilities that the unit gives it:
// root reads files that the account may not, and weed would not start with them.
// -as root checks as root alone.

// unitName is the unit of the RPM, and of the guide
const unitName = "weed.service"

// cutAs removes -as ACCOUNT from args, which are weed's options otherwise
func cutAs(args []string) (rest []string, as string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		name := strings.TrimLeft(a, "-")
		switch {
		case a == "--" || !strings.HasPrefix(a, "-"):
			return append(rest, args[i:]...), as, nil
		case name == "as":
			if i+1 >= len(args) {
				return nil, "", errors.New("-as needs an account")
			}
			as = args[i+1]
			i++
		case strings.HasPrefix(name, "as="):
			as = strings.TrimPrefix(name, "as=")
		default:
			rest = append(rest, a)
		}
	}
	return rest, as, nil
}

// unit is how systemd runs weed: the account and the ambient capabilities of the
// unit's service, if systemd has it
type unit struct {
	user string
	caps []uintptr
}

func readUnit() (unit, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "show", "--property=LoadState,User,AmbientCapabilities", unitName).Output()
	if err != nil {
		return unit{}, false
	}
	var u unit
	loaded := false
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		switch k {
		case "LoadState":
			loaded = v == "loaded"
		case "User":
			u.user = v
		case "AmbientCapabilities":
			u.caps = capabilities(v)
		}
	}
	return u, loaded
}

// capNames are the capabilities by number, as systemd names them
var capNames = strings.Fields(`cap_chown cap_dac_override cap_dac_read_search cap_fowner cap_fsetid
	cap_kill cap_setgid cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
	cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock cap_ipc_owner cap_sys_module
	cap_sys_rawio cap_sys_chroot cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
	cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config cap_mknod cap_lease
	cap_audit_write cap_audit_control cap_setfcap cap_mac_override cap_mac_admin cap_syslog
	cap_wake_alarm cap_block_suspend cap_audit_read cap_perfmon cap_bpf cap_checkpoint_restore`)

func capabilities(names string) []uintptr {
	var caps []uintptr
	for _, n := range strings.Fields(strings.ToLower(names)) {
		for i, c := range capNames {
			if c == n {
				caps = append(caps, uintptr(i))
			}
		}
	}
	return caps
}

// The capabilities of the RPM's unit, for -as without it
var unitCaps = capabilities("cap_setuid cap_setgid cap_kill cap_net_bind_service")

// checkAs runs weed check, with args, again as the account that weed runs as, if
// root runs it and weed runs as another: as -as says, or the unit. It returns how it
// went: ok, and if not, what weed check said.
func checkAs(args []string, as, config string) (account, why string, ok bool, out string) {
	if os.Geteuid() != 0 || config == "" {
		// Not root (as in the unit's ExecStartPre, as its account), or the quick start
		return "", "", true, ""
	}
	caps := unitCaps
	u, loaded := readUnit()
	switch {
	case as == "root" || as == "0":
		return "", "", true, "" // as root alone: a file that weed does not run with, yet
	case as != "":
		account, why = as, "-as"
		if loaded && u.user == as {
			caps = u.caps
		}
	case loaded && u.user != "" && u.user != "root" && u.user != "0":
		account, why, caps = u.user, "User= of "+unitName, u.caps
	default:
		return "", "", true, ""
	}
	acc, err := fsuser.Lookup(account)
	if err != nil {
		return account, why, false, fmt.Sprintf("cannot check as the account %s: %v\n", account, err)
	}
	groups := make([]uint32, len(acc.Groups))
	for i, g := range acc.Groups {
		groups[i] = uint32(g)
	}
	// As systemd runs it: in /, the configuration named absolutely
	abs, err := filepath.Abs(config)
	if err != nil {
		return account, why, false, err.Error() + "\n"
	}
	var cargs []string
	for i := 0; i < len(args); i++ {
		a := strings.TrimLeft(args[i], "-")
		switch {
		case a == "config" && i+1 < len(args):
			i++
		case strings.HasPrefix(a, "config="):
		default:
			cargs = append(cargs, args[i])
		}
	}
	cmd := &exec.Cmd{
		Path: "/proc/self/exe",
		Args: append([]string{"weed", "check", "-config", abs}, cargs...),
		Dir:  "/",
		SysProcAttr: &syscall.SysProcAttr{
			Credential:  &syscall.Credential{Uid: uint32(acc.UID), Gid: uint32(acc.GID), Groups: groups},
			AmbientCaps: caps,
		},
	}
	b, err := cmd.CombinedOutput()
	return account, why, err == nil, string(b)
}
