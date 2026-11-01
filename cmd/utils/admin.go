package utils

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/labkode/weed/internal/admin"
	"github.com/labkode/weed/internal/config"
)

// The commands that talk to the control plane of a running weed (see internal/admin)

// adminFlags parses the options of a control plane command, which name the socket
// with -config (its admin.socket) or -socket; without either, it is the default one.
// It exits on -h (0) and on wrong usage (2).
func adminFlags(name, operands string, argc int, define func(*flag.FlagSet)) (*admin.Client, []string, error) {
	fs := flag.NewFlagSet("weed utils "+name, flag.ContinueOnError)
	configFile := fs.String("config", "", "the configuration file that weed runs with, which names the socket (admin.socket)")
	socket := fs.String("socket", "", "the control plane's socket (default "+config.QuickStart().AdminSocket+")")
	if define != nil {
		define(fs)
	}
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s\n\nOptions (before the arguments):\n", strings.TrimSpace("weed utils "+name+" [options] "+operands))
		fs.PrintDefaults()
	}
	var args []string
	if len(os.Args) > 3 {
		args = os.Args[3:] // after "weed utils <command>"
	}
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	} else if err != nil {
		os.Exit(2) // which Parse has printed
	}
	if fs.NArg() != argc {
		fs.Usage()
		os.Exit(2)
	}
	path := *socket
	switch {
	case *configFile != "" && *socket != "":
		return nil, nil, errors.New("give -config or -socket, not both")
	case *configFile != "":
		cfg, _, err := config.Read(*configFile)
		if err != nil {
			return nil, nil, err
		}
		if cfg.AdminSocket == "" {
			return nil, nil, fmt.Errorf("%s disables the control plane (admin.socket)", *configFile)
		}
		path = cfg.AdminSocket
	case path == "":
		path = config.QuickStart().AdminSocket // that of weed without a configuration file
	}
	return admin.NewClient(path), fs.Args(), nil
}

// adminExit ends a command that failed
func adminExit(err error) {
	fmt.Fprintln(os.Stderr, "weed utils:", err)
	os.Exit(1)
}

// HandleBan bans a user: weed refuses its requests, whatever their credentials, and
// stops its worker processes at once
func HandleBan() {
	var reason string
	c, args, err := adminFlags("ban", "<user>", 1, func(fs *flag.FlagSet) {
		fs.StringVar(&reason, "reason", "", "why, kept with the ban")
	})
	if err != nil {
		adminExit(err)
	}
	var res admin.BanResult
	if err := c.Do("PUT", "/v1/bans/"+url.PathEscape(args[0]), admin.BanRequest{Reason: reason}, &res); err != nil {
		adminExit(err)
	}
	if res.Added {
		fmt.Printf("banned %s", res.User)
	} else {
		fmt.Printf("%s was banned already, since %s", res.User, res.Since.Local().Format("2006-01-02 15:04:05 MST"))
		if res.Reason != "" {
			fmt.Printf(" (%s)", res.Reason)
		}
	}
	if res.WorkersKilled > 0 {
		fmt.Printf("; stopped its %d worker process(es)", res.WorkersKilled)
	}
	fmt.Println()
	if res.Warning != "" {
		adminExit(errors.New(res.Warning))
	}
}

// HandleUnban lifts the ban of a user
func HandleUnban() {
	c, args, err := adminFlags("unban", "<user>", 1, nil)
	if err != nil {
		adminExit(err)
	}
	var res admin.UnbanResult
	if err := c.Do("DELETE", "/v1/bans/"+url.PathEscape(args[0]), nil, &res); err != nil {
		adminExit(err)
	}
	if res.Removed {
		fmt.Printf("lifted the ban of %s\n", res.User)
	} else {
		fmt.Printf("%s was not banned\n", res.User)
	}
	if res.Warning != "" {
		adminExit(errors.New(res.Warning))
	}
}

// HandleBans lists the banned users
func HandleBans() {
	var asJSON bool
	c, _, err := adminFlags("bans", "", 0, func(fs *flag.FlagSet) {
		fs.BoolVar(&asJSON, "json", false, "print the answer of weed, as JSON")
	})
	if err != nil {
		adminExit(err)
	}
	var res admin.Bans
	if err := c.Do("GET", "/v1/bans", nil, &res); err != nil {
		adminExit(err)
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(res)
		return
	}
	printBans(os.Stdout, res)
}

func printBans(out io.Writer, res admin.Bans) {
	if len(res.Bans) == 0 {
		fmt.Fprintln(out, "no user is banned")
		return
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "USER\tSINCE\tBY\tREASON")
	for _, b := range res.Bans {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", b.User, b.Since.Local().Format("2006-01-02 15:04:05 MST"), b.By, b.Reason)
	}
	w.Flush()
}
