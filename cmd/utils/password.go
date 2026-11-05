package utils

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/utils"
	"golang.org/x/sys/unix"
)

// The commands that change weed's password file (basic.htpasswd) and app tokens file
// (basic.app_tokens)

// defaultConfig is the configuration file that names them without -config: the
// RPM's, if there is one
const defaultConfig = "/etc/weed/weed.toml"

// credentialFlags parses the options of a command that changes the file of option
// (pick of the configuration): -file, or that of -config. It exits on -h (0) and on
// wrong usage (2): operands are minArgs to maxArgs.
func credentialFlags(name, operands, about, option string, pick func(*config.Config) string, args []string,
	minArgs, maxArgs int, define func(*flag.FlagSet)) (file, from string, rest []string) {
	fs := flag.NewFlagSet("weed utils "+name, flag.ContinueOnError)
	configFile := fs.String("config", "", "weed's configuration file, whose "+option+" it changes (default "+defaultConfig+", if it exists)")
	fileFlag := fs.String("file", "", "the file to change, rather than "+option+" of the configuration")
	if define != nil {
		define(fs)
	}
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: weed utils %s [options] %s\n\n%s\n\nOptions (before the arguments):\n", name, operands, about)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	} else if err != nil {
		os.Exit(2) // which Parse has printed
	}
	if fs.NArg() < minArgs || fs.NArg() > maxArgs {
		fs.Usage()
		os.Exit(2)
	}
	switch {
	case *configFile != "" && *fileFlag != "":
		utilsExit(errors.New("give -config or -file, not both"))
	case *fileFlag != "":
		return *fileFlag, "-file", fs.Args()
	case *configFile == "":
		if _, err := os.Stat(defaultConfig); err != nil {
			return pick(config.Default()), "", fs.Args()
		}
		*configFile = defaultConfig
	}
	cfg, _, err := config.Read(*configFile)
	if err != nil {
		utilsExit(err)
	}
	return pick(cfg), option + " of " + *configFile, fs.Args()
}

func utilsExit(err error) {
	fmt.Fprintln(os.Stderr, "weed utils:", err)
	os.Exit(1)
}

// reloadHint says when weed sees the change
const reloadHint = "weed reads it again on systemctl reload weed (SIGHUP), and every server.reload_interval"

// HandlePassword sets the password of a user in weed's password file, or removes it
func HandlePassword() {
	var del bool
	file, from, args := credentialFlags("password", "<user>",
		"Sets the password of the user in weed's password file (basic.htpasswd), adding the user\n"+
			"if it is not there, or removes the user (-delete). It asks for the password twice on a\n"+
			"terminal, and otherwise reads the first line of stdin:\n\n"+
			"    # weed utils password alice\n"+
			"    # printf '%s\\n' \"$PASSWORD\" | weed utils password alice\n\n"+
			"The file keeps its owner, group and mode; a new one is of the group weed, 0640, if there is one (0600 otherwise).",
		"basic.htpasswd", func(c *config.Config) string { return c.HtpasswdFile },
		os.Args[3:], 1, 2, func(fs *flag.FlagSet) {
			fs.BoolVar(&del, "delete", false, "remove the user")
		})
	name := args[0]
	where := describe(file, from)
	if del {
		if len(args) != 1 {
			utilsExit(errors.New("-delete takes the user alone"))
		}
		found, err := utils.RemoveUser(file, name)
		if err != nil {
			utilsExit(err)
		}
		if !found {
			utilsExit(fmt.Errorf("%s is not in %s", name, where))
		}
		fmt.Printf("Removed %s from %s; %s\n", name, where, reloadHint)
		return
	}
	var password string
	if len(args) == 2 {
		password = args[1]
		fmt.Fprintf(os.Stderr, "weed utils: a password on the command line is seen by other users (ps) and kept in the shell's history: without it, weed utils password asks for it, or reads it from stdin\n")
	} else {
		var err error
		if password, err = readPassword(name); err != nil {
			utilsExit(err)
		}
	}
	replaced, err := utils.SetPassword(file, name, password)
	if err != nil {
		utilsExit(err)
	}
	what := "Added " + name + " to"
	if replaced {
		what = "Changed the password of " + name + " in"
	}
	fmt.Printf("%s %s; %s\n", what, where, reloadHint)
}

// describe names file, and where it comes from
func describe(file, from string) string {
	if from == "" || from == "-file" {
		return file
	}
	return file + " (" + from + ")"
}

// readPassword asks for the password of name twice, without echo, on a terminal;
// otherwise it is the first line of stdin
func readPassword(name string) (string, error) {
	fd := int(os.Stdin.Fd())
	if _, err := unix.IoctlGetTermios(fd, unix.TCGETS); err != nil {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && (!errors.Is(err, io.EOF) || line == "") {
			return "", errors.New("no password on stdin (weed utils password asks for it on a terminal)")
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	first, err := prompt(fd, "Password of "+name+": ")
	if err != nil {
		return "", err
	}
	again, err := prompt(fd, "Again: ")
	if err != nil {
		return "", err
	}
	if first != again {
		return "", errors.New("the passwords differ")
	}
	return first, nil
}

// prompt reads a line from the terminal fd without echo
func prompt(fd int, text string) (string, error) {
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return "", err
	}
	quiet := *old
	quiet.Lflag &^= unix.ECHO
	quiet.Lflag |= unix.ICANON | unix.ISIG
	quiet.Iflag |= unix.ICRNL
	fmt.Fprint(os.Stderr, text)
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &quiet); err != nil {
		return "", err
	}
	// The echo comes back on Ctrl-C too
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		select {
		case <-sig:
			unix.IoctlSetTermios(fd, unix.TCSETS, old)
			fmt.Fprintln(os.Stderr)
			os.Exit(130)
		case <-done:
		}
	}()
	var line []byte
	buf := make([]byte, 256)
	for {
		n, rerr := unix.Read(fd, buf)
		if n > 0 {
			line = append(line, buf[:n]...)
		}
		if n <= 0 || rerr != nil || strings.Contains(string(line), "\n") {
			err = rerr
			break
		}
	}
	close(done)
	signal.Stop(sig)
	unix.IoctlSetTermios(fd, unix.TCSETS, old)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	s, _, _ := strings.Cut(string(line), "\n")
	return strings.TrimRight(s, "\r"), nil
}

// HandleToken generates an app token for a user, in weed's app tokens file
func HandleToken() {
	if len(os.Args) < 4 || os.Args[3] != "generate" {
		fmt.Println("Usage: weed utils token generate [options] <user>")
		fmt.Println("")
		fmt.Println("Generates an app token for the user, in weed's app tokens file (basic.app_tokens).")
		fmt.Println("weed utils token generate -h lists the options.")
		if len(os.Args) >= 4 && os.Args[3] != "-h" && os.Args[3] != "--help" {
			os.Exit(2)
		}
		return
	}
	file, from, args := credentialFlags("token generate", "<user>",
		"Generates an app token for the user, in weed's app tokens file (basic.app_tokens), and\n"+
			"prints it. The file keeps its owner, group and mode; a new one is of the group weed, 0640, if there is one (0600 otherwise).",
		"basic.app_tokens", func(c *config.Config) string { return c.AppTokensFile },
		os.Args[4:], 1, 1, nil)
	name := args[0]
	token := utils.GenerateAppToken()
	if err := utils.AddToken(file, name, token); err != nil {
		utilsExit(err)
	}
	fmt.Printf("Generated token for user '%s': %s\n", name, token)
	fmt.Printf("Token saved to %s; %s\n", describe(file, from), reloadHint)
}
