//go:build linux

// weed builds and runs on Linux alone
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/labkode/weed/cmd/utils"
	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/findlimits"
	"github.com/labkode/weed/internal/logger"
	"github.com/labkode/weed/internal/server"
	"github.com/labkode/weed/internal/systemd"
	"github.com/labkode/weed/internal/version"
	"golang.org/x/sys/unix"
)

// weed executes itself again as /proc/self/exe, confined, and so its starter of
// workers: the kernel names them "exe". They take the name of weed's command again,
// so that ps -C weed, pgrep -x weed and top show them. Init runs on the main thread,
// whose name is the process's.
//
// The main goroutine keeps the main thread, so that no other goroutine runs there:
// some confine their thread and end with it (the starter's, as it starts a worker,
// keeps CAP_SETUID and CAP_SETGID alone, and Landlock's rules), and Go cannot end the
// main thread, which would stay so. The kernel shows the main thread's credentials as
// the process's (/proc/PID/status).
func init() {
	runtime.LockOSThread()
	if name := filepath.Base(os.Args[0]); name != "" && name != "." && name != "/" {
		if b, err := unix.BytePtrFromString(name); err == nil {
			unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(b)), 0, 0, 0)
			runtime.KeepAlive(b)
		}
	}
}

func main() {
	// Check for utility commands
	if len(os.Args) > 1 && os.Args[1] == "utils" {
		utils.HandleUtilsCommand(os.Args)
		return
	}
	// The starter of workers, which weed starts before it gives up its privileges
	if len(os.Args) > 1 && os.Args[1] == "starter" {
		if err := server.RunStarter(); err != nil {
			if !errors.Is(err, server.ErrReported) {
				fmt.Fprintln(os.Stderr, "weed starter:", err)
			}
			os.Exit(1)
		}
		return
	}
	// Worker processes, which weed starts to access files as Unix accounts
	if len(os.Args) > 1 && os.Args[1] == "worker" {
		if err := server.RunWorker(); err != nil {
			logger.Fatal("worker failed", err)
		}
		return
	}

	// Print a configuration file with every option
	if len(os.Args) > 1 && os.Args[1] == "config" {
		fmt.Print(config.Example())
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Print(version.Current().Text())
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "check" {
		os.Exit(check(os.Args[2:]))
	}
	// What weed can serve on this machine, and the settings that would let it serve more
	if len(os.Args) > 1 && os.Args[1] == "limits" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		code := findlimits.Main(ctx, os.Args[2:], os.Stdout, os.Stderr)
		stop()
		os.Exit(code)
	}

	cfg, src, err := config.FromArgs(os.Args[1:])
	switch {
	case errors.Is(err, flag.ErrHelp):
		return
	case errors.Is(err, config.ErrUsage):
		os.Exit(2)
	case err != nil:
		logger.Fatal("cannot read the configuration", err)
	}
	if err := cfg.Validate(); err != nil {
		logger.Fatal("invalid configuration", err)
	}
	level, _ := cfg.Level()
	reopenLog, err := logger.Setup(logger.Options{Level: level, Format: cfg.LogFormat, File: cfg.LogFile})
	if err != nil {
		logger.Fatal("cannot open the log file", err)
	}

	// Starts the starter of workers, then executes weed again without privileges,
	// confined with Landlock
	if err := server.Confine(cfg, src); err != nil {
		logger.Fatal("cannot confine weed with Landlock", err)
	}

	srv := server.New(cfg)
	srv.SetSource(src)
	srv.MonitorOnMainPort = src.Path == "" // no metrics_address without a file
	if err := srv.Initialize(); err != nil {
		logger.Fatal("cannot start", err)
	}

	// Print startup information
	srv.LogStartupInfo()

	// Reopen the log file (for logrotate) and reload credentials on SIGHUP
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			systemd.Reloading()
			if err := reopenLog(); err != nil {
				slog.Error("cannot reopen the log file, logging to the previous one", "file", cfg.LogFile, "error", err)
			}
			srv.Reload()
			systemd.Ready(srv.StatusLine())
		}
	}()

	// Serve until SIGINT/SIGTERM, then shut down gracefully
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.Run(ctx); err != nil {
		logger.Fatal("cannot serve", err)
	}
}

// check reports whether weed would start with the configuration that args name,
// without serving: it reads and checks everything weed does at startup, and prints
// the problems and warnings weed would log. It returns the exit status.
func check(args []string) int {
	args, as, err := cutAs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "weed check:", err)
		return 2
	}
	cfg, src, err := config.FromArgs(args)
	switch {
	case errors.Is(err, flag.ErrHelp):
		return 0
	case errors.Is(err, config.ErrUsage):
		return 2
	case err == nil:
		err = cfg.Validate()
	}
	if err == nil {
		slog.SetDefault(slog.New(logger.NewHandler(os.Stderr, logger.FormatText, slog.LevelWarn)))
		srv := server.New(cfg)
		if err = srv.Check(); err == nil {
			srv.LogStartupInfo() // its warnings
		}
	}
	name := src.Path
	if name == "" {
		name = "weed"
		for i, a := range args {
			if strings.TrimLeft(a, "-") == "config" && i+1 < len(args) {
				name = args[i+1]
			} else if v, ok := strings.CutPrefix(strings.TrimLeft(a, "-"), "config="); ok {
				name = v
			}
		}
	}
	if err != nil {
		// Errors about the file name it already
		fmt.Fprintf(os.Stderr, "weed would not start with %s: %s\n", name, strings.TrimPrefix(err.Error(), name+": "))
		return 1
	}
	if src.Path == "" {
		fmt.Println("weed would start with the default configuration (no -config)")
		return 0
	}
	account, why, ok, out := checkAs(args, as, src.Path)
	if !ok {
		fmt.Fprintf(os.Stderr, "weed would start with %s as root, but not as the account %s that it runs as (%s):\n%s", src.Path, account, why, out)
		return 1
	}
	if account != "" {
		fmt.Printf("%s: weed would start with it (sha256 %s), as the account %s too (%s)\n", src.Path, src.SHA256, account, why)
	} else {
		fmt.Printf("%s: weed would start with it (sha256 %s)\n", src.Path, src.SHA256)
	}
	return 0
}
