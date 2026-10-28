package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/labkode/weed/cmd/utils"
	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/logger"
	"github.com/labkode/weed/internal/server"
	"github.com/labkode/weed/internal/systemd"
	"github.com/labkode/weed/internal/version"
)

func main() {
	// Check for utility commands
	if len(os.Args) > 1 && os.Args[1] == "utils" {
		utils.HandleUtilsCommand(os.Args)
		return
	}
	// Worker processes, started by weed with unix_users enabled
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

	srv := server.New(cfg)
	srv.SetSource(src)
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
	} else {
		fmt.Printf("%s: weed would start with it (sha256 %s)\n", src.Path, src.SHA256)
	}
	return 0
}
