package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/labkode/weed/cmd/utils"
	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/logger"
	"github.com/labkode/weed/internal/server"
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

	cfg, err := config.FromArgs(os.Args[1:])
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
			if err := reopenLog(); err != nil {
				slog.Error("cannot reopen the log file, logging to the previous one", "file", cfg.LogFile, "error", err)
			}
			srv.Reload()
		}
	}()

	// Serve until SIGINT/SIGTERM, then shut down gracefully
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.Run(ctx); err != nil {
		logger.Fatal("cannot serve", err)
	}
}
