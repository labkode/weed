package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/labkode/weed/cmd/utils"
	"github.com/labkode/weed/internal/config"
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
			log.Fatal(err)
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
		log.Fatal(err)
	}

	// Set up logging
	if cfg.LogFile != "" {
		logFile, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
		if err != nil {
			log.Fatalf("Failed to open log file %s: %v", cfg.LogFile, err)
		}
		log.SetOutput(logFile)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Configuration validation failed: %v", err)
	}

	// Create and configure server
	srv := server.New(cfg)

	// Initialize server components
	if err := srv.Initialize(); err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}

	// Print startup information
	srv.LogStartupInfo()

	// Reload credentials on SIGHUP
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			srv.Reload()
		}
	}()

	// Serve until SIGINT/SIGTERM, then shut down gracefully
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
