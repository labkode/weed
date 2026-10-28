package main

import (
	"context"
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

	// Parse configuration
	cfg := config.ParseFlags()

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

	// Serve until SIGINT/SIGTERM, then shut down gracefully
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
