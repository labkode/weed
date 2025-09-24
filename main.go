package main

import (
	"log"
	"os"

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

	// Create and configure server
	srv := server.New(cfg)

	// Initialize server components
	if err := srv.Initialize(); err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}

	// Print startup information
	srv.LogStartupInfo()

	// Start server
	if err := srv.Start(); err != nil {
		log.Fatal(err)
	}
}
