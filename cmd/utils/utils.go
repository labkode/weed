package utils

import (
	"fmt"
	"os"

	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/utils"
)

// HandleUtilsCommand handles the utils command line interface
func HandleUtilsCommand(args []string) {
	if len(args) < 3 {
		PrintHelp()
		return
	}

	switch args[2] {
	case "cert":
		HandleCert()
	case "password":
		HandlePassword()
	case "token":
		// For token operations, we'll use a minimal config
		cfg := &config.Config{}
		HandleToken(cfg)
	default:
		fmt.Printf("Unknown utils command: %s\n", args[2])
		PrintHelp()
	}
}

// HandleCommand handles the utils command with a provided config
func HandleCommand(cfg *config.Config) {
	if len(os.Args) < 3 {
		PrintHelp()
		return
	}

	switch os.Args[2] {
	case "cert":
		HandleCert()
	case "password":
		HandlePassword()
	case "token":
		HandleToken(cfg)
	default:
		fmt.Printf("Unknown utils command: %s\n", os.Args[2])
		PrintHelp()
	}
}

// PrintHelp prints the utils help
func PrintHelp() {
	fmt.Println("Usage: weed utils <command>")
	fmt.Println("")
	fmt.Println("Available commands:")
	fmt.Println("  cert     - Generate TLS certificates")
	fmt.Println("  password - Generate password hashes")
	fmt.Println("  token    - Manage application tokens")
}

// HandleCert handles certificate generation
func HandleCert() {
	if len(os.Args) > 3 && (os.Args[3] == "-h" || os.Args[3] == "--help") {
		fmt.Println("Usage: weed utils cert")
		fmt.Println("")
		fmt.Println("Generates server.crt and server.key for TLS")
		return
	}

	if err := utils.GenerateTLSCertificates(); err != nil {
		fmt.Printf("Error generating certificates: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Generated server.crt and server.key")
}

// HandlePassword handles password hash generation
func HandlePassword() {
	if len(os.Args) < 5 || (len(os.Args) > 3 && (os.Args[3] == "-h" || os.Args[3] == "--help")) {
		fmt.Println("Usage: weed utils password <username> <password>")
		fmt.Println("")
		fmt.Println("Generates a bcrypt hash and appends to .htpasswd file")
		return
	}

	username := os.Args[3]
	password := os.Args[4]

	if err := utils.AddUserToHtpasswd(username, password); err != nil {
		fmt.Printf("Error adding user: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Added user '%s' to .htpasswd\n", username)
}

// HandleToken handles token management
func HandleToken(cfg *config.Config) {
	if len(os.Args) < 4 {
		fmt.Println("Usage: weed utils token <generate|list|revoke>")
		return
	}

	switch os.Args[3] {
	case "generate":
		HandleTokenGenerate(cfg)
	default:
		fmt.Println("Usage: weed utils token <generate>")
	}
}

// HandleTokenGenerate handles token generation
func HandleTokenGenerate(cfg *config.Config) {
	if len(os.Args) < 5 {
		fmt.Println("Usage: weed utils token generate <username>")
		return
	}

	username := os.Args[4]
	token := utils.GenerateAppToken()
	
	if err := utils.AddTokenToFile(cfg.AppTokensFile, username, token); err != nil {
		fmt.Printf("Error generating token: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated token for user '%s': %s\n", username, token)
	fmt.Printf("Token saved to %s\n", cfg.AppTokensFile)
}
