package utils

import (
	"fmt"
	"os"

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
		HandleToken()
	case "ban":
		HandleBan()
	case "unban":
		HandleUnban()
	case "bans":
		HandleBans()
	default:
		fmt.Printf("Unknown utils command: %s\n", args[2])
		PrintHelp()
	}
}

// PrintHelp prints the utils help
func PrintHelp() {
	fmt.Println("Usage: weed utils <command>")
	fmt.Println("")
	fmt.Println("Available commands:")
	fmt.Println("  cert     - Generate TLS certificates")
	fmt.Println("  password - Set or remove a user's password (basic.htpasswd)")
	fmt.Println("  token    - Generate an app token for a user (basic.app_tokens)")
	fmt.Println("")
	fmt.Println("Commands of a running weed, through its control plane (admin.socket):")
	fmt.Println("  ban      - Ban a user: refuse its requests, stop its worker processes")
	fmt.Println("  unban    - Lift the ban of a user")
	fmt.Println("  bans     - List the banned users")
	fmt.Println("")
	fmt.Println("weed utils <command> -h describes a command.")
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
