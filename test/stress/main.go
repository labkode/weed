// Command stress finds the limits of a weed server, and of the machine it runs on
// (see internal/stress, and stress -h). weed limits runs it against a weed of its own.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/labkode/weed/internal/stress"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := stress.Main(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
