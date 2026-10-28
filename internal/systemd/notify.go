// Package systemd tells systemd about the state of the service (sd_notify), so that
// systemctl status shows it: weed is ready once it listens, reloads on SIGHUP (and
// says when it is done), and stops. It does nothing unless systemd set NOTIFY_SOCKET,
// as it does for Type=notify and Type=notify-reload services.
package systemd

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// Ready says that the service is up, with a status line for systemctl status
func Ready(status string) { notify("READY=1\nSTATUS=" + oneLine(status)) }

// Status replaces the status line
func Status(status string) { notify("STATUS=" + oneLine(status)) }

// Reloading says that a reload has started; Ready says when it is done
func Reloading() {
	state := "RELOADING=1"
	if usec, ok := monotonicUsec(); ok {
		// Type=notify-reload needs to know which reload this is
		state += fmt.Sprintf("\nMONOTONIC_USEC=%d", usec)
	}
	notify(state)
}

// Stopping says that the service is shutting down
func Stopping() { notify("STOPPING=1") }

func oneLine(s string) string { return strings.ReplaceAll(s, "\n", " ") }

// notify sends state to systemd. Failures are ignored: the service runs the same
// without systemd knowing.
func notify(state string) error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
	}
	if socket[0] == '@' { // abstract namespace
		socket = "\x00" + socket[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}
