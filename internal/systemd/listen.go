package systemd

import (
	"fmt"
	"net"
	"os"
	"strconv"
)

// Socket activation: systemd (a .socket unit) listens on weed's ports, and passes the
// sockets to weed as file descriptors from 3 on (LISTEN_FDS). They stay open while
// weed restarts, so that clients wait in their queue instead of being refused.

const listenFDsStart = 3

// listenFDs is how many sockets systemd passed to this process
func listenFDs() int {
	if pid, err := strconv.Atoi(os.Getenv("LISTEN_PID")); err != nil || pid != os.Getpid() {
		return 0
	}
	n, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// Listeners takes the sockets that systemd passed, and unsets LISTEN_PID, LISTEN_FDS
// and LISTEN_FDNAMES: no one takes them again, and processes that weed starts do not
// get them (their descriptors are closed on exec from then on)
func Listeners() ([]net.Listener, error) {
	n := listenFDs()
	for _, v := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		os.Unsetenv(v)
	}
	return fileListeners(listenFDsStart, n)
}

func fileListeners(first, n int) ([]net.Listener, error) {
	var ls []net.Listener
	for fd := first; fd < first+n; fd++ {
		f := os.NewFile(uintptr(fd), "socket "+strconv.Itoa(fd))
		l, err := net.FileListener(f) // a duplicate, closed on exec
		f.Close()
		if err != nil {
			for _, l := range ls {
				l.Close()
			}
			return nil, fmt.Errorf("the socket that systemd passed as file descriptor %d (LISTEN_FDS) is not one to listen on: %w", fd, err)
		}
		ls = append(ls, l)
	}
	return ls, nil
}
