package systemd

import "golang.org/x/sys/unix"

// ListenPorts are the TCP ports of the sockets that systemd passed, which it listens
// on for weed: weed looks at them without taking them, before it executes itself
// again (to be confined with Landlock), which they stay open across
func ListenPorts() []int {
	return socketPorts(listenFDsStart, listenFDs())
}

func socketPorts(first, n int) []int {
	var ports []int
	for fd := first; fd < first+n; fd++ {
		switch sa, _ := unix.Getsockname(fd); a := sa.(type) {
		case *unix.SockaddrInet4:
			ports = append(ports, a.Port)
		case *unix.SockaddrInet6:
			ports = append(ports, a.Port)
		}
	}
	return ports
}
