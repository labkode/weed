package admin

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerOf returns the credentials of the process that connected c (SO_PEERCRED)
func peerOf(c *net.UnixConn) (Peer, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Peer{UID: -1}, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return Peer{UID: -1}, err
	}
	if credErr != nil {
		return Peer{UID: -1}, credErr
	}
	return Peer{UID: int(cred.Uid), PID: int(cred.Pid)}, nil
}
