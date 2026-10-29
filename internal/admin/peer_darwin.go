package admin

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerOf returns the user of the process that connected c (LOCAL_PEERCRED)
func peerOf(c *net.UnixConn) (Peer, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Peer{UID: -1}, err
	}
	var cred *unix.Xucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return Peer{UID: -1}, err
	}
	if credErr != nil {
		return Peer{UID: -1}, credErr
	}
	return Peer{UID: int(cred.Uid)}, nil
}
