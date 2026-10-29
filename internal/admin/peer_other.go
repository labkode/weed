//go:build !linux && !darwin

package admin

import "net"

// peerOf cannot tell who connected here: every connection is refused
func peerOf(*net.UnixConn) (Peer, error) { return Peer{UID: -1}, errNoPeerCredentials }
