// Package admin is weed's control plane: an HTTP API, with JSON bodies, on a Unix
// socket that only root and weed's own user can use. weed utils talks to it (ban,
// unban, bans, status); the routes are versioned (/v1/...), so that operations can be
// added without breaking clients.
package admin

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/labkode/weed/internal/bans"
)

// BanRequest is the (optional) body of PUT /v1/bans/{user}
type BanRequest struct {
	Reason string `json:"reason,omitempty"`
}

// BanResult answers PUT /v1/bans/{user}
type BanResult struct {
	bans.Ban
	Added         bool   `json:"added"`             // false if the user was banned already (Ban is that ban)
	WorkersKilled int    `json:"workers_killed"`    // the user's worker processes, stopped at once
	Warning       string `json:"warning,omitempty"` // e.g. the ban could not be saved
}

// UnbanResult answers DELETE /v1/bans/{user}
type UnbanResult struct {
	User    string `json:"user"`
	Removed bool   `json:"removed"` // false if the user was not banned
	Warning string `json:"warning,omitempty"`
}

// Bans answers GET /v1/bans
type Bans struct {
	Bans []bans.Ban `json:"bans"`
}

// Error is the body of answers other than 2xx
type Error struct {
	Error string `json:"error"`
}

// Peer is the process at the other end of a connection to the socket
type Peer struct {
	UID, PID int
}

func (p Peer) String() string {
	if p.PID == 0 {
		return fmt.Sprintf("uid %d", p.UID)
	}
	return fmt.Sprintf("uid %d, pid %d", p.UID, p.PID)
}

// LogValue logs a peer as String does, in every log format
func (p Peer) LogValue() slog.Value { return slog.StringValue(p.String()) }

// Listen creates the socket at path, in a directory that only its owner can enter
// if it has to create it, and accepts connections from root and this process's
// user only. A socket left by a weed that died is replaced; one that a running
// weed listens on is not.
func Listen(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&fs.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close()
			return nil, fmt.Errorf("%s is in use, by another weed?", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return &listener{ln}, nil
}

// allowed says whether a user may use the control plane
func allowed(uid int) bool { return uid == 0 || uid == os.Geteuid() }

type listener struct{ *net.UnixListener }

// Accept returns the next connection from an allowed user; the others are closed
func (l *listener) Accept() (net.Conn, error) {
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		peer, err := peerOf(c)
		if err != nil || !allowed(peer.UID) {
			slog.Warn("refused a connection to the admin socket", "peer", peer, "error", err)
			c.Close()
			continue
		}
		return &conn{c, peer}, nil
	}
}

type conn struct {
	*net.UnixConn
	peer Peer
}

type peerKey struct{}

// ConnContext gives the requests of a connection its peer (see PeerOf); it is the
// http.Server's ConnContext
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	if c, ok := c.(*conn); ok {
		return context.WithValue(ctx, peerKey{}, c.peer)
	}
	return ctx
}

// PeerOf returns who sent a request to the control plane
func PeerOf(ctx context.Context) Peer {
	p, _ := ctx.Value(peerKey{}).(Peer)
	return p
}

var errNoPeerCredentials = errors.New("cannot tell who connects to a Unix socket on this system")
