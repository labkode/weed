package admin

import (
	"bufio"
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// dialAs connects to a Unix socket from a thread whose effective user is uid, which
// is what the server sees (SO_PEERCRED)
func dialAs(t *testing.T, path string, uid int) net.Conn {
	t.Helper()
	type result struct {
		fd  int
		err error
	}
	ch := make(chan result)
	go func() {
		runtime.LockOSThread() // the thread exits with the goroutine, and its credentials
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			ch <- result{-1, err}
			return
		}
		// This thread only (unix.Setresuid would change every thread)
		if _, _, e := unix.RawSyscall(unix.SYS_SETRESUID, ^uintptr(0), uintptr(uid), ^uintptr(0)); e != 0 {
			ch <- result{-1, e}
			return
		}
		err = unix.Connect(fd, &unix.SockaddrUnix{Name: path})
		ch <- result{fd, err}
	}()
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	f := os.NewFile(uintptr(r.fd), "admin")
	defer f.Close()
	c, err := net.FileConn(f)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// Only root and this process's user may use the control plane, even if the socket's
// permissions let others connect
func TestPeers(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (make test-root)")
	}
	var log lockedBuffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&log, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	path := socketPath(t)
	serve(t, path)
	os.Chmod(filepath.Dir(filepath.Dir(path)), 0o755)
	os.Chmod(filepath.Dir(path), 0o755)
	os.Chmod(path, 0o666)

	request := func(c net.Conn) (string, error) {
		defer c.Close()
		c.Write([]byte("GET / HTTP/1.1\r\nHost: weed\r\nConnection: close\r\n\r\n"))
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b), nil
	}
	if body, err := request(dialAs(t, path, 0)); err != nil || !strings.Contains(body, "uid 0, pid ") {
		t.Errorf("root: %q, %v", body, err)
	}
	if body, err := request(dialAs(t, path, 65534)); err == nil {
		t.Errorf("nobody got an answer: %q", body)
	}
	if !strings.Contains(log.String(), `msg="refused a connection to the admin socket" peer="uid 65534, pid `) {
		t.Errorf("logged:\n%s", log.String())
	}
}
