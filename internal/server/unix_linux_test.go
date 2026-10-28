//go:build linux

package server

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/fsuser"
	"github.com/labkode/weed/internal/metrics"
	"github.com/labkode/weed/internal/testutil"
	"golang.org/x/sys/unix"
)

// Run as root: make test-root, or go test -exec sudo -run 'UnixUsers|Worker' ./internal/server

// unixNode is a node with -unix-users, whose accounts are alice, bob and carol (who
// is also in group 6100); alice authenticates with her password, the others with tokens
type unixNode struct {
	*node
	iss *testutil.Issuer

	mu       sync.Mutex
	accounts map[string]*fsuser.User
}

func newUnixNode(t *testing.T, mod func(cfg *config.Config)) *unixNode {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (make test-root)")
	}
	n := &unixNode{iss: testutil.NewIssuer(t), accounts: map[string]*fsuser.User{
		"alice": {Name: "alice", UID: 6001, GID: 6001, Groups: []int{6001}},
		"bob":   {Name: "bob", UID: 6002, GID: 6002, Groups: []int{6002}},
		"carol": {Name: "carol", UID: 6003, GID: 6003, Groups: []int{6003, 6100}},
	}}
	issuers := n.iss.WriteIssuers(tokenAudience, "/")
	n.node = newNode(t, func(cfg *config.Config, _ string) {
		cfg.TokenIssuers = issuers
		cfg.TokenCAPath = n.iss.CAFile
		cfg.UnixUsers = true
		if mod != nil {
			mod(cfg)
		}
	})
	n.srv.AuthStore.LookupUnixUser = func(name string) (*fsuser.User, error) {
		n.mu.Lock()
		defer n.mu.Unlock()
		if u, ok := n.accounts[name]; ok {
			return u, nil
		}
		return nil, errors.New("no such account")
	}
	// The users must be able to reach the exported directory
	for p := n.dir; p != os.TempDir() && p != "/"; p = filepath.Dir(p) {
		os.Chmod(p, 0755)
	}
	return n
}

// as returns the headers that authenticate as user
func (n *unixNode) as(user string) []string {
	if user == "alice" {
		return nil
	}
	return bearer(n.iss.Token(tokenAudience, "storage.read:/ storage.modify:/", map[string]interface{}{"sub": user}))
}

func (n *unixNode) local(p string) string { return filepath.Join(n.dir, filepath.FromSlash(p)) }

// setup creates a file, or a directory if p ends with a slash
func (n *unixNode) setup(p string, mode os.FileMode, uid, gid int) {
	if strings.HasSuffix(p, "/") {
		os.Mkdir(n.local(p), mode)
	} else {
		os.WriteFile(n.local(p), []byte(p), mode)
	}
	os.Chmod(n.local(p), mode)
	os.Chown(n.local(p), uid, gid)
}

func (n *unixNode) owner(p string) [2]int {
	n.t.Helper()
	fi, err := os.Stat(n.local(p))
	if err != nil {
		n.t.Fatalf("%s: %v", p, err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	return [2]int{int(st.Uid), int(st.Gid)}
}

// workers returns the worker processes of this process by account, as ps shows them
func workers(t *testing.T) map[string][]int {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string][]int)
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || procStatus(pid)["PPid"] != strconv.Itoa(os.Getpid()) {
			continue
		}
		cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		args := strings.Split(strings.TrimSuffix(string(cmdline), "\x00"), "\x00")
		if len(args) == 3 && args[0] == "weed" && args[1] == "worker" {
			out[args[2]] = append(out[args[2]], pid)
		}
	}
	return out
}

// workerOf returns the pid of the only worker of an account
func workerOf(t *testing.T, name string) int {
	t.Helper()
	pids := workers(t)[name]
	if len(pids) != 1 {
		t.Fatalf("workers of %s: %v", name, pids)
	}
	return pids[0]
}

func procStatus(pid int) map[string]string {
	status, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	fields := make(map[string]string)
	for _, line := range strings.Split(string(status), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			fields[k] = strings.TrimSpace(v)
		}
	}
	return fields
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func TestUnixUsers(t *testing.T) {
	n := newUnixNode(t, nil)
	n.setup("/alice/", 0755, 6001, 6001)
	n.setup("/alice/private", 0600, 6001, 6001)
	n.setup("/alice/public", 0644, 6001, 6001)
	n.setup("/shared/", 0775, 6002, 6100)
	n.setup("/shared/bobs", 0644, 6002, 6100)
	n.setup("/shared/team", 0640, 6002, 6100)

	for _, c := range []struct {
		user, method, path string
		headers            []string
		want               int
	}{
		{"alice", "PUT", "/alice/new", nil, 201},
		{"alice", "MKCOL", "/alice/dir", nil, 201},
		{"alice", "COPY", "/alice/public", []string{"Destination", "/webdav/alice/copy"}, 201},
		{"bob", "GET", "/alice/public", nil, 200},
		{"bob", "GET", "/alice/private", nil, 403},
		{"bob", "PUT", "/alice/x", nil, 403},
		{"bob", "MKCOL", "/alice/d", nil, 403},
		{"bob", "DELETE", "/alice/public", nil, 403},
		{"bob", "MOVE", "/alice/public", []string{"Destination", "/webdav/shared/moved"}, 403},
		{"carol", "GET", "/shared/team", nil, 200}, // through a supplementary group
		{"alice", "GET", "/shared/team", nil, 403},
		{"carol", "PUT", "/shared/new", nil, 201},     // group-writable directory
		{"carol", "PUT", "/shared/bobs", nil, 403},    // ...but bob's file is not writable by carol
		{"mallory", "GET", "/alice/public", nil, 403}, // no account
		// A lock would keep the owner from writing
		{"bob", "LOCK", "/alice/public", nil, 403},
		{"bob", "LOCK", "/alice/", nil, 403},
		{"carol", "LOCK", "/shared/", nil, 200},
		{"alice", "LOCK", "/alice/public", nil, 200},
	} {
		headers := append(c.headers, n.as(c.user)...)
		body := ""
		switch c.method {
		case "PUT":
			body = c.user + "'s data"
		case "LOCK":
			body = `<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>`
		}
		if resp, msg := n.do(c.method, c.path, body, headers...); resp.StatusCode != c.want {
			t.Errorf("%s: %s %s = %d %q, want %d", c.user, c.method, c.path, resp.StatusCode, msg, c.want)
		}
	}
	for p, want := range map[string][2]int{
		"/alice/new": {6001, 6001}, "/alice/dir": {6001, 6001}, "/alice/copy": {6001, 6001},
		"/shared/new": {6003, 6003}, "/shared/bobs": {6002, 6100},
	} {
		if got := n.owner(p); got != want {
			t.Errorf("%s owned by %v, want %v", p, got, want)
		}
	}
	if content, _ := n.read("/shared/bobs"); content != "/shared/bobs" {
		t.Errorf("bob's file replaced: %q", content)
	}

	if _, body := n.do("GET", n.ts.URL+"/proc/whoami", ""); !strings.Contains(body, "Unix Account: alice (uid 6001") {
		t.Errorf("whoami: %q", body)
	}

	// Macaroons are minted by the front process, which has the secret, and act as
	// the account they were minted for
	macaroon, _ := n.mint("/alice/", `{"caveats": ["activity:DOWNLOAD,LIST"]}`)
	if code := n.status("GET", "/alice/private", "", bearer(macaroon)...); code != 200 {
		t.Errorf("GET with alice's macaroon: %d", code)
	}

	// Third-party copies access the local file as the user too
	remote := newNode(t, nil)
	remote.write("/f", "remote data")
	remoteAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(basicUser+":"+basicPass))
	code, body := copyTPC(t, n.node, "/alice/pulled", "Source", remote.url("/f"), "TransferHeaderAuthorization", remoteAuth)
	expectSuccess(t, code, body)
	if got := n.owner("/alice/pulled"); got != [2]int{6001, 6001} {
		t.Errorf("pulled file owned by %v", got)
	}
	code, body = copyTPC(t, n.node, "/alice/stolen", append([]string{"Source", remote.url("/f"), "TransferHeaderAuthorization", remoteAuth}, n.as("bob")...)...)
	expectFailure(t, code, body, "permission denied")

	code, body = copyTPC(t, n.node, "/alice/private", "Destination", remote.url("/pushed"), "TransferHeaderAuthorization", remoteAuth)
	expectSuccess(t, code, body)
	if content, _ := remote.read("/pushed"); content != "/alice/private" {
		t.Errorf("pushed %q", content)
	}
	code, body = copyTPC(t, n.node, "/alice/private", append([]string{"Destination", remote.url("/leaked"), "TransferHeaderAuthorization", remoteAuth}, n.as("bob")...)...)
	expectFailure(t, code, body, "permission denied")
	if _, ok := remote.read("/leaked"); ok {
		t.Error("bob pushed alice's private file")
	}
}

// Each account's requests are served by a process of its own, which runs as the
// account and with no privileges
func TestWorkerProcesses(t *testing.T) {
	n := newUnixNode(t, nil)
	n.setup("/alice/", 0755, 6001, 6001)
	n.setup("/shared/", 0775, 6002, 6100)
	n.setup("/shared/bobs", 0644, 6002, 6100)

	uploaded := metrics.UploadBytes.Get()
	if code := n.status("PUT", "/alice/f", strings.Repeat("x", 1000)); code != 201 {
		t.Fatalf("PUT as alice: %d", code)
	}
	if code := n.status("PROPFIND", "/shared/", "", append(n.as("carol"), "Depth", "1")...); code != 207 {
		t.Fatalf("PROPFIND as carol: %d", code)
	}
	for _, u := range []*fsuser.User{n.accounts["alice"], n.accounts["carol"]} {
		status := procStatus(workerOf(t, u.Name))
		id := strconv.Itoa(u.UID)
		gid := strconv.Itoa(u.GID)
		if got := strings.Fields(status["Uid"]); !slices.Equal(got, []string{id, id, id, id}) {
			t.Errorf("%s: uids %v", u.Name, got)
		}
		if got := strings.Fields(status["Gid"]); !slices.Equal(got, []string{gid, gid, gid, gid}) {
			t.Errorf("%s: gids %v", u.Name, got)
		}
		var want []string
		for _, g := range u.Groups {
			want = append(want, strconv.Itoa(g))
		}
		if got := strings.Fields(status["Groups"]); !slices.Equal(got, want) {
			t.Errorf("%s: groups %v, want %v", u.Name, got, want)
		}
		for _, set := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
			if status[set] != "0000000000000000" {
				t.Errorf("%s: %s %s", u.Name, set, status[set])
			}
		}
		if status["NoNewPrivs"] != "1" || status["Name"] != "weed" {
			t.Errorf("%s: no_new_privs %s, name %q", u.Name, status["NoNewPrivs"], status["Name"])
		}
		// None of weed's environment, which may hold secrets
		environ, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", workerOf(t, u.Name)))
		if err != nil {
			t.Errorf("cannot read the environment of %s's worker (needs CAP_SYS_PTRACE): %v", u.Name, err)
		}
		for _, v := range strings.Split(strings.TrimSuffix(string(environ), "\x00"), "\x00") {
			if k, _, _ := strings.Cut(v, "="); !slices.Contains([]string{"PATH", "TZ", "SSL_CERT_FILE", "SSL_CERT_DIR", "GODEBUG", "GOGC", "GOMAXPROCS", "GOMEMLIMIT", "GOTRACEBACK"}, k) {
				t.Errorf("%s: environment has %q", u.Name, k)
			}
		}
	}

	// Workers report their metrics to the front process
	eventually(t, "the upload to be counted", func() bool { return metrics.UploadBytes.Get()-uploaded == 1000 })

	// Clients cannot state what the front process states to workers: bob may create
	// files but not replace them, whatever he claims
	createOnly := bearer(n.iss.Token(tokenAudience, "storage.read:/ storage.create:/", map[string]interface{}{"sub": "bob"}))
	forged := append(createOnly, "X-Weed-Identity", `{"username":"bob","method":"token"}`)
	if code := n.status("PUT", "/shared/bobs", "replaced", forged...); code != 403 {
		t.Errorf("replacing with a forged identity: %d", code)
	}
	if content, _ := n.read("/shared/bobs"); content != "/shared/bobs" {
		t.Errorf("bob's file replaced: %q", content)
	}
	if code := n.status("PUT", "/shared/bobs-new", "new", forged...); code != 201 {
		t.Errorf("creating: %d", code)
	}

	// Workers check that they run as their account with no privileges, and refuse to
	// serve otherwise: here as root, which fsuser.Lookup would not return
	n.mu.Lock()
	n.accounts["toor"] = &fsuser.User{Name: "toor", UID: 0, GID: 0, Groups: []int{0}}
	n.mu.Unlock()
	if code := n.status("GET", "/alice/f", "", n.as("toor")...); code != 503 {
		t.Errorf("worker running as root: %d", code)
	}
}

func TestWorkerLifecycle(t *testing.T) {
	n := newUnixNode(t, nil)
	n.setup("/alice/", 0755, 6001, 6001)
	n.setup("/shared/", 0775, 6002, 6100)
	n.setup("/shared/team", 0640, 6002, 6100)
	get := func(user, p string) int { return n.status("GET", p, "", n.as(user)...) }

	// A worker that dies is replaced on the next request
	if code := n.status("PUT", "/alice/f", "data"); code != 201 {
		t.Fatalf("PUT: %d", code)
	}
	pid := workerOf(t, "alice")
	failed := metrics.WorkerExits.Get("failed")
	syscall.Kill(pid, syscall.SIGKILL)
	eventually(t, "the failure to be noticed", func() bool { return metrics.WorkerExits.Get("failed") == failed+1 })
	if code := get("alice", "/alice/f"); code != 200 {
		t.Errorf("GET after the worker died: %d", code)
	}
	if workerOf(t, "alice") == pid {
		t.Error("the killed worker is still there")
	}

	// SIGHUP is for the front process (pkill -HUP weed reaches workers too)
	pid = workerOf(t, "alice")
	syscall.Kill(pid, syscall.SIGHUP)
	time.Sleep(50 * time.Millisecond)
	if code := get("alice", "/alice/f"); code != 200 || workerOf(t, "alice") != pid {
		t.Errorf("after SIGHUP: %d", code)
	}

	// Reloading keeps the workers (and the locks they hold)
	if code := get("carol", "/shared/team"); code != 200 {
		t.Fatalf("carol: %d", code)
	}
	pid = workerOf(t, "carol")
	n.srv.Reload()
	if code := get("carol", "/shared/team"); code != 200 || workerOf(t, "carol") != pid {
		t.Errorf("after reloading: %d", code)
	}

	// An account that changed gets a new worker once it is looked up again (after a
	// minute, or a reload): carol has left group 6100
	pid = workerOf(t, "carol")
	n.mu.Lock()
	n.accounts["carol"] = &fsuser.User{Name: "carol", UID: 6003, GID: 6003, Groups: []int{6003}}
	n.mu.Unlock()
	n.srv.AuthStore.ForgetUnixUsers()
	if code := get("carol", "/shared/team"); code != 403 {
		t.Errorf("carol after leaving the group: %d", code)
	}
	eventually(t, "carol's worker to be replaced", func() bool {
		pids := workers(t)["carol"]
		return len(pids) == 1 && pids[0] != pid
	})
	if groups := procStatus(workerOf(t, "carol"))["Groups"]; groups != "6003" {
		t.Errorf("carol's new worker is in groups %q", groups)
	}
}

func TestWorkerIdleTimeout(t *testing.T) {
	n := newUnixNode(t, func(cfg *config.Config) { cfg.WorkerIdleTimeout = 200 * time.Millisecond })
	n.setup("/alice/", 0755, 6001, 6001)
	if code := n.status("PUT", "/alice/f", "data"); code != 201 {
		t.Fatalf("PUT: %d", code)
	}
	eventually(t, "the idle worker to stop", func() bool { return len(workers(t)["alice"]) == 0 })
	if code := n.status("GET", "/alice/f", ""); code != 200 {
		t.Errorf("GET after the worker stopped: %d", code)
	}
}

func TestMaxWorkers(t *testing.T) {
	n := newUnixNode(t, func(cfg *config.Config) { cfg.MaxWorkers = 1 })
	n.setup("/alice/", 0755, 6001, 6001)

	// alice keeps her worker busy with an upload she is still sending
	body, send := io.Pipe()
	req, _ := http.NewRequest("PUT", n.url("/alice/slow"), body)
	req.SetBasicAuth(basicUser, basicPass)
	req.ContentLength = 10
	done := make(chan int, 1)
	go func() {
		resp, err := n.ts.Client().Do(req)
		if err != nil {
			done <- 0
			return
		}
		resp.Body.Close()
		done <- resp.StatusCode
	}()
	send.Write([]byte("12345"))
	eventually(t, "alice's worker", func() bool { return len(workers(t)["alice"]) == 1 })

	propfind := func() int { return n.status("PROPFIND", "/", "", append(n.as("bob"), "Depth", "0")...) }
	if code := propfind(); code != 503 {
		t.Errorf("bob while alice's worker is busy: %d", code)
	}
	send.Write([]byte("67890"))
	send.Close()
	if code := <-done; code != 201 {
		t.Errorf("alice's upload: %d", code)
	}
	// alice's worker is idle now, and makes room
	if code := propfind(); code != 207 {
		t.Errorf("bob once alice's worker is idle: %d", code)
	}
	eventually(t, "alice's worker to stop", func() bool { return len(workers(t)["alice"]) == 0 })
}

// A worker that is replaced finishes its requests in progress, then stops
func TestWorkerReplacedDuringRequest(t *testing.T) {
	n := newUnixNode(t, nil)
	n.setup("/alice/", 0755, 6001, 6001)
	body, send := io.Pipe()
	req, _ := http.NewRequest("PUT", n.url("/alice/slow"), body)
	req.SetBasicAuth(basicUser, basicPass)
	req.ContentLength = 10
	done := make(chan int, 1)
	go func() {
		resp, err := n.ts.Client().Do(req)
		if err != nil {
			done <- 0
			return
		}
		resp.Body.Close()
		done <- resp.StatusCode
	}()
	send.Write([]byte("12345"))
	eventually(t, "alice's worker", func() bool { return len(workers(t)["alice"]) == 1 })
	pid := workerOf(t, "alice")

	// alice joins a group, so her next request goes to a new worker
	n.mu.Lock()
	n.accounts["alice"] = &fsuser.User{Name: "alice", UID: 6001, GID: 6001, Groups: []int{6001, 6100}}
	n.mu.Unlock()
	n.srv.AuthStore.ForgetUnixUsers()
	if code := n.status("PROPFIND", "/alice/", "", "Depth", "0"); code != 207 {
		t.Errorf("PROPFIND as alice: %d", code)
	}
	send.Write([]byte("67890"))
	send.Close()
	if code := <-done; code != 201 {
		t.Errorf("upload across the replacement: %d", code)
	}
	if content, _ := n.read("/alice/slow"); content != "1234567890" {
		t.Errorf("stored %q", content)
	}
	eventually(t, "the replaced worker to stop", func() bool {
		return !slices.Contains(workers(t)["alice"], pid)
	})
}

// TestWorkerCgroups rearranges the cgroups of the machine it runs on, as a service
// manager delegating a cgroup to weed would: run it in a container (make test-cgroups)
func TestWorkerCgroups(t *testing.T) {
	if os.Getenv("WEED_TEST_CGROUPS") == "" {
		t.Skip("rearranges the machine's cgroups: run in a container with make test-cgroups")
	}
	cgroupOf := func(pid int) string {
		data, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
		return strings.TrimSpace(strings.TrimPrefix(string(data), "0::"))
	}
	own := cgroupOf(os.Getpid())
	parent := filepath.Join("/sys/fs/cgroup", own)
	// Controllers can only be enabled below a cgroup without processes
	os.Mkdir(filepath.Join(parent, "init"), 0755)
	procs, _ := os.ReadFile(filepath.Join(parent, "cgroup.procs"))
	for _, pid := range strings.Fields(string(procs)) {
		os.WriteFile(filepath.Join(parent, "init", "cgroup.procs"), []byte(pid), 0)
	}
	if err := os.WriteFile(filepath.Join(parent, "cgroup.subtree_control"), []byte("+memory +pids"), 0); err != nil {
		t.Fatal(err)
	}
	delegated := filepath.Join(parent, "weed")
	os.Mkdir(delegated, 0755)
	if err := os.WriteFile(filepath.Join(delegated, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
		t.Fatal(err)
	}

	n := newUnixNode(t, func(cfg *config.Config) {
		cfg.WorkerCgroupLimits = []string{"pids.max=64", "memory.max=256M"}
		cfg.WorkerIdleTimeout = 500 * time.Millisecond
	})
	n.setup("/alice/", 0755, 6001, 6001)
	if code := n.status("PUT", "/alice/f", "data"); code != 201 {
		t.Fatalf("PUT: %d", code)
	}
	if got, want := cgroupOf(os.Getpid()), filepath.Join(own, "weed", "main"); got != want {
		t.Errorf("weed is in %s, want %s", got, want)
	}
	if got, want := cgroupOf(workerOf(t, "alice")), filepath.Join(own, "weed", "worker-alice"); got != want {
		t.Errorf("alice's worker is in %s, want %s", got, want)
	}
	dir := filepath.Join(delegated, "worker-alice")
	for file, want := range map[string]string{"pids.max": "64", "memory.max": "268435456"} {
		if got, _ := os.ReadFile(filepath.Join(dir, file)); strings.TrimSpace(string(got)) != want {
			t.Errorf("%s = %q, want %s", file, got, want)
		}
	}
	// The cgroup goes with the worker
	eventually(t, "the cgroup to be removed", func() bool {
		_, err := os.Stat(dir)
		return errors.Is(err, os.ErrNotExist)
	})
}

// -tpc-max-transfers bounds the third-party copies of all accounts together
func TestWorkersShareTPCLimit(t *testing.T) {
	n := newUnixNode(t, func(cfg *config.Config) { cfg.TPCMaxTransfers = 1 })
	n.setup("/alice/", 0755, 6001, 6001)
	n.setup("/bob/", 0755, 6002, 6002)
	// The first copy hangs until released, others complete at once
	var requests atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			close(started)
			<-release
		}
		io.WriteString(w, "data")
	}))
	defer src.Close()

	done := make(chan int, 1)
	go func() {
		code, _ := copyTPC(t, n.node, "/alice/f", "Source", src.URL+"/f")
		done <- code
	}()
	<-started
	if code, body := copyTPC(t, n.node, "/bob/f", append([]string{"Source", src.URL + "/f"}, n.as("bob")...)...); code != 503 {
		t.Errorf("bob's copy while alice's runs: %d %q", code, body)
	}
	close(release)
	if code := <-done; code != 202 {
		t.Errorf("alice's copy: %d", code)
	}
}

// weed may run as an unprivileged account with only CAP_SETUID and CAP_SETGID, as
// systemd's AmbientCapabilities= gives them; its workers must not inherit them
func TestWorkersOfUnprivilegedFront(t *testing.T) {
	if os.Getenv("WEED_TEST_FRONT") == "" {
		if os.Geteuid() != 0 {
			t.Skip("needs root (make test-root)")
		}
		// Run this test again as uid 6009 with those capabilities
		cmd := exec.Command("/proc/self/exe", "-test.run=^TestWorkersOfUnprivilegedFront$", "-test.v")
		cmd.Env = append(os.Environ(), "WEED_TEST_FRONT=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential:  &syscall.Credential{Uid: 6009, Gid: 6009, Groups: []uint32{6009}},
			AmbientCaps: []uintptr{unix.CAP_SETUID, unix.CAP_SETGID},
		}
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "--- PASS: TestWorkersOfUnprivilegedFront") {
			t.Fatalf("as uid 6009: %v\n%s", err, out)
		}
		return
	}

	if status := procStatus(os.Getpid()); status["Uid"] != "6009\t6009\t6009\t6009" || status["CapAmb"] != "00000000000000c0" {
		t.Fatalf("not running as intended: uid %q, ambient capabilities %q", status["Uid"], status["CapAmb"])
	}
	n := newNode(t, func(cfg *config.Config, _ string) { cfg.UnixUsers = true })
	n.srv.AuthStore.LookupUnixUser = func(name string) (*fsuser.User, error) {
		return &fsuser.User{Name: "alice", UID: 6001, GID: 6001, Groups: []int{6001}}, nil
	}
	for p := n.dir; p != os.TempDir() && p != "/"; p = filepath.Dir(p) {
		os.Chmod(p, 0755)
	}
	os.Chmod(n.dir, 0777)
	if code := n.status("PUT", "/f", "data"); code != 201 {
		t.Fatalf("PUT: %d", code)
	}
	fi, err := os.Stat(filepath.Join(n.dir, "f"))
	if err != nil || fi.Sys().(*syscall.Stat_t).Uid != 6001 {
		t.Fatalf("file not created by alice's worker: %v", err)
	}
	status := procStatus(workerOf(t, "alice"))
	for _, set := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
		if status[set] != "0000000000000000" {
			t.Errorf("alice's worker has capabilities: %s %s", set, status[set])
		}
	}
}

// Workers verify TPC endpoints with the CAs as they are after a reload
func TestWorkersReloadTPCCAs(t *testing.T) {
	src := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "4")
		io.WriteString(w, "data")
	}))
	defer src.Close()
	caFile := writePEM(t, testutil.NewCA(t, testutil.Name(t, "CN=Unrelated")).Cert.Raw)
	// The users read the CAs
	for p := caFile; p != os.TempDir() && p != "/"; p = filepath.Dir(p) {
		os.Chmod(p, 0755)
	}
	os.Chmod(caFile, 0644)

	n := newUnixNode(t, func(cfg *config.Config) { cfg.TPCCAPath = caFile })
	n.setup("/alice/", 0755, 6001, 6001)
	code, body := copyTPC(t, n.node, "/alice/a", "Source", src.URL+"/f")
	expectFailure(t, code, body, "certificate")
	pid := workerOf(t, "alice")

	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: src.Certificate().Raw}), 0644)
	n.srv.Reload()
	eventually(t, "the worker to reload", func() bool {
		code, body = copyTPC(t, n.node, "/alice/b", "Source", src.URL+"/f")
		return code == 202 && finalLine(body) == "success: Created"
	})
	if workerOf(t, "alice") != pid {
		t.Error("the worker was replaced")
	}
}

// BenchmarkWorkers compares serving files directly with handing requests to a worker:
//
//	WEED_BENCH_MIB=1024 go test -exec sudo ./internal/server -run '^$' -bench Workers -benchtime 3x
func BenchmarkWorkers(b *testing.B) {
	size := benchSize(b)
	for _, mode := range []string{"direct", "worker"} {
		var n *node
		if mode == "worker" {
			if os.Geteuid() != 0 {
				b.Skip("needs root")
			}
			n = newNode(b, func(cfg *config.Config, _ string) { cfg.UnixUsers = true })
			n.srv.AuthStore.LookupUnixUser = func(string) (*fsuser.User, error) {
				return &fsuser.User{Name: "alice", UID: 6001, GID: 6001, Groups: []int{6001}}, nil
			}
			for p := n.dir; p != os.TempDir() && p != "/"; p = filepath.Dir(p) {
				os.Chmod(p, 0755)
			}
			os.Chmod(n.dir, 0777) // alice writes
		} else {
			n = newNode(b, nil)
		}
		f, _ := os.Create(n.dir + "/f")
		io.Copy(f, &patternReader{n: size})
		f.Close()
		os.Chmod(n.dir+"/f", 0644)
		b.Run(mode+"/PUT", func(b *testing.B) {
			b.SetBytes(size)
			for b.Loop() {
				req, _ := http.NewRequest("PUT", n.url("/put"), &patternReader{n: size})
				req.ContentLength = size
				req.SetBasicAuth(basicUser, basicPass)
				send(b, n.ts.Client(), req, 201, 204)
			}
		})
		b.Run(mode+"/GET", func(b *testing.B) {
			b.SetBytes(size)
			for b.Loop() {
				req, _ := http.NewRequest("GET", n.url("/f"), nil)
				req.SetBasicAuth(basicUser, basicPass)
				send(b, n.ts.Client(), req, 200)
			}
		})
	}
}
