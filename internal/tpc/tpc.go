// Package tpc implements the active side of WLCG HTTP third-party copy (TPC).
//
// A client sends COPY to this server with either a Source header (pull: this server
// GETs the remote file and stores it locally) or a remote Destination header (push:
// this server PUTs a local file to the remote endpoint). The response is 202 Accepted
// followed by a stream of performance markers and a final "success:" or "failure:"
// line. Headers named TransferHeader<Name> are forwarded to the remote as <Name>.
//
// Data integrity follows https://github.com/labkode/wlcg-tpc: when the COPY carries a
// Repr-Digest (RFC 9530), a pull asks the source for the digest (Want-Repr-Digest),
// fails early if the source's value contradicts the client's, and always verifies the
// received data; a push forwards the Repr-Digest so the destination can verify it, and
// reports a 412 from the destination as a checksum mismatch.
package tpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/labkode/weed/internal/davfs"
	"github.com/labkode/weed/internal/digest"
	"github.com/labkode/weed/internal/metrics"
)

// Mode is the direction of a transfer
type Mode int

const (
	// Pull copies a remote file to this server
	Pull Mode = iota
	// Push copies a local file to a remote server
	Push
)

func (m Mode) String() string {
	if m == Push {
		return "push"
	}
	return "pull"
}

// LogValue logs a mode as String does, in every log format
func (m Mode) LogValue() slog.Value { return slog.StringValue(m.String()) }

// ErrChecksumMismatch is wrapped by the errors of transfers that failed because the
// data did not match the checksum given by the client
var ErrChecksumMismatch = errors.New("client/server checksum mismatch")

// Config tunes the TPC engine
type Config struct {
	// MarkerInterval is how often performance markers are sent
	MarkerInterval time.Duration
	// StallTimeout aborts a transfer that makes no progress for this long (0 disables)
	StallTimeout time.Duration
	// MaxTransfers bounds concurrent transfers; further requests get 503
	MaxTransfers int
	// AllowHTTP permits plain-text http:// remote endpoints
	AllowHTTP bool
	// AllowLocal permits remote endpoints on loopback and link-local addresses
	// (which include cloud metadata services); only enable it for testing
	AllowLocal bool
	// AllowPrivate permits remote endpoints on private and other non-global
	// addresses (RFC 1918, RFC 4193, shared address space), e.g. site-internal storage
	AllowPrivate bool
	// RootCAs verifies remote TLS endpoints; nil means the system roots
	RootCAs *x509.CertPool
}

// Job is one transfer
type Job struct {
	Mode Mode
	// Remote is the other endpoint
	Remote *url.URL
	// Local is the exported directory, opened for the request, and Name the file in
	// it (destination for Pull, source for Push)
	Local *davfs.Tree
	Name  string
	// Header is sent to the remote endpoint
	Header http.Header
	// Expected holds the digests the client asserted in Repr-Digest (may be empty)
	Expected digest.Set
	// ReprDigest is the client's Repr-Digest field, forwarded verbatim on push
	ReprDigest string
	// NoReplace makes a pull fail rather than replace an existing local file
	NoReplace bool
}

// Engine runs transfers
type Engine struct {
	cfg    Config
	client atomic.Pointer[http.Client]
	slots  chan struct{}
}

// New creates an engine
func New(cfg Config) *Engine {
	if cfg.MarkerInterval <= 0 {
		cfg.MarkerInterval = 5 * time.Second
	}
	if cfg.MaxTransfers <= 0 {
		cfg.MaxTransfers = 1
	}
	e := &Engine{
		cfg:   cfg,
		slots: make(chan struct{}, cfg.MaxTransfers),
	}
	e.client.Store(newClient(cfg))
	return e
}

// SetRootCAs makes new transfers verify remote endpoints with pool; transfers in
// progress are not affected
func (e *Engine) SetRootCAs(pool *x509.CertPool) {
	cfg := e.cfg
	cfg.RootCAs = pool
	if old := e.client.Swap(newClient(cfg)); old != nil {
		old.CloseIdleConnections()
	}
}

func newClient(cfg Config) *http.Client {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	if !cfg.AllowLocal || !cfg.AllowPrivate {
		// Checked on the resolved address at connect time, so redirects and DNS tricks are covered too
		policy := addressPolicy{allowLocal: cfg.AllowLocal, allowPrivate: cfg.AllowPrivate}
		dialer.Control = policy.control
	}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSClientConfig:       &tls.Config{RootCAs: cfg.RootCAs, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 5 * time.Minute,
		ExpectContinueTimeout: 5 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   4,
		// Files must be stored byte for byte; never ask for a transparently decoded encoding
		DisableCompression: true,
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			if req.Method != via[0].Method {
				return fmt.Errorf("refusing redirect that turns %s into %s", via[0].Method, req.Method)
			}
			if req.URL.Scheme != "https" && !cfg.AllowHTTP {
				return fmt.Errorf("refusing redirect to %s: plain http is not allowed", redact(req.URL))
			}
			return nil
		},
	}
}

// addressPolicy decides which addresses third-party copies may connect to, so that
// clients cannot use the server to reach services that are not exposed to them
type addressPolicy struct {
	allowLocal, allowPrivate bool
}

// thisNetwork (0.0.0.0/8) reaches the local host on some systems
var thisNetwork = netip.MustParsePrefix("0.0.0.0/8")

// nonGlobal are special-purpose ranges (RFC 6890) that netip does not classify
var nonGlobal = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),  // shared address space (carrier-grade NAT)
	netip.MustParsePrefix("192.0.0.0/24"),   // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"),  // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),    // reserved, including broadcast
	netip.MustParsePrefix("64:ff9b:1::/48"), // local-use IPv4/IPv6 translation
	netip.MustParsePrefix("2001:db8::/32"),  // documentation
	netip.MustParsePrefix("2001:2::/48"),    // benchmarking
	netip.MustParsePrefix("100::/64"),       // discard-only
	netip.MustParsePrefix("2001::/32"),      // Teredo, which embeds IPv4 addresses
	netip.MustParsePrefix("2002::/16"),      // 6to4, which embeds IPv4 addresses
	netip.MustParsePrefix("64:ff9b::/96"),   // NAT64, which embeds IPv4 addresses
}

func (p addressPolicy) allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || thisNetwork.Contains(ip) {
		return p.allowLocal
	}
	if ip.IsPrivate() {
		return p.allowPrivate
	}
	for _, n := range nonGlobal {
		if n.Contains(ip) {
			return p.allowPrivate
		}
	}
	return true
}

func (p addressPolicy) control(network, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return err
	}
	if !p.allowed(ap.Addr()) {
		return fmt.Errorf("connections to %s are not allowed for third-party copy", ap.Addr())
	}
	return nil
}

// ValidateRemote checks that a remote endpoint may be used
func (e *Engine) ValidateRemote(u *url.URL) error {
	if u.Scheme != "https" && !(u.Scheme == "http" && e.cfg.AllowHTTP) {
		return fmt.Errorf("scheme %q is not allowed for third-party copy", u.Scheme)
	}
	return nil
}

// hopByHop headers are never forwarded, whatever the client asks for
var hopByHop = map[string]bool{
	"Host": true, "Content-Length": true, "Transfer-Encoding": true, "Connection": true,
	"Te": true, "Trailer": true, "Upgrade": true, "Expect": true, "Keep-Alive": true,
	"Proxy-Connection": true,
}

// TransferHeaders returns the headers to send to the remote endpoint: every request
// header TransferHeader<Name> becomes <Name>
func TransferHeaders(in http.Header) http.Header {
	const prefix = "transferheader"
	out := http.Header{}
	for k, vs := range in {
		if len(k) <= len(prefix) || !strings.EqualFold(k[:len(prefix)], prefix) {
			continue
		}
		name := http.CanonicalHeaderKey(k[len(prefix):])
		if hopByHop[name] {
			continue
		}
		out[name] = append(out[name], vs...)
	}
	return out
}

// progress is shared between a transfer and the marker loop
type progress struct {
	counter atomic.Pointer[atomic.Int64] // replaced when a push is retried after a redirect
	remote  atomic.Value                 // string, the address of the remote peer
}

func (p *progress) bytes() int64 {
	if c := p.counter.Load(); c != nil {
		return c.Load()
	}
	return 0
}

// Reserve takes one of the MaxTransfers slots for a transfer, and returns the
// function that frees it. When none is free it answers 503 and returns false.
func (e *Engine) Reserve(w http.ResponseWriter) (release func(), ok bool) {
	select {
	case e.slots <- struct{}{}:
		return func() { <-e.slots }, true
	default:
		metrics.TPCRejected.Inc()
		w.Header().Set("Retry-After", "60")
		http.Error(w, "Too many concurrent third-party copies", http.StatusServiceUnavailable)
		return nil, false
	}
}

// Serve answers a TPC COPY: 202, performance markers, then the final status line.
// All checks that can be done synchronously must have been done by the caller.
func (e *Engine) Serve(w http.ResponseWriter, r *http.Request, job *Job) {
	release, ok := e.Reserve(w)
	if !ok {
		return
	}
	defer release()

	mode := job.Mode.String()
	metrics.TPCActive.Inc(mode)
	defer metrics.TPCActive.Dec(mode)

	ctx, cancel := context.WithCancelCause(r.Context())
	defer cancel(nil)
	p := &progress{}
	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- e.run(ctx, job, p) }()

	slog.InfoContext(r.Context(), "third-party copy started", "mode", job.Mode, "local", job.Name, "remote", redact(job.Remote))
	w.Header().Set("Content-Type", "text/perf-marker-stream")
	w.WriteHeader(http.StatusAccepted)
	rc := http.NewResponseController(w)
	rc.Flush()

	ticker := time.NewTicker(e.cfg.MarkerInterval)
	defer ticker.Stop()
	lastBytes, lastProgress := int64(0), time.Now()
	for {
		select {
		case err := <-done:
			n := p.bytes()
			metrics.TPCBytes.Add(n, mode)
			if err != nil {
				metrics.TPCTransfers.Inc(mode, "failure")
				if errors.Is(err, ErrChecksumMismatch) {
					metrics.ChecksumMismatches.Inc("tpc_" + mode)
				}
				davfs.NoteNoSpace(r.Context(), r.URL.Path, err)
				slog.WarnContext(r.Context(), "third-party copy failed", "mode", job.Mode, "bytes", n, "duration", time.Since(start), "error", err)
				fmt.Fprintf(w, "failure: %s\n", oneLine(err.Error()))
			} else {
				metrics.TPCTransfers.Inc(mode, "success")
				slog.InfoContext(r.Context(), "third-party copy completed", "mode", job.Mode, "bytes", n, "duration", time.Since(start))
				fmt.Fprint(w, "success: Created\n")
			}
			rc.Flush()
			return
		case now := <-ticker.C:
			n := p.bytes()
			if n != lastBytes {
				lastBytes, lastProgress = n, now
			} else if e.cfg.StallTimeout > 0 && now.Sub(lastProgress) >= e.cfg.StallTimeout {
				cancel(fmt.Errorf("transfer stalled: no data for %v", e.cfg.StallTimeout))
			}
			writeMarker(w, now, n, p)
			rc.Flush()
		}
	}
}

// writeMarker writes a performance marker in the format FTS/davix parse
func writeMarker(w io.Writer, now time.Time, n int64, p *progress) {
	fmt.Fprintf(w, "Perf Marker\n\tTimestamp: %d\n\tStripe Index: 0\n\tStripe Bytes Transferred: %d\n\tTotal Stripe Count: 1\n", now.Unix(), n)
	if remote, _ := p.remote.Load().(string); remote != "" {
		fmt.Fprintf(w, "\tRemoteConnections: tcp:%s\n", remote)
	}
	fmt.Fprint(w, "End\n")
}

func (e *Engine) run(ctx context.Context, job *Job, p *progress) error {
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			p.remote.Store(info.Conn.RemoteAddr().String())
		},
	})
	var err error
	if job.Mode == Push {
		err = e.push(ctx, job, p)
	} else {
		err = e.pull(ctx, job, p)
	}
	// Report why the transfer was cancelled (stall, shutdown) rather than "context canceled"
	if err != nil && ctx.Err() != nil {
		if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) {
			return cause
		}
	}
	return err
}

func (e *Engine) pull(ctx context.Context, job *Job, p *progress) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, job.Remote.String(), nil)
	if err != nil {
		return err
	}
	req.Header = job.Header.Clone()
	if len(job.Expected) > 0 {
		req.Header.Set("Want-Repr-Digest", digest.FormatWant(job.Expected.Algorithms()))
	}

	resp, err := e.client.Load().Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", redact(job.Remote), unwrapURLError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return remoteError("GET", job.Remote, resp)
	}
	// Without Content-Length or chunked framing a dropped connection looks like a
	// complete file, so such responses are refused
	if resp.ContentLength < 0 && !(len(resp.TransferEncoding) > 0 && resp.TransferEncoding[0] == "chunked") {
		return errors.New("source response has no Content-Length or chunked encoding; truncation would be undetectable")
	}
	// We never ask for an encoding, so anything but identity would be stored mangled
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
		return fmt.Errorf("source sent unrequested Content-Encoding %q", ce)
	}

	// If the source states a digest that contradicts the client, there is no point
	// in transferring the data (scenario a of the WLCG TPC data integrity spec)
	if len(job.Expected) > 0 {
		if src, _, err := digest.ParseReprDigest(resp.Header.Get("Repr-Digest")); err == nil {
			if alg, bad := digest.Mismatch(job.Expected, src); bad {
				return fmt.Errorf("file not saved: %w: source reports %s %x, client expects %x", ErrChecksumMismatch,
					alg, src[alg], job.Expected[alg])
			}
		}
	}

	af, err := job.Local.CreateAtomic(ctx, job.Name, 0666)
	if err != nil {
		return fmt.Errorf("cannot create local file: %w", err)
	}
	defer af.Abort()

	// adler32 is always computed: it is cheap and is the checksum WLCG asks for afterwards
	hasher := digest.NewHasher(append([]string{digest.Adler}, job.Expected.Algorithms()...)...)
	counter := new(atomic.Int64)
	p.counter.Store(counter)
	n, readErr, writeErr := digest.Copy(af, &countingReader{r: resp.Body, n: counter}, hasher)
	if writeErr != nil {
		return fmt.Errorf("writing local file after %d bytes: %w", n, writeErr)
	}
	if readErr != nil {
		return fmt.Errorf("reading from source after %d bytes: %w", n, readErr)
	}
	if resp.ContentLength >= 0 && n != resp.ContentLength {
		return fmt.Errorf("source sent %d bytes, expected %d", n, resp.ContentLength)
	}

	sums := hasher.Sums()
	if alg, bad := digest.Mismatch(job.Expected, sums); bad {
		return fmt.Errorf("file not saved: %w: received data has %s %x, client expects %x", ErrChecksumMismatch,
			alg, sums[alg], job.Expected[alg])
	}
	digest.Store(af.File, sums)
	commit := af.Commit
	if job.NoReplace {
		commit = af.CommitNoReplace
	}
	if err := commit(); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("file not saved: it was created during the transfer, and the token does not allow replacing it")
		}
		return fmt.Errorf("cannot store local file: %w", err)
	}
	return nil
}

func (e *Engine) push(ctx context.Context, job *Job, p *progress) error {
	f, err := job.Local.Open(ctx, job.Name)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	f.Close()
	if err != nil {
		return err
	}
	size := fi.Size()

	// Each attempt (the first PUT, and any retry after a 307/308 redirect) reads the
	// file afresh with its own counter and hasher
	type attempt struct {
		counter *atomic.Int64
		hasher  *digest.Hasher
		body    io.Closer
		done    chan struct{} // closed once the hasher has seen everything it will see
	}
	var last *attempt
	newBody := func() (io.ReadCloser, error) {
		f, err := job.Local.Open(ctx, job.Name)
		if err != nil {
			return nil, err
		}
		a := &attempt{counter: new(atomic.Int64), hasher: digest.NewHasher(job.Expected.Algorithms()...), done: make(chan struct{})}
		last = a
		p.counter.Store(a.counter)
		if len(job.Expected) == 0 {
			close(a.done)
			a.body = f
			return struct {
				io.Reader
				io.Closer
			}{&countingReader{r: f, n: a.counter}, f}, nil
		}
		// The file is read ahead and hashed while the transport sends what was read
		pr, pw := io.Pipe()
		go func() {
			defer close(a.done)
			defer f.Close()
			_, readErr, writeErr := digest.Copy(pw, f, a.hasher)
			if readErr != nil {
				pw.CloseWithError(readErr)
			} else {
				pw.CloseWithError(writeErr) // nil: the reader sees io.EOF
			}
		}()
		a.body = pr
		return struct {
			io.Reader
			io.Closer
		}{&countingReader{r: pr, n: a.counter}, pr}, nil
	}
	body, err := newBody()
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, job.Remote.String(), body)
	if err != nil {
		body.Close()
		return err
	}
	req.ContentLength = size
	req.GetBody = newBody
	req.Header = job.Header.Clone()
	if job.ReprDigest != "" {
		req.Header.Set("Repr-Digest", job.ReprDigest)
	}
	if size > 0 {
		// Learn about authorization failures and redirects before sending the data
		req.Header.Set("Expect", "100-continue")
	}

	resp, err := e.client.Load().Do(req)
	if err != nil {
		return fmt.Errorf("PUT %s: %w", redact(job.Remote), unwrapURLError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusPreconditionFailed && job.ReprDigest != "" {
		return fmt.Errorf("file not saved: %w reported by destination (412 Precondition Failed)", ErrChecksumMismatch)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return remoteError("PUT", job.Remote, resp)
	}

	// Closing the body stops the hasher from reading past what was sent (if the file
	// grew); once it is done it has seen every byte sent
	last.body.Close()
	<-last.done
	if sent := last.counter.Load(); sent != size {
		return fmt.Errorf("destination answered %s after %d of %d bytes", resp.Status, sent, size)
	}
	if alg, bad := digest.Mismatch(job.Expected, last.hasher.Sums()); bad {
		return fmt.Errorf("%w: source file does not match the client checksum for %s (the destination did not verify it)", ErrChecksumMismatch, alg)
	}
	return nil
}

type countingReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func remoteError(method string, u *url.URL, resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	msg := oneLine(string(b))
	if msg != "" {
		msg = ": " + msg
	}
	return fmt.Errorf("%s %s failed: %s%s", method, redact(u), resp.Status, msg)
}

// unwrapURLError drops the url.Error wrapper, whose message would repeat the full URL
func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// redact removes credentials that may be embedded in URLs (user info, query tokens)
func redact(u *url.URL) string {
	if u == nil {
		return ""
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String()
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
