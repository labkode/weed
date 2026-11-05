package handlers

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/labkode/weed/internal/auth"
	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/davfs"
	"github.com/labkode/weed/internal/davreq"
	"github.com/labkode/weed/internal/digest"
	"github.com/labkode/weed/internal/logger"
	"github.com/labkode/weed/internal/metrics"
	"github.com/labkode/weed/internal/tpc"
	"github.com/labkode/weed/internal/x509utils"
	"golang.org/x/net/webdav"
)

const (
	defaultMaxValidity  = 24 * time.Hour
	maxMacaroonRequest  = 64 << 10
	supportedAlgorithms = "adler (adler32), crc32c, md5, sha, sha-256, sha-512"
)

// WebDAVHandler wraps the webdav.Handler with custom functionality
type WebDAVHandler struct {
	*webdav.Handler
	Directory string
	Config    *config.Config
	AuthStore *auth.AuthStore
	FS        davfs.FS
	// TPC runs third-party copies; nil when TPC is disabled
	TPC *tpc.Engine
}

// NewWebDAVHandler creates a new WebDAV handler
func NewWebDAVHandler(directory string, cfg *config.Config, authStore *auth.AuthStore) *WebDAVHandler {
	fs := davfs.FS{Root: directory, Gate: davfs.NewGate(cfg.WorkerMaxStorageCalls)}
	webdavHandler := &webdav.Handler{
		Prefix:     davreq.Prefix, // Set prefix to /webdav so hrefs are generated correctly
		LockSystem: webdav.NewMemLS(),
		// FileSystem: each request's own (serveDAV)
		Logger: func(r *http.Request, err error) {
			if err == nil {
				return
			}
			// Missing and existing files are the clients' business, and so are the
			// requests that their clients left
			level := slog.LevelInfo
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrExist) || clientGone(err) {
				level = slog.LevelDebug
			}
			slog.Log(r.Context(), level, "WebDAV request failed", "method", r.Method, "path", r.URL.Path, "error", err)
		},
	}

	return &WebDAVHandler{
		Handler:   webdavHandler,
		Directory: directory,
		Config:    cfg,
		AuthStore: authStore,
		FS:        fs,
	}
}

// ServeHTTP serves the WebDAV namespace, after authentication. It runs in the worker
// process of the identity's Unix account (see internal/worker).
func (h *WebDAVHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Encoded dot segments survive ServeMux path cleaning; never serve them
	if !davreq.IsClean(r.URL.Path) {
		slog.WarnContext(r.Context(), "non-canonical path refused", "path", r.URL.Path)
		http.Error(w, "Non-canonical path", http.StatusBadRequest)
		return
	}
	// The exported directory, opened for this request: no name leads out of it
	tree, err := h.FS.Open(r.Context())
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			http.Error(w, "Permission denied", http.StatusForbidden)
			return
		}
		if clientGone(err) {
			// It waited for the storage (davfs.Gate) until its client went
			slog.DebugContext(r.Context(), "a request ended before calling the storage", "error", err)
			http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
			return
		}
		slog.ErrorContext(r.Context(), "cannot open the exported directory", "dir", h.FS.Root, "error", err)
		http.Error(w, "The exported directory is not available", http.StatusServiceUnavailable)
		return
	}
	defer tree.Close()
	if !h.usesAsDirectories(w, r, tree) {
		return
	}

	// Macaroon minting requests (POST with application/macaroon-request content-type)
	if davreq.IsMacaroonRequest(r) {
		h.handleMacaroonRequest(w, r)
		return
	}

	switch r.Method {
	case "PROPFIND":
		// Reject infinite depth PROPFIND requests (an absent Depth means infinity)
		depth := r.Header.Get("Depth")
		if depth == "infinity" || depth == "" {
			slog.InfoContext(r.Context(), "PROPFIND with infinite depth refused", "path", r.URL.Path)
			http.Error(w, "Infinite depth PROPFIND requests are not allowed", http.StatusForbidden)
			return
		}
		h.handlePropfind(w, r, tree)
		return
	case http.MethodPut:
		h.handlePut(w, r, tree)
		return
	case http.MethodGet, http.MethodHead:
		h.addDigestHeaders(w, r, tree)
		h.serveFile(w, r, tree)
		return
	case http.MethodPost:
		h.serveFile(w, r, tree) // as x/net/webdav does
		return
	case "COPY", "MOVE":
		h.handleCopyMove(w, r, tree)
		return
	case "UNLOCK", "LOCK":
		if !h.lockTokenInScope(w, r) {
			return
		}
		if r.Method == "LOCK" && !h.mayLock(w, r, tree) {
			return
		}
	}

	h.serveDAV(w, r, tree)
}

// mayLock refuses to lock an existing resource that the user cannot write: the lock
// would keep those who can from writing it. A LOCK that creates the resource needs
// permission to create it.
func (h *WebDAVHandler) mayLock(w http.ResponseWriter, r *http.Request, tree *davfs.Tree) bool {
	if info, ok := auth.GetAuthInfoFromContext(r.Context()); !ok || info.Unix == nil {
		return true // tests that serve files as this process's user
	}
	name, ok := davreq.Strip(r.URL.Path)
	if !ok {
		return true
	}
	if _, err := tree.Stat(r.Context(), name); err == nil {
		if err := tree.Writable(r.Context(), name); err != nil {
			http.Error(w, "Permission denied", http.StatusForbidden)
			return false
		}
	}
	return true
}

// serveFile answers GET, HEAD and POST of a file as x/net/webdav does, with
// http.ServeContent (ranges, conditional requests), but for its Content-Type, from
// its name's extension alone: ServeContent would read the first 512 bytes of a file
// without one it knows. A directory, or anything but a regular file, gets 405: the
// file is opened without blocking, as a FIFO's open would until it has a writer (see
// davfs.Tree.Open). The extension's type is the system's (shared-mime-info, or
// /etc/mime.types), or Go's.
func (h *WebDAVHandler) serveFile(w http.ResponseWriter, r *http.Request, tree *davfs.Tree) {
	name, ok := davreq.Strip(r.URL.Path)
	if !ok {
		h.davError(w, r, http.StatusNotFound, errors.New("outside the WebDAV namespace"))
		return
	}
	f, err := tree.Open(r.Context(), name)
	if errors.Is(err, davfs.ErrNotRegular) {
		h.davError(w, r, http.StatusMethodNotAllowed, nil)
		return
	}
	if err != nil {
		h.fsError(w, r, err, http.StatusNotFound)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		h.fsError(w, r, err, http.StatusNotFound)
		return
	}
	w.Header().Set("ETag", etagFor(fi))
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", contentType(name))
	}
	http.ServeContent(w, r, name, fi.ModTime(), f)
}

// serveDAV hands the request to x/net/webdav, on tree, turning the 404, 405, 409 and
// 500 it answers when the filesystem refuses an operation into 403
func (h *WebDAVHandler) serveDAV(w http.ResponseWriter, r *http.Request, tree *davfs.Tree) {
	dw := &deniedWriter{ResponseWriter: w}
	dav := *h.Handler
	dav.FileSystem = tree
	dav.ServeHTTP(dw, r.WithContext(davfs.TrackDenied(r.Context(), &dw.denied)))
}

type deniedWriter struct {
	http.ResponseWriter
	denied    atomic.Bool
	rewritten bool
}

func (d *deniedWriter) WriteHeader(code int) {
	switch code {
	case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusConflict, http.StatusInternalServerError:
		if d.denied.Load() {
			d.rewritten = true
			d.ResponseWriter.Header().Set("Content-Type", "text/plain; charset=utf-8")
			d.ResponseWriter.WriteHeader(http.StatusForbidden)
			d.ResponseWriter.Write([]byte("Permission denied\n"))
			return
		}
	}
	d.ResponseWriter.WriteHeader(code)
}

func (d *deniedWriter) Write(b []byte) (int, error) {
	if d.rewritten {
		return len(b), nil // the text of the original status
	}
	return d.ResponseWriter.Write(b)
}

func (d *deniedWriter) Unwrap() http.ResponseWriter { return d.ResponseWriter }

const errNoOverwrite = "The token allows creating this file, not replacing it (storage.create without storage.modify)"

const errOnlyDirectory = "The token allows this path as a directory only (its scope ends in /), and it is not one"

// usesAsDirectories enforces AuthInfo.Directories: these paths are covered by token
// scopes naming them as directories, so each must be a directory or not exist, and
// the request may only create a directory there (MKCOL, or COPY/MOVE of a directory).
// A concurrent request could still swap a directory for a file in between, but only
// with credentials that cover the file.
func (h *WebDAVHandler) usesAsDirectories(w http.ResponseWriter, r *http.Request, tree *davfs.Tree) bool {
	info, ok := auth.GetAuthInfoFromContext(r.Context())
	if !ok || len(info.Directories) == 0 {
		return true
	}
	stat := func(urlPath string) (os.FileInfo, error) {
		name, _ := davreq.Strip(urlPath)
		return tree.Stat(r.Context(), name)
	}
	for _, d := range info.Directories {
		// A path that cannot be stat'ed cannot be used either: the request fails by itself
		fi, err := stat(d)
		if err == nil && !fi.IsDir() || err != nil && r.Method == "LOCK" { // locking a missing resource creates an empty file
			http.Error(w, errOnlyDirectory, http.StatusForbidden)
			return false
		}
		if r.Method == "COPY" || r.Method == "MOVE" {
			// The destination becomes what the source is
			if t, err := davreq.ParseTarget(r); err == nil && t.Kind == davreq.CopyLocal && t.Local == d {
				if src, err := stat(path.Clean(r.URL.Path)); err == nil && !src.IsDir() {
					http.Error(w, errOnlyDirectory, http.StatusForbidden)
					return false
				}
			}
		}
	}
	return true
}

// mayNotOverwrite reports whether the request's credentials only allow writing
// files that do not exist yet
func mayNotOverwrite(r *http.Request) bool {
	info, ok := auth.GetAuthInfoFromContext(r.Context())
	return ok && info.NoOverwrite
}

// etagFor matches the ETags generated by x/net/webdav for the same file
func etagFor(fi os.FileInfo) string {
	mt := fi.ModTime()
	return string(appendETag(nil, mt.Unix(), int64(mt.Nanosecond()), fi.Size()))
}

func etagListContains(list, etag string) bool {
	for _, e := range strings.Split(list, ",") {
		if strings.TrimPrefix(strings.TrimSpace(e), "W/") == etag {
			return true
		}
	}
	return false
}

// putPreconditionsHold evaluates If-Match / If-None-Match for a PUT
func putPreconditionsHold(r *http.Request, exists bool, etag string) bool {
	if inm := strings.TrimSpace(r.Header.Get("If-None-Match")); inm != "" && exists {
		if inm == "*" || etagListContains(inm, etag) {
			return false
		}
	}
	if im := strings.TrimSpace(r.Header.Get("If-Match")); im != "" {
		if !exists || (im != "*" && !etagListContains(im, etag)) {
			return false
		}
	}
	return true
}

// expectedDigests reads the client's Repr-Digest. A malformed value is a 400 and a
// value with no supported algorithm is a 406; in both cases the response is written.
func expectedDigests(w http.ResponseWriter, r *http.Request) (digest.Set, string, bool) {
	values := r.Header.Values("Repr-Digest")
	if len(values) == 0 {
		return nil, "", true
	}
	raw := strings.Join(values, ", ")
	set, unsupported, err := digest.ParseReprDigest(raw)
	if err != nil {
		http.Error(w, "Invalid Repr-Digest: "+err.Error(), http.StatusBadRequest)
		return nil, "", false
	}
	if len(set) == 0 {
		msg := "Repr-Digest contains no supported algorithm"
		if len(unsupported) > 0 {
			msg += " (got " + strings.Join(unsupported, ", ") + ")"
		}
		http.Error(w, msg+"; supported: "+supportedAlgorithms, http.StatusNotAcceptable)
		return nil, "", false
	}
	return set, raw, true
}

// handlePut stores uploads atomically: the data goes to a temporary file that is
// verified against any Repr-Digest and only then renamed into place
func (h *WebDAVHandler) handlePut(w http.ResponseWriter, r *http.Request, tree *davfs.Tree) {
	ctx := r.Context()
	name, ok := davreq.Strip(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("Content-Range") != "" {
		http.Error(w, "Partial PUT (Content-Range) is not supported", http.StatusBadRequest)
		return
	}
	expected, _, ok := expectedDigests(w, r)
	if !ok {
		return
	}
	if !davfs.Valid(name) {
		http.NotFound(w, r)
		return
	}

	release, status, err := h.confirmLocks(r, name)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	defer release()

	fi, statErr := tree.Stat(ctx, name)
	exists := statErr == nil
	if exists && fi.IsDir() {
		http.Error(w, "Cannot PUT to a collection", http.StatusMethodNotAllowed)
		return
	}
	etag := ""
	if exists {
		etag = etagFor(fi)
	}
	if !putPreconditionsHold(r, exists, etag) {
		http.Error(w, "Precondition failed", http.StatusPreconditionFailed)
		return
	}
	noOverwrite := mayNotOverwrite(r)
	if exists && noOverwrite {
		http.Error(w, errNoOverwrite, http.StatusForbidden)
		return
	}

	af, err := tree.CreateAtomic(ctx, name, 0666)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Parent collection does not exist", http.StatusConflict)
			return
		}
		slog.ErrorContext(ctx, "cannot create the upload's temporary file", "path", r.URL.Path, "error", err)
		http.Error(w, "Cannot create file", http.StatusForbidden)
		return
	}
	defer af.Abort()

	// adler32 is always computed: it is cheap and is the checksum WLCG asks for afterwards
	hasher := digest.NewHasher(append([]string{digest.Adler}, expected.Algorithms()...)...)
	n, readErr, writeErr := digest.Copy(af, r.Body, hasher)
	if writeErr != nil {
		slog.ErrorContext(ctx, "cannot write an upload", "path", r.URL.Path, "bytes", n, "error", writeErr)
		http.Error(w, "Failed to store file", http.StatusInternalServerError)
		return
	}
	if readErr != nil {
		slog.WarnContext(ctx, "upload aborted", "path", r.URL.Path, "bytes", n, "error", readErr)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	sums := hasher.Sums()
	if alg, bad := digest.Mismatch(expected, sums); bad {
		slog.WarnContext(ctx, "upload does not match its Repr-Digest", "path", r.URL.Path, "algorithm", alg,
			"expected", fmt.Sprintf("%x", expected[alg]), "received", fmt.Sprintf("%x", sums[alg]))
		metrics.ChecksumMismatches.Inc("put")
		http.Error(w, fmt.Sprintf("File not saved: client/server checksum mismatch (%s)", alg), http.StatusPreconditionFailed)
		return
	}
	digest.Store(af.File, sums)
	newFi, err := af.Stat()
	if err == nil && noOverwrite {
		err = af.CommitNoReplace()
		if errors.Is(err, os.ErrExist) {
			http.Error(w, errNoOverwrite, http.StatusForbidden)
			return
		}
	} else if err == nil {
		err = af.Commit()
	}
	if errors.Is(err, fs.ErrNotExist) {
		// Its collection was removed (DELETE, MOVE) while it was being written, with
		// the temporary file in it: a conflict between requests, not a fault of weed
		slog.WarnContext(ctx, "upload's collection removed while it was written", "path", r.URL.Path, "error", err)
		http.Error(w, "The parent collection was removed during the upload", http.StatusConflict)
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "cannot store an upload", "path", r.URL.Path, "error", err)
		http.Error(w, "Failed to store file", http.StatusInternalServerError)
		return
	}

	slog.DebugContext(ctx, "stored an upload", "path", r.URL.Path, "bytes", n, "adler32", fmt.Sprintf("%x", sums[digest.Adler]))
	metrics.UploadBytes.Add(n)
	w.Header().Set("ETag", etagFor(newFi))
	w.Header().Set("Repr-Digest", digest.FormatReprDigest(sums))
	if exists {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
}

// addDigestHeaders answers Want-Repr-Digest (RFC 9530) and Want-Digest (RFC 3230)
// on GET and HEAD; the body is then served by the WebDAV handler
func (h *WebDAVHandler) addDigestHeaders(w http.ResponseWriter, r *http.Request, tree *davfs.Tree) {
	want := digest.ParseWant(r.Header.Get("Want-Repr-Digest"))
	legacy := digest.ParseWantLegacy(r.Header.Get("Want-Digest"))
	if len(want) == 0 && len(legacy) == 0 {
		return
	}
	name, ok := davreq.Strip(r.URL.Path)
	if !ok {
		return
	}
	// Only a regular file is opened: opening a FIFO waits for a writer
	f, err := tree.Open(r.Context(), name)
	if err != nil {
		return
	}
	defer f.Close()

	// Digests are computed while files are written (PUT, TPC pull), never to answer a
	// read: the answer is the most preferred of those stored, if any is
	sums, err := digest.Stored(f, slices.Concat(want, legacy))
	if err != nil {
		slog.ErrorContext(r.Context(), "cannot read the stored digests", "path", r.URL.Path, "error", err)
		return
	}
	found := false
	if alg, ok := firstStored(want, sums); ok {
		w.Header().Set("Repr-Digest", digest.FormatReprDigest(digest.Set{alg: sums[alg]}))
		found = true
	}
	if alg, ok := firstStored(legacy, sums); ok {
		w.Header().Set("Digest", digest.FormatLegacy(alg, sums[alg]))
		found = true
	}
	if !found {
		slog.InfoContext(r.Context(), "no stored digest of the algorithms asked for: weed did not write the file, or it has changed since",
			"path", r.URL.Path, "algorithms", slices.Concat(want, legacy))
	}
}

// firstStored returns the first of algs that sums has
func firstStored(algs []string, sums digest.Set) (string, bool) {
	for _, alg := range algs {
		if _, ok := sums[alg]; ok {
			return alg, true
		}
	}
	return "", false
}

// handleCopyMove serves third-party copies itself and hands local COPY/MOVE to the
// WebDAV handler after normalizing the request
func (h *WebDAVHandler) handleCopyMove(w http.ResponseWriter, r *http.Request, tree *davfs.Tree) {
	target, err := davreq.ParseTarget(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if target.Kind != davreq.CopyLocal {
		h.handleTPC(w, r, target, tree)
		return
	}

	src := path.Clean(r.URL.Path)
	if target.Local == src {
		http.Error(w, "Destination equals source", http.StatusForbidden)
		return
	}
	// Copying or moving a collection into itself would recurse or fail half way
	if strings.HasPrefix(target.Local, src+"/") {
		http.Error(w, "Destination is inside the source collection", http.StatusForbidden)
		return
	}

	// x/net/webdav compares Destination hosts literally and would reject equivalent
	// spellings (default port, letter case); give it the already validated path
	r.Header.Set("Destination", (&url.URL{Path: target.Local}).String())
	if r.Method == "MOVE" && r.Header.Get("Overwrite") == "" {
		// RFC 4918 section 10.6: an absent Overwrite means T; x/net/webdav assumes F for MOVE
		r.Header.Set("Overwrite", "T")
	}
	if mayNotOverwrite(r) {
		if name, ok := davreq.Strip(target.Local); ok {
			if _, err := tree.Lstat(r.Context(), name); err == nil {
				http.Error(w, errNoOverwrite, http.StatusForbidden)
				return
			}
		}
		r.Header.Set("Overwrite", "F") // x/net/webdav checks again just before writing
	}
	h.serveDAV(w, r, tree)
}

// handleTPC validates a third-party copy request and hands it to the TPC engine
func (h *WebDAVHandler) handleTPC(w http.ResponseWriter, r *http.Request, target davreq.Target, tree *davfs.Tree) {
	if h.TPC == nil {
		http.Error(w, "Third-party copy is not enabled on this server", http.StatusNotImplemented)
		return
	}
	if err := h.TPC.ValidateRemote(target.Remote); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if cred := r.Header.Get("Credential"); cred != "" && !strings.EqualFold(cred, "none") {
		http.Error(w, fmt.Sprintf("Credential %q is not supported: credential delegation is not available; use Credential: none with TransferHeaderAuthorization", cred),
			http.StatusNotImplemented)
		return
	}
	expected, reprDigest, ok := expectedDigests(w, r)
	if !ok {
		return
	}
	name, ok := davreq.Strip(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !davfs.Valid(name) {
		http.NotFound(w, r)
		return
	}

	job := &tpc.Job{
		Remote:     target.Remote,
		Local:      tree,
		Name:       name,
		Header:     tpc.TransferHeaders(r.Header),
		Expected:   expected,
		ReprDigest: reprDigest,
	}
	fi, statErr := tree.Stat(r.Context(), name)
	if errors.Is(statErr, fs.ErrPermission) {
		http.Error(w, "Permission denied", http.StatusForbidden)
		return
	}

	if target.Kind == davreq.CopyPull {
		job.Mode = tpc.Pull
		if statErr == nil && fi.IsDir() {
			http.Error(w, "Cannot copy a file onto a collection", http.StatusMethodNotAllowed)
			return
		}
		if statErr == nil && r.Header.Get("Overwrite") == "F" {
			http.Error(w, "Destination exists and Overwrite is F", http.StatusPreconditionFailed)
			return
		}
		job.NoReplace = mayNotOverwrite(r)
		if statErr == nil && job.NoReplace {
			http.Error(w, errNoOverwrite, http.StatusForbidden)
			return
		}
		if _, err := tree.Stat(r.Context(), path.Dir(path.Clean("/"+name))); err != nil {
			http.Error(w, "Parent collection does not exist", http.StatusConflict)
			return
		}
		// Hold the destination for the whole transfer so WebDAV writers cannot interleave
		release, status, err := h.confirmLocks(r, name)
		if err != nil {
			http.Error(w, err.Error(), status)
			return
		}
		defer release()
	} else {
		job.Mode = tpc.Push
		if statErr != nil {
			http.NotFound(w, r)
			return
		}
		if !fi.Mode().IsRegular() {
			http.Error(w, "Only files can be pushed", http.StatusMethodNotAllowed)
			return
		}
	}

	h.TPC.Serve(w, r, job)
}

// IndexHandler serves the server info page with authenticated user info
func (h *WebDAVHandler) IndexHandler(w http.ResponseWriter, r *http.Request) {
	// Only serve the index page for the exact root path "/"
	// Return 404 for all other paths to prevent catch-all behavior
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Build the main page content without authentication status
	var authMethodsSection string

	// Generate authentication methods section - only show enabled methods
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	baseURL := html.EscapeString(fmt.Sprintf("%s://%s", scheme, r.Host))

	var authLinks []string
	var accessExamples []string

	// Only show links for enabled authentication methods
	if h.Config.BasicAuth {
		authLinks = append(authLinks, `<li><a href="/auth/basic">Basic Authentication</a> - Use username/password</li>`)
		accessExamples = append(accessExamples, fmt.Sprintf(`<li>curl with basic auth: curl -u user:pass %s/webdav/</li>`, baseURL))
	}

	if h.Config.X509Auth && h.Config.TLS {
		authLinks = append(authLinks, `<li><a href="/auth/x509">X.509 Certificate</a> - Use client certificate</li>`)
		accessExamples = append(accessExamples, fmt.Sprintf(`<li>curl with cert: curl --cert client.crt --key client.key %s/webdav/</li>`, baseURL))
	}

	if h.Config.OIDCAuth {
		authLinks = append(authLinks, `<li><a href="/auth/oidc">Get a token</a> - Log in at the identity provider for a WLCG token, to use with any client</li>`)
	}

	// Build the authentication methods section
	authMethodsSection = ""
	if len(authLinks) > 0 {
		authMethodsSection += "<h3>Authentication Methods</h3>\n<ul>\n"
		for _, link := range authLinks {
			authMethodsSection += link + "\n"
		}
		authMethodsSection += "</ul>\n"
	}

	// Build the WebDAV access section
	if len(accessExamples) > 0 {
		authMethodsSection += "<h3>WebDAV Access</h3>\n<ul>\n"
		for _, example := range accessExamples {
			authMethodsSection += example + "\n"
		}
		authMethodsSection += "</ul>"
	}

	// Add utility links section
	authMethodsSection += "<h3>Utility Links</h3>\n<ul>\n"
	authMethodsSection += `<li><a href="/proc/whoami">View account details</a></li>` + "\n"
	authMethodsSection += `<li><a href="/proc/x509">View X.509 certificate info</a></li>` + "\n"
	authMethodsSection += "</ul>"

	// If no authentication methods are enabled
	if len(authLinks) == 0 {
		authMethodsSection = "<h3>Authentication</h3>\n<p>No authentication methods are currently enabled on this server.</p>\n" + authMethodsSection
	}

	page := `<!DOCTYPE html>
<html>
<head>
<title>WebDAV Server</title>
</head>
<body>
<h1>WebDAV Server</h1>

<p>Server Address: ` + html.EscapeString(r.Host) + `</p>

` + authMethodsSection + `

</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
}

// ProcX509Handler shows X.509 certificate information
func (h *WebDAVHandler) ProcX509Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	// This route is public, so there is never an authenticated user in context
	fmt.Fprintf(w, "No authenticated user in context\n")
	fmt.Fprintf(w, "(This route is not protected by authentication middleware)\n\n")

	if r.TLS == nil {
		fmt.Fprint(w, "No TLS connection\n")
		return
	}

	fmt.Fprintf(w, "TLS Connection Info:\n")
	fmt.Fprintf(w, "Version: %s\n", tls.VersionName(r.TLS.Version))
	fmt.Fprintf(w, "Cipher Suite: %s\n", tls.CipherSuiteName(r.TLS.CipherSuite))
	fmt.Fprintf(w, "Server Name: %s\n", r.TLS.ServerName)
	fmt.Fprintf(w, "\n")

	if len(r.TLS.PeerCertificates) == 0 {
		fmt.Fprint(w, "No client certificate provided\n")
		if h.Config.X509Auth {
			fmt.Fprint(w, "X.509 Authentication Status: Would FAIL (no certificate)\n")
		}
		return
	}

	for i, cert := range r.TLS.PeerCertificates {
		fmt.Fprintf(w, "Client Certificate [%d]:\n", i)
		fmt.Fprintf(w, "Subject: %s\n", cert.Subject.String())
		fmt.Fprintf(w, "Issuer: %s\n", cert.Issuer.String())
		fmt.Fprintf(w, "Serial Number: %s\n", cert.SerialNumber.String())
		fmt.Fprintf(w, "Not Before: %s\n", cert.NotBefore.Format(time.RFC3339))
		fmt.Fprintf(w, "Not After: %s\n", cert.NotAfter.Format(time.RFC3339))
		fmt.Fprintf(w, "Distinguished Name: %s\n\n", x509utils.GetDNParts(cert))
	}

	// Show the X.509 authentication outcome if X.509 auth is enabled
	if !h.Config.X509Auth {
		fmt.Fprintf(w, "X.509 Authentication: DISABLED on this server\n")
		return
	}
	fmt.Fprintf(w, "X.509 Authentication Simulation:\n")
	eec, proxies, err := h.AuthStore.VerifyClientCertificate(r.TLS.PeerCertificates)
	if err != nil {
		fmt.Fprintf(w, "Authentication Status: Would FAIL (%v)\n", err)
		slog.DebugContext(r.Context(), "/proc/x509: certificate not verified", "error", err)
		return
	}
	dn := x509utils.GetDNParts(eec)
	username, ok := h.AuthStore.MapDN(dn)
	if !ok {
		fmt.Fprintf(w, "Authentication Status: Would FAIL (not in the grid-mapfile)\n")
		fmt.Fprintf(w, "Identity DN: %s\n", dn)
		slog.DebugContext(r.Context(), "/proc/x509: DN not in the grid-mapfile", "dn", dn)
		return
	}
	fmt.Fprintf(w, "Authentication Status: Would SUCCEED\n")
	fmt.Fprintf(w, "Identity DN: %s\n", dn)
	if proxies > 0 {
		fmt.Fprintf(w, "Proxy certificates: %d\n", proxies)
	}
	fmt.Fprintf(w, "Username would be: %s\n", username)
	fmt.Fprintf(w, "Method: X.509 Certificate\n")
	fmt.Fprintf(w, "To authenticate: Visit /auth/x509 or any protected route\n")

}

// WhoAmIHandler shows information about the current authenticated user
func (h *WebDAVHandler) WhoAmIHandler(w http.ResponseWriter, r *http.Request) {
	reqID := logger.GetRequestID(r.Context())

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	fmt.Fprintf(w, "=== WebDAV Server - Who Am I ===\n\n")

	// Check if user is authenticated via new AuthInfo context
	if authInfo, authenticated := auth.GetAuthInfoFromContext(r.Context()); authenticated {
		fmt.Fprintf(w, "Status: Authenticated\n")
		fmt.Fprintf(w, "Username: %s\n", authInfo.Username)
		fmt.Fprintf(w, "Authentication Method: %s\n", authInfo.Method)
		if authInfo.Unix != nil {
			fmt.Fprintf(w, "Unix Account: %s\n", authInfo.Unix)
		}
		fmt.Fprintf(w, "\nAuthentication Details:\n")
		for key, value := range authInfo.Details {
			fmt.Fprintf(w, "  %s: %v\n", key, value)
		}
	} else if username, hasUsername := auth.GetUsernameFromContext(r.Context()); hasUsername {
		// Fallback for backward compatibility
		fmt.Fprintf(w, "Status: Authenticated (legacy)\n")
		fmt.Fprintf(w, "Username: %s\n", username)
		fmt.Fprintf(w, "Authentication Method: Unknown (legacy context)\n")
	} else {
		fmt.Fprintf(w, "Status: Not Authenticated\n")
		fmt.Fprintf(w, "Username: Anonymous\n")
		fmt.Fprintf(w, "Authentication Method: None\n")
	}

	// Additional request information
	fmt.Fprintf(w, "\nRequest Information:\n")
	fmt.Fprintf(w, "  Request ID: %s\n", reqID)
	fmt.Fprintf(w, "  Remote Address: %s\n", r.RemoteAddr)
	fmt.Fprintf(w, "  User Agent: %s\n", r.UserAgent())
	fmt.Fprintf(w, "  Method: %s\n", r.Method)
	fmt.Fprintf(w, "  Path: %s\n", r.URL.Path)
	fmt.Fprintf(w, "  TLS: %t\n", r.TLS != nil)

	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		fmt.Fprintf(w, "  Client Certificate: Present\n")
		fmt.Fprintf(w, "  Certificate Subject: %s\n", r.TLS.PeerCertificates[0].Subject.String())
	}

}

// OIDCHandler starts an OIDC login: it sends the browser to the identity provider
func (h *WebDAVHandler) OIDCHandler(authStore *auth.AuthStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authURL, cookie := authStore.StartOIDCLogin(r.TLS != nil)
		http.SetCookie(w, cookie)
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// BasicAuthSuccessHandler handles successful basic authentication
func (h *WebDAVHandler) BasicAuthSuccessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	authInfo, authenticated := auth.GetAuthInfoFromContext(r.Context())
	if !authenticated {
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	page := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
	<title>Basic Authentication Success</title>
</head>
<body>
	<h1>Basic Authentication Successful!</h1>
	<p>Welcome, <strong>%s</strong>!</p>
	<p>You have successfully authenticated using Basic Authentication.</p>

	<h3>Next Steps:</h3>
	<ul>
		<li><a href="/webdav/">Access WebDAV content</a></li>
		<li><a href="/proc/whoami">View account information</a></li>
		<li><a href="/">Return to home page</a></li>
	</ul>
</body>
</html>`, html.EscapeString(authInfo.Username))

	w.Write([]byte(page))
}

// X509AuthSuccessHandler handles successful X.509 certificate authentication
func (h *WebDAVHandler) X509AuthSuccessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	authInfo, authenticated := auth.GetAuthInfoFromContext(r.Context())
	if !authenticated {
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	page := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
	<title>X.509 Certificate Authentication Success</title>
</head>
<body>
	<h1>X.509 Certificate Authentication Successful!</h1>
	<p>Welcome, <strong>%s</strong>!</p>
	<p>You have successfully authenticated using your client certificate.</p>

	<h3>Certificate Information:</h3>
	<p>Distinguished Name: %s</p>

	<h3>Next Steps:</h3>
	<ul>
		<li><a href="/webdav/">Access WebDAV content</a></li>
		<li><a href="/proc/x509">View certificate information</a></li>
		<li><a href="/proc/whoami">View account information</a></li>
		<li><a href="/">Return to home page</a></li>
	</ul>
</body>
</html>`, html.EscapeString(authInfo.Username), html.EscapeString(fmt.Sprint(authInfo.Details["distinguished_name"])))

	w.Write([]byte(page))
}

// OIDCRedirectHandler completes an OIDC login when the identity provider sends the
// browser back, and shows the access token it issued
func (h *WebDAVHandler) OIDCRedirectHandler(authStore *auth.AuthStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		// The page shows a token: it must not be stored, framed or sent in a Referer
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

		secure := r.TLS != nil
		var login string
		if c, err := r.Cookie(auth.OIDCLoginCookie(secure)); err == nil {
			login = c.Value
		}
		// A login cookie is used once
		http.SetCookie(w, &http.Cookie{Name: auth.OIDCLoginCookie(secure), Path: "/", HttpOnly: true, Secure: secure, MaxAge: -1})

		tok, err := authStore.FinishOIDCLogin(ctx, login, r.URL.Query())
		if err != nil {
			status, level := http.StatusBadGateway, slog.LevelWarn
			switch {
			case errors.Is(err, auth.ErrOIDCState):
				status, level = http.StatusBadRequest, slog.LevelInfo
			case errors.Is(err, auth.ErrOIDCRefused):
				status, level = http.StatusUnauthorized, slog.LevelInfo
			case auth.IsForbidden(err):
				status, level = http.StatusForbidden, slog.LevelInfo
				if user := auth.RefusedUser(err); user != "" {
					logger.SetUsername(ctx, user)
				}
			}
			slog.Log(ctx, level, "OIDC login failed", "status", status, "error", err)
			oidcPage(w, status, "Login failed", "<p>"+html.EscapeString(err.Error())+"</p>\n<p><a href=\"/auth/oidc\">Try again</a></p>")
			return
		}
		logger.SetUsername(ctx, tok.Username) // the user the token maps to
		slog.InfoContext(ctx, "gave out a token through an OIDC login", "user", tok.Username, "issuer", tok.Issuer,
			"subject", tok.Subject, "scopes", strings.Join(tok.Scopes, " "), "expires", tok.Expiry)

		e := html.EscapeString
		scheme, dav := "http", "dav"
		if secure {
			scheme, dav = "https", "davs"
		}
		groups := ""
		if len(tok.Groups) > 0 {
			groups = "<br>\nGroups: " + e(strings.Join(tok.Groups, " "))
		}
		oidcPage(w, http.StatusOK, "Your access token", fmt.Sprintf(`<p>Issued by %s to %s; this server serves it as user <strong>%s</strong>.<br>
Scopes: %s%s<br>
Expires: %s (in %.0f minutes)</p>
<p><textarea readonly rows="12" cols="80">%s</textarea></p>
<h3>Use it</h3>
<pre>export BEARER_TOKEN=...   # the token above
curl -H "Authorization: Bearer $BEARER_TOKEN" -o file %s://%s/webdav/path/file
curl -H "Authorization: Bearer $BEARER_TOKEN" -T file %s://%s/webdav/path/file
gfal-ls %s://%s/webdav/path/   # gfal2 reads BEARER_TOKEN</pre>
<p>Anyone holding the token has these rights until it expires: do not share it.
<a href="/auth/oidc">Get a new token</a> when it expires.</p>`,
			e(tok.Issuer), e(tok.Subject), e(tok.Username), e(strings.Join(tok.Scopes, " ")), groups,
			tok.Expiry.UTC().Format(time.RFC1123), time.Until(tok.Expiry).Minutes(), e(tok.Token),
			scheme, e(r.Host), scheme, e(r.Host), dav, e(r.Host)))
	}
}

// oidcPage answers with a page of the OIDC login; body is HTML
func oidcPage(w http.ResponseWriter, status int, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, "<!DOCTYPE html>\n<html>\n<head>\n\t<title>%s</title>\n</head>\n<body>\n<h1>%s</h1>\n%s\n</body>\n</html>\n",
		html.EscapeString(title), html.EscapeString(title), body)
}

// handleMacaroonRequest handles POST requests with application/macaroon-request content-type
func (h *WebDAVHandler) handleMacaroonRequest(w http.ResponseWriter, r *http.Request) {
	if h.AuthStore == nil || !h.AuthStore.MacaroonEnabled {
		http.Error(w, "Macaroons are not enabled on this server", http.StatusNotImplemented)
		return
	}

	authInfo, authenticated := auth.GetAuthInfoFromContext(r.Context())
	if !authenticated || authInfo.Username == "" {
		slog.ErrorContext(r.Context(), "macaroon request without an authenticated user")
		http.Error(w, "Authentication required for macaroon creation", http.StatusUnauthorized)
		return
	}
	if authInfo.Method == "token" {
		// The macaroon would not be bound by the token's scopes (also refused by auth)
		http.Error(w, "A macaroon cannot be requested with a token", http.StatusForbidden)
		return
	}

	// Parse the JSON request body
	var req struct {
		Caveats  []string `json:"caveats"`
		Validity string   `json:"validity,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxMacaroonRequest)).Decode(&req); err != nil {
		slog.InfoContext(r.Context(), "invalid macaroon request", "error", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	for _, c := range req.Caveats {
		if err := auth.ValidateCaveat(c); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Every macaroon expires; the requested validity is capped by the server maximum
	validity := h.Config.MacaroonMaxValidity
	if validity <= 0 {
		validity = defaultMaxValidity
	}
	if req.Validity != "" {
		d, err := parseISODuration(req.Validity)
		if err != nil {
			slog.InfoContext(r.Context(), "invalid macaroon validity", "error", err)
			http.Error(w, "Invalid validity duration", http.StatusBadRequest)
			return
		}
		if d < validity {
			validity = d
		}
	}
	expiry := time.Now().Add(validity).UTC().Truncate(time.Second)

	// Always add a path caveat based on the URL path component
	caveats := append([]string(nil), req.Caveats...)
	caveats = append(caveats, "path:"+r.URL.Path, "before:"+expiry.Format(time.RFC3339))

	var token string
	var err error
	if authInfo.Macaroon != nil {
		// Authenticated with a macaroon: the new one is an attenuation of it, so it
		// keeps every restriction (and the identity) of the original
		token, err = h.AuthStore.AttenuateMacaroon(authInfo.Macaroon, caveats)
		if prev, ok := authInfo.Details["expires"].(time.Time); ok && prev.Before(expiry) {
			expiry = prev
		}
	} else {
		// The identity caveat comes first and cannot be supplied by the client
		token, err = h.AuthStore.CreateMacaroon(append([]string{"id:" + authInfo.Username}, caveats...))
	}
	if err != nil {
		slog.ErrorContext(r.Context(), "cannot create a macaroon", "error", err)
		http.Error(w, "Failed to create macaroon", http.StatusInternalServerError)
		return
	}

	slog.InfoContext(r.Context(), "minted a macaroon", "user", authInfo.Username, "path", r.URL.Path, "caveats", caveats)

	// Return the macaroon as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"macaroon":   token,
		"expires_in": int(time.Until(expiry).Seconds()),
	})
}

var isoDuration = regexp.MustCompile(`^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$`)

// parseISODuration parses the ISO 8601 durations used in macaroon requests,
// e.g. PT60M, PT1H30M, P1DT12H. Years, months and weeks are not supported.
func parseISODuration(s string) (time.Duration, error) {
	m := isoDuration.FindStringSubmatch(s)
	if m == nil || s == "P" || strings.HasSuffix(s, "T") {
		return 0, fmt.Errorf("invalid ISO 8601 duration: %q", s)
	}
	var d time.Duration
	for i, unit := range []time.Duration{24 * time.Hour, time.Hour, time.Minute} {
		if m[i+1] == "" {
			continue
		}
		n, err := strconv.ParseInt(m[i+1], 10, 64)
		if err != nil || n > 100000 {
			return 0, fmt.Errorf("invalid ISO 8601 duration: %q", s)
		}
		d += time.Duration(n) * unit
	}
	if m[4] != "" {
		secs, err := strconv.ParseFloat(m[4], 64)
		if err != nil || secs > 1e9 {
			return 0, fmt.Errorf("invalid ISO 8601 duration: %q", s)
		}
		d += time.Duration(secs * float64(time.Second))
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration must be positive: %q", s)
	}
	return d, nil
}
