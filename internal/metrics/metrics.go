// Package metrics exposes counters and gauges in the Prometheus text format.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// A Vec is a family of counters or gauges told apart by label values
type Vec struct {
	name, help, kind string
	labels           []string

	mu     sync.RWMutex
	values map[string]*atomic.Int64 // joined label values -> value
}

var (
	registryMu sync.Mutex
	registry   []*Vec
)

func newVec(kind, name, help string, labels ...string) *Vec {
	v := &Vec{name: name, help: help, kind: kind, labels: labels, values: make(map[string]*atomic.Int64)}
	registryMu.Lock()
	registry = append(registry, v)
	registryMu.Unlock()
	return v
}

// NewCounter registers a counter family
func NewCounter(name, help string, labels ...string) *Vec {
	return newVec("counter", name, help, labels...)
}

// NewGauge registers a gauge family
func NewGauge(name, help string, labels ...string) *Vec {
	return newVec("gauge", name, help, labels...)
}

func (v *Vec) value(labelValues []string) *atomic.Int64 {
	if len(labelValues) != len(v.labels) {
		panic(fmt.Sprintf("metrics: %s takes %d labels, got %d", v.name, len(v.labels), len(labelValues)))
	}
	key := strings.Join(labelValues, "\x00")
	v.mu.RLock()
	val, ok := v.values[key]
	v.mu.RUnlock()
	if ok {
		return val
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if val, ok = v.values[key]; !ok {
		val = new(atomic.Int64)
		v.values[key] = val
	}
	return val
}

// Add adds n to the value with the given label values
func (v *Vec) Add(n int64, labelValues ...string) { v.value(labelValues).Add(n) }

// Inc adds one to the value with the given label values
func (v *Vec) Inc(labelValues ...string) { v.Add(1, labelValues...) }

// Dec subtracts one from the value with the given label values (gauges)
func (v *Vec) Dec(labelValues ...string) { v.Add(-1, labelValues...) }

// Get returns the value with the given label values
func (v *Vec) Get(labelValues ...string) int64 { return v.value(labelValues).Load() }

func (v *Vec) write(w io.Writer) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", v.name, v.help, v.name, v.kind)
	v.mu.RLock()
	keys := make([]string, 0, len(v.values))
	for k := range v.values {
		keys = append(keys, k)
	}
	v.mu.RUnlock()
	sort.Strings(keys)
	for _, k := range keys {
		v.mu.RLock()
		val := v.values[k].Load()
		v.mu.RUnlock()
		fmt.Fprintf(w, "%s%s %d\n", v.name, Labels(v.labels, strings.Split(k, "\x00")), val)
	}
}

// Labels formats a label set ({a="x",b="y"}), escaping the values
func Labels(names, values []string) string {
	if len(names) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, n := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		v := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(values[i])
		fmt.Fprintf(&b, `%s="%s"`, n, v)
	}
	b.WriteByte('}')
	return b.String()
}

// Handler serves all registered metrics, followed by what extra writes (metrics
// computed when scraped)
func Handler(extra func(w io.Writer)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		registryMu.Lock()
		vecs := append([]*Vec(nil), registry...)
		registryMu.Unlock()
		for _, v := range vecs {
			v.write(w)
		}
		if extra != nil {
			extra(w)
		}
	})
}

// WriteGauge writes a single gauge sample with its metadata
func WriteGauge(w io.Writer, name, help string, value float64, labelNames, labelValues []string) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s%s %g\n", name, help, name, name, Labels(labelNames, labelValues), value)
}

// The metrics weed records
var (
	HTTPRequests = NewCounter("weed_http_requests_total",
		"HTTP requests by method and status code.", "method", "code")
	HTTPResponseBytes = NewCounter("weed_http_response_bytes_total",
		"Bytes sent in HTTP response bodies, by method.", "method")
	Auth = NewCounter("weed_auth_requests_total",
		"Authentication outcomes of WebDAV requests, by the method that decided them (none when no credentials were accepted).", "method", "result")
	UploadBytes = NewCounter("weed_upload_bytes_total",
		"Bytes stored by successful uploads (PUT).")
	ChecksumMismatches = NewCounter("weed_checksum_mismatches_total",
		"Transfers refused because the data did not match the client's checksum, by operation.", "operation")
	TPCTransfers = NewCounter("weed_tpc_transfers_total",
		"Finished third-party copies by mode (pull, push) and result (success, failure).", "mode", "result")
	TPCBytes = NewCounter("weed_tpc_bytes_total",
		"Bytes moved by third-party copies, by mode.", "mode")
	TPCActive = NewGauge("weed_tpc_active_transfers",
		"Third-party copies in progress, by mode.", "mode")
	TPCRejected = NewCounter("weed_tpc_rejected_total",
		"Third-party copies refused because -tpc-max-transfers were already running.")
	Reloads = NewCounter("weed_reloads_total",
		"Credential reloads by result (success, or partial when some file could not be read).", "result")
)

// davMethods are the methods counted by name; others are counted as "other" so
// that clients cannot create unbounded label values
var davMethods = map[string]bool{
	"GET": true, "HEAD": true, "PUT": true, "POST": true, "DELETE": true, "OPTIONS": true,
	"PROPFIND": true, "PROPPATCH": true, "MKCOL": true, "COPY": true, "MOVE": true, "LOCK": true, "UNLOCK": true,
}

// Method returns the label value for an HTTP method
func Method(m string) string {
	if davMethods[m] {
		return m
	}
	return "other"
}
