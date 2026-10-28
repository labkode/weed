package server

import (
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/labkode/weed/internal/digest"
)

// Throughput of transfers through weed over loopback, to see what checksums cost
// next to the disk and the network stack. The size defaults to 256 MiB; for
// multi-GB files:
//
//	WEED_BENCH_MIB=4096 go test ./internal/server -run '^$' -bench . -benchtime 3x

func benchSize(b *testing.B) int64 {
	mib := int64(256)
	if s := os.Getenv("WEED_BENCH_MIB"); s != "" {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			b.Fatal(err)
		}
		mib = v
	}
	return mib << 20
}

// pattern is incompressible data, repeated
var pattern = func() []byte {
	p := make([]byte, 1<<20)
	rand.Read(p)
	return p
}()

// patternReader yields n bytes of pattern
type patternReader struct{ off, n int64 }

func (r *patternReader) Read(p []byte) (int, error) {
	if r.off >= r.n {
		return 0, io.EOF
	}
	k := copy(p, pattern[r.off%int64(len(pattern)):])
	if rem := r.n - r.off; int64(k) > rem {
		k = int(rem)
	}
	r.off += int64(k)
	return k, nil
}

// digestsOf returns a Repr-Digest field with the digests of n bytes of pattern
func digestsOf(n int64, algs ...string) string {
	if len(algs) == 0 {
		return ""
	}
	h := digest.NewHasher(algs...)
	io.Copy(h, &patternReader{n: n})
	return digest.FormatReprDigest(h.Sums())
}

var checksumCases = []struct {
	name string
	algs []string
}{
	{"adler32 only", nil}, // weed always computes adler32
	{"+md5", []string{digest.MD5}},
	{"+sha-256", []string{digest.SHA256}},
	{"+crc32c+md5+sha-256", []string{digest.CRC32C, digest.MD5, digest.SHA256}},
}

func send(b *testing.B, client *http.Client, req *http.Request, want ...int) {
	resp, err := client.Do(req)
	if err != nil {
		b.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if !slices.Contains(want, resp.StatusCode) {
		b.Fatalf("%s %s: %d", req.Method, req.URL.Path, resp.StatusCode)
	}
}

func BenchmarkPut(b *testing.B) {
	size := benchSize(b)
	n := newNode(b, nil)
	for _, c := range checksumCases {
		reprDigest := digestsOf(size, c.algs...)
		b.Run(c.name, func(b *testing.B) {
			b.SetBytes(size)
			for b.Loop() {
				req, _ := http.NewRequest("PUT", n.url("/put"), &patternReader{n: size})
				req.ContentLength = size
				req.SetBasicAuth(basicUser, basicPass)
				if reprDigest != "" {
					req.Header.Set("Repr-Digest", reprDigest)
				}
				send(b, n.ts.Client(), req, 201, 204)
			}
		})
	}
}

func BenchmarkGet(b *testing.B) {
	size := benchSize(b)
	n := newNode(b, nil)
	f, _ := os.Create(n.dir + "/f")
	io.Copy(f, &patternReader{n: size})
	f.Close()
	b.SetBytes(size)
	for b.Loop() {
		req, _ := http.NewRequest("GET", n.url("/f"), nil)
		req.SetBasicAuth(basicUser, basicPass)
		send(b, n.ts.Client(), req, 200)
	}
}

func BenchmarkTPCPull(b *testing.B) {
	size := benchSize(b)
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		io.Copy(w, &patternReader{n: size})
	}))
	defer src.Close()
	n := newNode(b, nil)
	for _, c := range checksumCases {
		reprDigest := digestsOf(size, c.algs...)
		b.Run(c.name, func(b *testing.B) {
			b.SetBytes(size)
			for b.Loop() {
				req, _ := http.NewRequest("COPY", n.url("/pulled"), nil)
				req.SetBasicAuth(basicUser, basicPass)
				req.Header.Set("Source", src.URL+"/f")
				if reprDigest != "" {
					req.Header.Set("Repr-Digest", reprDigest)
				}
				resp, err := n.ts.Client().Do(req)
				if err != nil {
					b.Fatal(err)
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if !strings.HasSuffix(string(body), "success: Created\n") {
					b.Fatalf("TPC: %d %s", resp.StatusCode, body)
				}
			}
		})
	}
}

// BenchmarkDiskWrite is the baseline: writing and syncing the same amount of data
func BenchmarkDiskWrite(b *testing.B) {
	size := benchSize(b)
	dir := b.TempDir()
	buf := make([]byte, 1<<20)
	b.SetBytes(size)
	for b.Loop() {
		f, err := os.CreateTemp(dir, "w")
		if err != nil {
			b.Fatal(err)
		}
		io.CopyBuffer(f, &patternReader{n: size}, buf)
		f.Sync()
		f.Close()
		os.Remove(f.Name())
	}
}

func BenchmarkTPCPush(b *testing.B) {
	size := benchSize(b)
	active, passive := newNode(b, nil), newNode(b, nil)
	f, _ := os.Create(active.dir + "/f")
	io.Copy(f, &patternReader{n: size})
	f.Close()
	mac, _ := passive.mint("/", `{"caveats":["activity:UPLOAD"]}`)
	for _, c := range checksumCases {
		reprDigest := digestsOf(size, c.algs...)
		b.Run(c.name, func(b *testing.B) {
			b.SetBytes(size)
			for b.Loop() {
				req, _ := http.NewRequest("COPY", active.url("/f"), nil)
				req.SetBasicAuth(basicUser, basicPass)
				req.Header.Set("Destination", passive.url("/pushed"))
				req.Header.Set("TransferHeaderAuthorization", "Bearer "+mac)
				if reprDigest != "" {
					req.Header.Set("Repr-Digest", reprDigest)
				}
				resp, err := active.ts.Client().Do(req)
				if err != nil {
					b.Fatal(err)
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if !strings.HasSuffix(string(body), "success: Created\n") {
					b.Fatalf("TPC: %d %s", resp.StatusCode, body)
				}
			}
		})
	}
}
