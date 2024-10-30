package main

import (
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"hash/adler32"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/webdav"
)

type digest struct {
	Algo  string
	Value string
}

func (d *digest) isSupported() bool {
	if digestAlgo(d.Algo) == digestAdler || digestAlgo(d.Algo) == digestMD5 {
		return true
	}
	return false
}

type digestAlgo string

const (
	digestAdler digestAlgo = "adler"
	digestMD5   digestAlgo = "md5"
)

// String provides a character representation as expected
// by the HTTP Repr-Digest
func (d *digest) String() string {
	return fmt.Sprintf("%s=:%s:", d.Algo, d.Value)
}

type TPCMode string

const (
	TPCModePull    TPCMode = "tpcpull"
	TPCModePush    TPCMode = "tpcpush"
	TPCModeInvalid TPCMode = "tpcinvalid"
)

func getTPCMode(r *http.Request) (TPCMode, error) {
	// TODO(labkode): limit lenght of header values
	source, destination := r.Header.Get("source"), r.Header.Get("destination")
	if source == "" && destination == "" {
		return TPCModeInvalid, errors.New("error: no Source or Destination headers")
	}

	if source != "" && destination != "" {
		return TPCModeInvalid, errors.New("error: Source and Destination headers cannot be defined simultaneously")
	}

	if source != "" {
		return TPCModePull, nil
	}
	return TPCModePush, nil
}

func copyTransferHeaders(from, to *http.Request) {
	for k, v := range from.Header {
		for _, vv := range v {
			if strings.HasPrefix(strings.ToLower(k), "transferheader") {
				key := k[len("transferheader"):]
				to.Header.Add(key, vv)
			}
		}
	}
}

func doTPCPush(fs webdav.FileSystem, w http.ResponseWriter, r *http.Request) {
}

func getOverwrite(r *http.Request) bool {
	val := strings.ToLower(r.Header.Get("overwrite"))
	switch val {
	case "":
		return true // default to true when header is not set
	case "t":
		return true
	case "f":
		return false
	default:
		return false // default to false when header contains non valid values
	}
}

// doTPCPull performs a Third Party Copy transfer.
// It does an HTTP GET request towards the source endpoint,
// defined in the HTTP Source header, and writes the local
// file.
// This function assumess the Source header is always present
// and has been already cleared.
func doTPCPull(fs webdav.FileSystem, w http.ResponseWriter, r *http.Request) {
	file := r.PathValue("file")
	source := r.Header.Get("source")
	overwrite := getOverwrite(r)

	fmt.Printf("destination=%s source=%s overwrite=%t", file, source, overwrite)

	getReq, err := http.NewRequest("GET", source, nil)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "error: source %q is invalid", source)
	}
	copyTransferHeaders(r, getReq)

	client := &http.Client{
		Transport: http.DefaultTransport,
		Timeout:   10 * time.Second,
	}

	getRes, err := client.Do(getReq)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "error: cannot do GET request: %v", err)
		return
	}

	// if source endpoints gives back an http status code >=400,
	// we assume is an error and the body of the response may contain
	// some additional information about it, so we'll try to read as much as 1K to provide
	// that information in the response.
	if getRes.StatusCode >= http.StatusBadRequest {
		var errBuffer = []byte{}

		_, err := io.LimitReader(getRes.Body, 1024).Read(errBuffer)
		if err != nil && err != io.EOF {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "error: cannot read error response from source %q", source)
			return
		}

		// we proxy the http error code obtained from the source to the client
		w.WriteHeader(getRes.StatusCode)
		fmt.Fprintf(w, "error: http(%d) source(%q) source-error(%q)", getRes.StatusCode, source, string(errBuffer))
		return
	}

	// we got a positive reponse from the source.
	// we proceed with verifications.

	// check presence of overwrite.
	// does the destination exists?
	_, err = fs.Stat(r.Context(), file)
	destinationExists := err == nil

	if destinationExists {
		if overwrite {
			goto write
		}

		// the file exists and we cannot overwrite
		w.WriteHeader(http.StatusPreconditionFailed)
		fmt.Fprintf(w, "error: destination already exists and overwrite is false")
		return
	}

	if os.IsNotExist(err) { // error is different from not found
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "error: destination cannot be stat: %v", err)
		return
	}

write:
	// at this point we need to write the destination file from the data
	// obtained from the source.
	// If a digest is provided, we need to compute it

	// if sent digest is not in the list of valid checksum types
	// we send back a 412.
	clientDigests := getClientDigests(r)
	if len(clientDigests) == 0 {
		w.WriteHeader(http.StatusPreconditionFailed)
		fmt.Fprintf(w, "error: digest not present in the request")
		return
	}

	if ok := areClientDigestsSupported(clientDigests); !ok {
		w.WriteHeader(http.StatusPreconditionFailed)
		fmt.Fprintf(w, "error: server does not accept supplied client digests: %v", clientDigests)
		return
	}

	// we need to write the file into a temporary location,
	// calculate the digests and validate them againt the client supplied ones
	tmpfn := getTemporaryFilename(file)
	flags := getOpenFlags(overwrite)
	fd, err := fs.OpenFile(r.Context(), tmpfn, flags, os.FileMode(0700))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "error: cannot open for write destination file: %s", tmpfn)
		return
	}
	defer fd.Close()

	// calculate digest while we write into the temporary file
	md5 := md5.New()
	adler32 := adler32.New()
	mw := io.MultiWriter(md5, adler32, fd)
	n, err := io.Copy(mw, r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "error: cannot copy request body into destination file: %v", err)
		return
	}
	log.Default().Printf("written %d bytes into %s", n, tmpfn)
	md5Digest := &digest{
		Algo:  string(digestMD5),
		Value: digestFromRaw(md5.Sum(nil)),
	}
	adler32Digest := &digest{
		Algo:  string(digestAdler),
		Value: digestFromRaw(adler32.Sum(nil)),
	}

	serverDigests := map[digestAlgo]*digest{
		digestAdler: adler32Digest,
		digestMD5:   md5Digest,
	}

	log.Default().Printf("%s md5 is %s", tmpfn, md5Digest.Value)
	log.Default().Printf("%s adler32 is %s", tmpfn, adler32Digest.Value)

	match := compareDigests(clientDigests, serverDigests)
	if !match {
		w.WriteHeader(http.StatusPreconditionFailed)
		fmt.Fprintf(w, "error: expected digest does not match")
		return
	}

	// we can rename the final to it's original location
	if err := fs.Rename(r.Context(), tmpfn, file); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "error: cannot rename %s to original location %s", tmpfn, file)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// compareDigets compares the client supplied digets with the server
// computed ones.
// If the client sent a digest that is not computed by the server
// it returns false.
func compareDigests(client, server map[digestAlgo]*digest) bool {
	for algo, digest := range client {
		d, ok := server[algo]
		if !ok {
			return false
		}
		if digest.Value != d.Value {
			return false
		}
	}
	return true
}

// digestFromRaw returns a base64 encoded value of the
// sum of the hash
func digestFromRaw(input []byte) string {
	return base64.StdEncoding.EncodeToString(input)
}

func getOpenFlags(overwrite bool) int {
	if !overwrite {
		return os.O_WRONLY
	}
	return os.O_WRONLY | os.O_CREATE | os.O_TRUNC
}

// returns true if all provided digests are supported by the server
// if a digest is not supported, it returns false
func areClientDigestsSupported(digests map[digestAlgo]*digest) bool {
	for _, digest := range digests {
		if !digest.isSupported() {
			return false
		}
	}
	return true
}

func getClientDigests(r *http.Request) map[digestAlgo]*digest {
	reprDigest := r.Header.Get("Repr-Digest")
	return parseReprDigest(reprDigest)
}

func (h *handler) copyHandler(w http.ResponseWriter, r *http.Request) {
	tpcMode, err := getTPCMode(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	if tpcMode == TPCModePull {
		doTPCPull(h.FileSystem, w, r)
		return
	}
	doTPCPush(h.FileSystem, w, r)
}

// input is an HTTP dictionary defined in https://www.rfc-editor.org/rfc/rfc8941#name-byte-sequences
// example:  "adler=:123=:,md5=:333=:"
func parseReprDigest(input string) map[digestAlgo]*digest {
	var base64regexp = regexp.MustCompile(`^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$`)
	digests := map[digestAlgo]*digest{}

	// split by comma
	commaTokens := strings.Split(input, ",") // [ "adler=:123=:" "md5=:333=:"]
	for _, t := range commaTokens {
		// base64 encoding of the value uses = as padding character
		// the separator is only the 1st equal, that splits the key and the value
		equalTokens := strings.Split(t, "=")
		if len(equalTokens) < 2 { // input is malformed
			return map[digestAlgo]*digest{}
		}
		key := equalTokens[0] // adler
		val := strings.Join(equalTokens[1:], "=")

		// validate val is base64 encoded and is delimited by colons(:)
		// an empty base64 encoded value will produce "::"
		if val[0] != ':' || val[len(val)-1] != ':' {
			return map[digestAlgo]*digest{}
		}

		// remove leading and trailing colons
		val = strings.Trim(val, ":") // 333=
		// val should now be a valid base64 value
		if ok := base64regexp.MatchString(val); !ok {
			return map[digestAlgo]*digest{}
		}
		d := &digest{Algo: key, Value: val}
		digests[digestAlgo(d.Algo)] = d
	}
	return digests
}

// getTemporaryFilename returns a temporary filename
// generated from the base of the input and some randomness
func getTemporaryFilename(input string) string {
	dir, base := path.Split(input)
	base = strings.Trim(base, "/")
	random := getRandomNumber()
	filename := fmt.Sprintf(".tmp-%d-%s", random, base) // ".tmp-12331313133-myfile.txt"
	filename = path.Join(dir, filename)
	return filename
}

func getRandomNumber() int {
	return rand.Intn(1024)
}
