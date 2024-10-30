package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
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
	reprDigest := r.Header.Get("Repr-Digest")
	contentDigest := r.Header.Get("Content-Digest")
	overwrite := getOverwrite(r)

	fmt.Printf("destination=%s source=%s reprDigest=%s contentDigest=%s overwrite=%t", file, source, reprDigest, contentDigest, overwrite)

	getReq, err := http.NewRequest("GET", source, nil)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "error: source %q is invalid", source)
	}

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
	clientDigests := getClientDigest(r)
	if len(clientDigests) == 0 {
		w.WriteHeader(http.StatusPreconditionFailed)
		fmt.Fprintf(w, "error: digest not present in the request")
		return
	}

	for _, clientDigest := range clientDigests {
		if !clientDigest.isSupported() {
			w.WriteHeader(http.StatusPreconditionFailed)
			fmt.Fprintf(w, "error: digest not present in the request")
			return
		}
	}
}

func getClientDigest(r *http.Request) []*digest {
	reprDigest := r.Header.Get("Repr-Digest")
	digests := newDigestFromHTTP(reprDigest)
	return digests
}

func newDigestFromHTTP(reprDigest string) []*digest {
	// Repr-Digest contains a dictionary as specified in https://www.rfc-editor.org/rfc/rfc8941#section-3.2
	return nil
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
// "adler=:123=:,md5=:333=:"
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
