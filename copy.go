package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

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

func doTPCPush(w http.ResponseWriter, r *http.Request) {
}

// doTPCPull performs a Third Party Copy transfer.
// It does an HTTP GET request towards the source endpoint,
// defined in the HTTP Source header, and writes the local
// file.
// This function assumess the Source header is always present
// and has been already cleared.
func doTPCPull(w http.ResponseWriter, r *http.Request) {
	file := r.PathValue("file")
	source := r.Header.Get("source")
	reprDigest := r.Header.Get("Repr-Digest")
	contentDigest := r.Header.Get("Content-Digest")
	fmt.Println(file, source, reprDigest, contentDigest)
}

func copyHandler(w http.ResponseWriter, r *http.Request) {
	tpcMode, err := getTPCMode(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	if tpcMode == TPCModePull {
		doTPCPull(w, r)
		return
	}
	doTPCPush(w, r)
}
