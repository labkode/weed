package main

import (
	"log"
	"net/http"
	"path"
	"strings"
)

func (h *handler) checkMacaroons(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if strings.ToLower(ct) == "application/macaroons-request" {
			h.doMacaroons(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *handler) doMacaroons(w http.ResponseWriter, r *http.Request) {
	// file may not exists, for example, when requesting a macaroon
	// to write a new file.
	file := path.Join("/", r.PathValue("file"))
	log.Default().Printf("macaroon requested for file:%s", file)

	w.WriteHeader(http.StatusNotImplemented)
}

type macaroonRequest struct {
	Caveats  []string `json:"caveats"`
	Validity string   `json:"validity"`
}
