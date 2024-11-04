package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"golang.org/x/net/webdav"
)

var portFlag = flag.Int("port", 9000, "tcp port")

func main() {
	flag.Parse()

	fs := webdav.NewMemFS()
	lock := webdav.NewMemLS()
	davHandler := &webdav.Handler{
		Prefix:     "",
		FileSystem: fs,
		LockSystem: lock,
		Logger: func(*http.Request, error) {
		},
	}

	davHandler.Prefix = "/"
	davHandler.FileSystem = fs
	davHandler.LockSystem = lock
	davHandler.Logger = logger
	h := &handler{
		Handler: davHandler,
	}

	router := http.NewServeMux()
	router.Handle("/", h)
	router.HandleFunc("COPY /{file...}", h.copyHandler)
	router.HandleFunc("GET /proc/x509", h.procX509Handler)

	err := http.ListenAndServe(
		fmt.Sprintf(":%d", *portFlag),
		router,
	)

	log.Default().Println(err)
}

type handler struct {
	*webdav.Handler
}

func (h *handler) procX509Handler(w http.ResponseWriter, r *http.Request) {
	// obtain TLS client certificate information and dump it back to
	// the user.
	cert := r.TLS.PeerCertificates[0]
	fmt.Fprintf(w, "%+v", cert)
}
