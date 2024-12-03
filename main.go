package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"

	"golang.org/x/net/webdav"
)

var portFlag = flag.Int("port", 9000, "tcp port")
var tlsFlag = flag.Bool("tls", false, "enable tls")

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
	router.Handle("/{file...}", h.checkMacaroons(h))
	router.HandleFunc("COPY /{file...}", h.copyHandler)
	router.HandleFunc("GET /proc/x509", h.procX509Handler)

	var err error
	if *tlsFlag {

		cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
		if err != nil {
			log.Fatalf("server loadkeys: %s", err)

		}

		tlsConfig := &tls.Config{
			ClientAuth: tls.RequestClientCert,
			//ClientCAs:             _rootCAs, // this comes from /etc/grid-security/certificate
			//RootCAs:               _rootCAs,
			Certificates: []tls.Certificate{cert},
		}

		addr := fmt.Sprintf(":%d", *portFlag)
		log.Default().Printf("Listening on %s", addr)
		s := http.Server{
			Addr:      addr,
			TLSConfig: tlsConfig,
			Handler:   router,
		}
		s.ListenAndServeTLS("server.crt", "server.key")

	} else {
		addr := fmt.Sprintf(":%d", *portFlag)
		log.Default().Printf("Listening on %s", addr)
		http.ListenAndServe(
			fmt.Sprintf(":%d", *portFlag),
			router,
		)
	}

	log.Default().Println(err)
}

type handler struct {
	*webdav.Handler
}

func (h *handler) procX509Handler(w http.ResponseWriter, r *http.Request) {
	// obtain TLS client certificate information and dump it back to
	// the user.
	getUserData(r)
}
