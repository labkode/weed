package main

import (
	"flag"
	"fmt"
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

	err := http.ListenAndServe(
		fmt.Sprintf(":%d", *portFlag),
		router,
	)

	fmt.Println(err)
}

/*
func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
}
*/

type handler struct {
	*webdav.Handler
}
