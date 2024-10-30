package main

import (
	"fmt"
	"net/http"

	"golang.org/x/net/webdav"
)

func main() {
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
		":9000",
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
