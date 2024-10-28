package main

import (
	"fmt"
	"net/http"

	"golang.org/x/net/webdav"
)

func main() {
	fs := webdav.NewMemFS()
	lock := webdav.NewMemLS()
	davHandler := &webdav.Handler{}
	davHandler.Prefix = "/"
	davHandler.FileSystem = fs
	davHandler.LockSystem = lock
	davHandler.Logger = logger

	router := http.NewServeMux()
	router.Handle("/", davHandler)
	router.HandleFunc("COPY /{file...}", copyHandler)

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
