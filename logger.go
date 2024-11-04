package main

import (
	"log"
	"net/http"
)

func logger(r *http.Request, err error) {
	log.Default().Println(*r, err)
}
