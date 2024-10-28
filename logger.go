package main

import (
	"fmt"
	"net/http"
)

func logger(r *http.Request, err error) {
	fmt.Println(*r, err)
}
