package server

import (
	"embed"
	"io/fs"
	"net/http"
)

// The dashboard (/dashboard/) is a page that the browser fills from /status and
// /metrics: it shows what they say, as tiles, charts and tables, and changes nothing.
// It is served wherever they are, with no authentication either.

//go:embed dashboard
var dashboardFiles embed.FS

// dashboardCSP lets the page run only its own script and style, and fetch only from
// weed: what /status says (account names, configuration values) cannot become code
const dashboardCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; " +
	"base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// dashboardHandler serves the files of the dashboard below /dashboard/
func dashboardHandler() http.Handler {
	files, err := fs.Sub(dashboardFiles, "dashboard")
	if err != nil {
		panic(err)
	}
	fileServer := http.StripPrefix("/dashboard/", http.FileServerFS(files))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", dashboardCSP)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-cache") // a new build may serve other files
		fileServer.ServeHTTP(w, r)
	})
}
