package server

import (
	"maps"
	"net/http"
	"sync"

	"github.com/labkode/weed/internal/auth"
	"github.com/labkode/weed/internal/davreq"
	"github.com/labkode/weed/internal/logger"
	"github.com/labkode/weed/internal/metrics"
)

// The transfers and other WebDAV requests that weed is serving now, by kind and by
// user: weed_requests_in_progress, and in_progress in /status

// The kinds of WebDAV requests
const (
	kindDownload = "download" // GET
	kindUpload   = "upload"   // PUT
	kindTPCPull  = "tpc_pull" // COPY with Source
	kindTPCPush  = "tpc_push" // COPY to another server's Destination
	kindOther    = "other"    // PROPFIND, HEAD, MKCOL, DELETE, MOVE, local COPY, ...
)

var requestKinds = []string{kindDownload, kindUpload, kindTPCPull, kindTPCPush, kindOther}

func init() {
	for _, k := range requestKinds {
		metrics.RequestsInProgress.Add(0, k) // exported from the start, at 0
	}
}

func requestKind(r *http.Request) string {
	switch r.Method {
	case http.MethodGet:
		return kindDownload
	case http.MethodPut:
		return kindUpload
	case "COPY":
		if t, err := davreq.ParseTarget(r); err == nil {
			switch t.Kind {
			case davreq.CopyPull:
				return kindTPCPull
			case davreq.CopyPush:
				return kindTPCPush
			}
		}
	}
	return kindOther
}

// inProgress counts the requests in progress of each user, by kind
type inProgress struct {
	mu     sync.Mutex
	byUser map[string]map[string]int
}

func (p *inProgress) add(user, kind string, n int) {
	metrics.RequestsInProgress.Add(int64(n), kind)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.byUser == nil {
		p.byUser = make(map[string]map[string]int)
	}
	kinds := p.byUser[user]
	if kinds == nil {
		kinds = make(map[string]int)
		p.byUser[user] = kinds
	}
	if kinds[kind] += n; kinds[kind] == 0 {
		delete(kinds, kind)
		if len(kinds) == 0 {
			delete(p.byUser, user)
		}
	}
}

// statusInProgress is in_progress in /status
type statusInProgress struct {
	Total  map[string]int            `json:"total"`   // by kind, every kind
	ByUser map[string]map[string]int `json:"by_user"` // the kinds each user has in progress
}

func (p *inProgress) status() statusInProgress {
	st := statusInProgress{Total: make(map[string]int), ByUser: make(map[string]map[string]int)}
	for _, k := range requestKinds {
		st.Total[k] = 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for user, kinds := range p.byUser {
		st.ByUser[user] = maps.Clone(kinds)
		for k, n := range kinds {
			st.Total[k] += n
		}
	}
	return st
}

// track counts the authenticated WebDAV requests that next serves while it serves
// them, as the user whom their credentials map to
func (s *Server) track(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kind, user := requestKind(r), logger.Nobody
		if info, ok := auth.GetAuthInfoFromContext(r.Context()); ok {
			user = info.Username
		}
		s.inProgress.add(user, kind, 1)
		defer s.inProgress.add(user, kind, -1)
		next.ServeHTTP(w, r)
	})
}
