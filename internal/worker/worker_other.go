//go:build !linux

package worker

import (
	"context"
	"net/http"
	"time"

	"github.com/labkode/weed/internal/config"
	"github.com/labkode/weed/internal/fsuser"
)

// Options configure a Pool
type Options struct {
	Config       config.Config
	IdleTimeout  time.Duration
	MaxWorkers   int
	Cgroups      bool
	CgroupLimits []string
}

// Pool is only supported on Linux
type Pool struct{}

// New is only supported on Linux
func New(Options) (*Pool, error) { return nil, errUnsupported }

func (p *Pool) Check() error                                                     { return errUnsupported }
func (p *Pool) Workers() []Info                                                  { return nil }
func (p *Pool) ServeHTTP(w http.ResponseWriter, r *http.Request, u *fsuser.User) {}
func (p *Pool) Reload()                                                          {}
func (p *Pool) Close(ctx context.Context)                                        {}

// Child is only supported on Linux
type Child struct{ Settings Settings }

// Attach is only supported on Linux
func Attach() (*Child, error) { return nil, errUnsupported }

func (c *Child) Fail(err error) error                      { return err }
func (c *Child) Serve(h http.Handler, reload func()) error { return errUnsupported }
