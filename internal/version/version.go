// Package version identifies the build of weed: the version and commit it was built
// from, the Go version, and the build of its executable, for the running process
// (Current) and for an executable on disk (OfFile).
package version

import (
	"debug/buildinfo"
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
)

// Info describes a build of weed
type Info struct {
	// Version is the module version: a VCS tag, or a pseudo-version
	// (v0.0.0-<time>-<commit>), with +dirty for uncommitted changes; "(devel)" for
	// binaries built without VCS information
	Version  string `json:"version"`
	Revision string `json:"revision,omitempty"` // commit
	Time     string `json:"time,omitempty"`     // of the commit
	Modified bool   `json:"modified"`           // built with uncommitted changes
	Go       string `json:"go"`
	Platform string `json:"platform"` // GOOS/GOARCH
	// Build identifies the executable (see Build); workers must run the same one
	Build string `json:"build"`
}

// Current is the build that runs; Build is "unknown" if the executable cannot be read
var Current = sync.OnceValue(func() Info {
	i := Info{Version: "unknown", Go: runtime.Version()}
	if bi, ok := debug.ReadBuildInfo(); ok {
		i = fromBuildInfo(bi)
	}
	i.Platform = runtime.GOOS + "/" + runtime.GOARCH
	i.Build = "unknown"
	if b, err := ExecutableBuild(); err == nil {
		i.Build = b
	}
	return i
})

// OfFile describes the build of the weed executable at path, without running it
func OfFile(path string) (Info, error) {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return Info{}, err
	}
	i := fromBuildInfo(bi)
	if i.Build, err = Build(path); err != nil {
		return Info{}, err
	}
	return i, nil
}

func fromBuildInfo(bi *debug.BuildInfo) Info {
	i := Info{Version: bi.Main.Version, Go: bi.GoVersion}
	var goos, goarch string
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			i.Revision = s.Value
		case "vcs.time":
			i.Time = s.Value
		case "vcs.modified":
			i.Modified = s.Value == "true"
		case "GOOS":
			goos = s.Value
		case "GOARCH":
			goarch = s.Value
		}
	}
	if goos != "" {
		i.Platform = goos + "/" + goarch
	}
	return i
}

// String describes the build on one line, e.g.
// "v1.2.0 (commit 46a37813bc81 of 2026-10-28T16:07:11Z) go1.27.3 linux/amd64"
func (i Info) String() string {
	s := i.Version
	if i.Revision != "" {
		rev := i.Revision
		if len(rev) > 12 {
			rev = rev[:12]
		}
		s += fmt.Sprintf(" (commit %s of %s", rev, i.Time)
		if i.Modified {
			s += ", modified"
		}
		s += ")"
	}
	return s + " " + i.Go + " " + i.Platform
}

// Text describes the build for weed version
func (i Info) Text() string {
	s := fmt.Sprintf("weed %s\n", i.Version)
	if i.Revision != "" {
		modified := ""
		if i.Modified {
			modified = ", with uncommitted changes"
		}
		s += fmt.Sprintf("commit   %s (%s)%s\n", i.Revision, i.Time, modified)
	}
	return s + fmt.Sprintf("go       %s %s\nbuild    %s\n", i.Go, i.Platform, i.Build)
}
