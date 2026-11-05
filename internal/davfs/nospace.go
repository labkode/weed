package davfs

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/labkode/weed/internal/metrics"
	"golang.org/x/sys/unix"
)

// A write that the storage refuses as it is full (ENOSPC), or as the account is over
// its quota (EDQUOT), is answered 507 Insufficient Storage, which clients tell from a
// fault of the server (500), counted, and logged at most once a minute

// NoSpace says why the storage refused err: "full", "quota", or "" if it did not
func NoSpace(err error) string {
	switch {
	case errors.Is(err, unix.ENOSPC):
		return "full"
	case errors.Is(err, unix.EDQUOT):
		return "quota"
	}
	return ""
}

// noSpaceLogged is when each reason was last logged (unix nanoseconds), and how many
// refusals were not logged since
var noSpaceLogged = map[string]*struct{ at, since atomic.Int64 }{"full": {}, "quota": {}}

// NoteNoSpace counts err, if the storage refused it for lack of space, logs it unless
// it logged one of the same reason less than a minute ago, and says why (see NoSpace)
func NoteNoSpace(ctx context.Context, path string, err error) string {
	why := NoSpace(err)
	if why == "" {
		return ""
	}
	metrics.StorageFull.Inc(why)
	l := noSpaceLogged[why]
	now, last := time.Now().UnixNano(), l.at.Load()
	if now-last < int64(time.Minute) || !l.at.CompareAndSwap(last, now) {
		l.since.Add(1)
		return why
	}
	msg := "the storage is full: writes get 507 Insufficient Storage"
	if why == "quota" {
		msg = "an account is over its quota on the storage: its writes get 507 Insufficient Storage"
	}
	slog.WarnContext(ctx, msg, "path", path, "error", err, "not_logged_since", l.since.Swap(0))
	return why
}

type noSpaceKey struct{}

// TrackNoSpace returns a context in which the first FS operation that the storage
// refuses for lack of space stores its error in full
func TrackNoSpace(ctx context.Context, full *atomic.Pointer[error]) context.Context {
	return context.WithValue(ctx, noSpaceKey{}, full)
}

func noteNoSpaceIn(ctx context.Context, err error) {
	if NoSpace(err) != "" {
		if full, ok := ctx.Value(noSpaceKey{}).(*atomic.Pointer[error]); ok {
			full.CompareAndSwap(nil, &err)
		}
	}
}
