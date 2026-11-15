// SPDX-License-Identifier: AGPL-3.0-or-later

package httpx

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// Budget is how long one request may take: Read for its body to arrive, Write
// for its whole response to be written. Zero means no deadline.
//
// The server itself has no ReadTimeout or WriteTimeout, on purpose: one figure
// for every route would either cut off an import's progress stream and a long
// export, or leave every other route able to hang for ever. Each request gets
// its own instead (Deadlines).
type Budget struct {
	Read, Write time.Duration
}

// Defaults for the budgets, each overridable by its environment variable.
const (
	// DefaultRequestTimeout bounds an ordinary route: reading its body, and
	// writing its answer. Generous, because creating or waking a branch is an
	// ordinary route too; what matters is that it is not for ever.
	DefaultRequestTimeout = 5 * time.Minute
	// DefaultUploadTimeout bounds receiving a file import's body. 4 GiB at
	// about 10 Mbit/s takes most of an hour.
	DefaultUploadTimeout = 2 * time.Hour
	// DefaultExportTimeout bounds writing an export, a file of a whole result.
	DefaultExportTimeout = time.Hour
)

// StreamWriteTimeout is how long one write to an event stream may stall. A
// stream itself may run for hours; a reader that stops reading is dropped
// after this, rather than holding the stream and what it keeps awake. A
// variable so a test can shorten it.
var StreamWriteTimeout = time.Minute

// EnvDuration reads FOX_<name> as a duration ("90s", "10m"), or def when it is
// unset or unreadable.
func EnvDuration(name string, def time.Duration) time.Duration {
	v := strings.TrimSpace(brand.Getenv(name))
	if v == "" {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d
	}
	return def
}

// EnvInt reads FOX_<name> as a positive whole number, or def.
func EnvInt(name string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(brand.Getenv(name))); err == nil && n > 0 {
		return n
	}
	return def
}

// RequestTimeout is FOX_HTTP_TIMEOUT, the budget of an ordinary route.
func RequestTimeout() time.Duration { return EnvDuration("HTTP_TIMEOUT", DefaultRequestTimeout) }

// UploadTimeout is FOX_UPLOAD_TIMEOUT, the time a file import's upload may take.
func UploadTimeout() time.Duration { return EnvDuration("UPLOAD_TIMEOUT", DefaultUploadTimeout) }

// ExportTimeout is FOX_EXPORT_TIMEOUT, the time an export may take to write.
func ExportTimeout() time.Duration { return EnvDuration("EXPORT_TIMEOUT", DefaultExportTimeout) }

// Deadlines sets each request's read and write deadlines from budget.
//
// The read deadline covers the body only, and is lifted once the body has been
// read: past that point, net/http watches the connection to notice a client
// that went away, and a read deadline still set would end the request's
// context while its handler was working. A request with no body gets none.
//
// The write deadline is always set, to the budget or to none: a kept-alive
// connection otherwise carries the last request's deadline into the next.
func Deadlines(budget func(*http.Request) Budget) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b := budget(r)
			rc := http.NewResponseController(w)
			now := time.Now()
			if b.Write > 0 {
				_ = rc.SetWriteDeadline(now.Add(b.Write))
			} else {
				_ = rc.SetWriteDeadline(time.Time{})
			}
			if b.Read > 0 && r.Body != nil && r.Body != http.NoBody {
				if rc.SetReadDeadline(now.Add(b.Read)) == nil {
					r.Body = &liftOnEOF{ReadCloser: r.Body, lift: func() { _ = rc.SetReadDeadline(time.Time{}) }}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// liftOnEOF lifts the read deadline once the body has been read to its end.
type liftOnEOF struct {
	io.ReadCloser
	once sync.Once
	lift func()
}

func (b *liftOnEOF) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.once.Do(b.lift)
	}
	return n, err
}

// StreamWrite writes one piece of a long-lived response (an event, a chunk of
// an export) under its own deadline, and then lifts it. Lifting matters as
// much as setting: HTTP/2 ends a stream whose deadline passes even while
// nothing is being written, and an event stream may be quiet for minutes.
func StreamWrite(w http.ResponseWriter, write func() error) error {
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(StreamWriteTimeout))
	err := write()
	if err == nil {
		err = rc.Flush()
	}
	_ = rc.SetWriteDeadline(time.Time{})
	return err
}

// Limiter caps how many of one kind of heavy request (an import, an export)
// run at once. Each holds a backend, a connection and possibly gigabytes of
// temporary disk; past the cap a request is refused straight away with 429,
// before its body is read, rather than queued behind the others.
type Limiter struct {
	what  string
	slots chan struct{}
}

// NewLimiter allows max requests at once; what names them in the refusal.
func NewLimiter(what string, max int) *Limiter {
	if max < 1 {
		max = 1
	}
	return &Limiter{what: what, slots: make(chan struct{}, max)}
}

// Wrap runs next while holding a slot, or refuses with 429 when none is free.
func (l *Limiter) Wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		select {
		case l.slots <- struct{}{}:
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprintf(w, "{\"error\":%q}\n", fmt.Sprintf(
				"%d %s already running, the most this server runs at once; try again when one has finished",
				cap(l.slots), l.what))
			return
		}
		defer func() { <-l.slots }()
		next(w, r)
	}
}
