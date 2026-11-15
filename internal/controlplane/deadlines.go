// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"net/http"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/httpx"
)

// Heavy requests, capped (FOX_MAX_IMPORTS, FOX_MAX_EXPORTS; 4 each by
// default). An import holds a load into a backend and, for a file, up to
// FOX_MAX_UPLOAD_MB of temporary disk; an export holds a connection reading a
// whole result. Past the cap the answer is a 429 straight away, before an
// upload is read, rather than every one of them slowing to a crawl together.
var (
	importSlots = httpx.NewLimiter("imports", httpx.EnvInt("MAX_IMPORTS", 4))
	exportSlots = httpx.NewLimiter("exports", httpx.EnvInt("MAX_EXPORTS", 4))
)

// apiPath is the path as the routes know it: /api/v1/… is /api/….
// versionAlias does the same, but runs after the deadlines are set.
func apiPath(r *http.Request) string {
	if rest, ok := strings.CutPrefix(r.URL.Path, versionedPrefix); ok {
		return "/api/" + rest
	}
	return r.URL.Path
}

// routeBudgets is each request's deadlines (httpx.Deadlines), read from the
// environment once at start.
func routeBudgets() func(*http.Request) httpx.Budget {
	normal, upload, export := httpx.RequestTimeout(), httpx.UploadTimeout(), httpx.ExportTimeout()
	return func(r *http.Request) httpx.Budget {
		switch routeKind(r) {
		case kindUpload:
			// The body is a file of up to gigabytes; its progress stream
			// after it guards each write itself (newSSE).
			return httpx.Budget{Read: upload}
		case kindStream:
			// An event stream may rightly run for hours. Each event has its
			// own write deadline instead (newSSE).
			return httpx.Budget{Read: normal}
		case kindExport:
			return httpx.Budget{Read: normal, Write: export}
		}
		return httpx.Budget{Read: normal, Write: normal}
	}
}

type kind int

const (
	kindNormal kind = iota
	kindUpload
	kindStream
	kindExport
)

func routeKind(r *http.Request) kind {
	p := apiPath(r)
	switch {
	case r.Method == http.MethodPost && p == "/api/import/file":
		return kindUpload
	case r.Method == http.MethodPost && p == "/api/import",
		r.Method == http.MethodPost && strings.HasPrefix(p, "/api/pipelines/") && strings.HasSuffix(p, "/run"),
		r.Method == http.MethodGet && strings.HasPrefix(p, "/api/branches/") && strings.HasSuffix(p, "/realtime"),
		r.Method == http.MethodGet && strings.HasPrefix(p, realtimeAPIPrefix+"/") && strings.HasSuffix(p, "/stream"):
		return kindStream
	case r.Method == http.MethodPost && strings.HasPrefix(p, "/api/branches/") && strings.HasSuffix(p, "/export"),
		r.Method == http.MethodGet && strings.HasPrefix(p, "/api/branches/") && strings.HasSuffix(p, "/ledger/export"),
		r.Method == http.MethodGet && p == "/api/audit-log/evidence",
		r.Method == http.MethodGet && p == "/api/access-review":
		return kindExport
	}
	return kindNormal
}
