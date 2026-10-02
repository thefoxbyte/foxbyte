//go:build !enterprise

// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"net/http"

	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/auth"
)

// mountEnterprise does nothing in the Standard build: there are no paid routes,
// because none of that code is compiled in. This is the seam, and it is
// deliberately the only one — the core never imports enterprise/ anywhere else.
func mountEnterprise(api, outer *http.ServeMux, store *auth.Store, acl *access.Checker) {}
