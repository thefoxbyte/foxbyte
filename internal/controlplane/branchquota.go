// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"errors"
	"net/http"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// allowCreate holds a request that would make a branch — a create, an import,
// a point-in-time restore — to the caller's branch limit and create rate
// (branch/quota.go), answering for it when it is refused. Admins pass.
func allowCreate(w http.ResponseWriter, r *http.Request) bool {
	u, _ := auth.UserFrom(r.Context())
	if err := branch.AllowBranchCreate(u.ID, acl.Admin(u)); err != nil {
		writeErr(w, createRefusalCode(err), err)
		return false
	}
	return true
}

// createRefusalCode is the status for a refused create: 429 for the rate,
// which waiting fixes, 403 for the limit, which only a delete does.
func createRefusalCode(err error) int {
	switch {
	case errors.Is(err, branch.ErrCreateRate):
		return http.StatusTooManyRequests
	case errors.Is(err, branch.ErrBranchQuota):
		return http.StatusForbidden
	}
	return http.StatusInternalServerError
}
