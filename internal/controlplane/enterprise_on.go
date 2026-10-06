//go:build enterprise

// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"net/http"

	// Registers the ETL engine with internal/branch. Blank, because nothing
	// here calls it: the free half dispatches through the runner this sets, so
	// that internal/branch never has to import enterprise/. Importing it is
	// what makes the engine exist in this binary.
	_ "github.com/thefoxbyte/foxbyte/enterprise/impact"
	_ "github.com/thefoxbyte/foxbyte/enterprise/pipeline"
	_ "github.com/thefoxbyte/foxbyte/enterprise/promote"
	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/auth"
)

// mountEnterprise registers the paid edition's routes.
//
// api is the inner mux behind the /api/ auth gate, so anything mounted there
// inherits versionAlias, checkBranchName, authorize and the body limits. outer
// is the top-level mux, for the rare route that must do its own authorization —
// a more specific pattern there beats the gate, as GET /api/openapi.yaml already
// relies on.
//
// This is the only file in the repository that may import enterprise/, and it is
// compiled out of the Standard build.
func mountEnterprise(api, outer *http.ServeMux, store *auth.Store, acl *access.Checker) {
	// Stage 3 mounts the realtime feed here.
}
