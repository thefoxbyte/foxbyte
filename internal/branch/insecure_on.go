//go:build insecure

// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

// insecureAllowed is true only in builds made with `-tags insecure`, enabling
// the FOX_AGENT_SUPERUSER and FOX_MCP_SUPERUSER escape hatches.
const insecureAllowed = true
