//go:build !insecure

// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

// insecureAllowed is false in release builds, so FOX_AGENT_SUPERUSER and
// FOX_MCP_SUPERUSER — superuser SQL for agents and MCP, and a DSN carrying the
// install's master password — are compiled out and no environment variable can
// turn them on. Build with `-tags insecure` where the old behaviour is wanted.
const insecureAllowed = false
