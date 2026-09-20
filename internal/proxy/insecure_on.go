//go:build insecure

// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy

// insecureAllowed is true only in builds made with `-tags insecure`, enabling
// the FOX_GATEWAY_NOAUTH escape hatch for trusted/local use.
const insecureAllowed = true
