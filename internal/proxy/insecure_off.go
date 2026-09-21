//go:build !insecure

// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy

// insecureAllowed is false in release builds, so FOX_GATEWAY_NOAUTH (a
// full authentication bypass) is compiled out and cannot be enabled by an
// environment variable in production. Build with `-tags insecure` for
// trusted/local use where the bypass is wanted.
const insecureAllowed = false
