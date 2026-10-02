//go:build !enterprise

// SPDX-License-Identifier: AGPL-3.0-or-later

package edition

// Enterprise is false in the Standard build. Nothing under enterprise/ is
// compiled in, so no environment variable, licence file or flag can turn a paid
// feature on — there is no code here to turn on. This is what keeps the
// Standard binary purely AGPL and freely redistributable.
const Enterprise = false
