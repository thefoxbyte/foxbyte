//go:build enterprise

// SPDX-License-Identifier: AGPL-3.0-or-later

package edition

// Enterprise is true in builds made with `-tags enterprise`, which compile in
// the code under enterprise/. It does not mean the features are unlocked: that
// is Has, and it needs a licence.
const Enterprise = true
