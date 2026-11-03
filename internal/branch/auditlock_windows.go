// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package branch

// lockAuditStore: the engine never runs on Windows itself (it runs in WSL,
// which is Linux), so there is no store here to share.
func lockAuditStore() (func(), error) { return func() {}, nil }
