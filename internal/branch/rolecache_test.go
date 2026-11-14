// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import "testing"

// The gateway remembers that it has already created a person's role. Deleting
// the branch and creating it again happens in another process, which cannot
// clear that memory. ForgetUserRole is what the gateway calls when Postgres
// then refuses the login, so the role is made on the new clone.
func TestForgetUserRoleDropsOnlyThatBranch(t *testing.T) {
	const (
		plain  = "dev\x00a@b.co\x00plain"
		masked = "dev\x00a@b.co\x00masked"
		other  = "other\x00a@b.co\x00plain"
	)
	ensuredRoles.Store(plain, struct{}{})
	ensuredRoles.Store(masked, struct{}{})
	ensuredRoles.Store(other, struct{}{})
	t.Cleanup(func() {
		ensuredRoles.Delete(plain)
		ensuredRoles.Delete(masked)
		ensuredRoles.Delete(other)
	})

	ForgetUserRole("dev", "a@b.co")
	if _, ok := ensuredRoles.Load(plain); ok {
		t.Error("the plain role on dev was remembered")
	}
	if _, ok := ensuredRoles.Load(masked); ok {
		t.Error("the masked role on dev was remembered")
	}
	if _, ok := ensuredRoles.Load(other); !ok {
		t.Error("another branch's role was forgotten")
	}
}
