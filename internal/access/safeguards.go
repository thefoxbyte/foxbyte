// SPDX-License-Identifier: AGPL-3.0-or-later

package access

import (
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// SafeguardAccessOf is the access review's counts for the safeguards
// evidence (point 11.4, Rule 6(1)(b)): read without being recorded as a
// review, which is the person's, not the evidence's.
func SafeguardAccessOf(store *auth.Store) *branch.SafeguardAccess {
	r, err := ProduceReview(store, ReviewOptions{DormantDays: 90})
	if err != nil {
		return &branch.SafeguardAccess{DormantDays: 90, Err: err.Error()}
	}
	s := r.Summary
	return &branch.SafeguardAccess{Accounts: s.Accounts, Admins: s.Admins, Dormant: s.Dormant, Keys: s.Keys, StaleKeys: s.StaleKeys, DormantDays: r.DormantDays}
}
