//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package accessreview

import (
	"fmt"
	"sort"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

func init() { access.SetReviewer(review) }

// inputs is everything the report is built from, gathered first so the
// building is a pure function the tests can drive.
type inputs struct {
	accounts []auth.Account
	keys     []auth.KeyRecord
	owners   map[string]int64     // branch → owner's account id
	signIns  map[string]time.Time // email → last console sign-in
	queries  map[string]time.Time // email → last query history kept
	branches []branch.BranchInfo
	admins   map[string][]string // running branch → db_admin members
	limits   []string            // what gathering could not read
}

func review(store *auth.Store, o access.ReviewOptions) (access.Review, error) {
	in, err := gather(store)
	if err != nil {
		return access.Review{}, err
	}
	now := o.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return build(in, o.DormantDays, now), nil
}

func gather(store *auth.Store) (inputs, error) {
	var in inputs
	var err error
	if in.accounts, err = store.ListAccounts(); err != nil {
		return in, fmt.Errorf("listing accounts: %w", err)
	}
	if in.keys, err = store.AllKeys(); err != nil {
		return in, fmt.Errorf("listing keys: %w", err)
	}
	if in.owners, err = store.BranchOwners(); err != nil {
		return in, fmt.Errorf("listing branch owners: %w", err)
	}
	if in.signIns, err = store.LastSignIns(); err != nil {
		return in, fmt.Errorf("reading sign-ins: %w", err)
	}
	if in.queries, err = store.LastQueries(); err != nil {
		// History may be off, or its table not made yet: a weaker report,
		// said so, rather than none.
		in.queries = map[string]time.Time{}
		in.limits = append(in.limits, "Query history could not be read, so a query is not counted as activity.")
	}
	if in.branches, err = branch.Branches(); err != nil {
		return in, fmt.Errorf("listing branches: %w", err)
	}
	running, err := branch.RunningBranches()
	if err != nil {
		return in, fmt.Errorf("listing running branches: %w", err)
	}
	in.admins = map[string][]string{}
	for _, b := range running {
		if a, err := branch.ListAdmins(b); err == nil {
			in.admins[b] = a
		}
	}
	return in, nil
}

// build turns the inputs into the report.
func build(in inputs, dormantDays int, now time.Time) access.Review {
	r := access.Review{Generated: now, DormantDays: dormantDays, Accounts: []access.ReviewAccount{},
		Keys: []access.ReviewKey{}, Branches: []access.ReviewBranch{}}
	cutoff := now.Add(-time.Duration(dormantDays) * 24 * time.Hour)
	ptr := func(t time.Time) *time.Time {
		if t.IsZero() {
			return nil
		}
		t = t.UTC()
		return &t
	}
	emails := map[int64]string{}
	for _, a := range in.accounts {
		emails[a.ID] = a.Email
	}
	installAdmins := map[string]bool{}
	for _, m := range in.admins["main"] {
		installAdmins[m] = true
	}

	// Keys first: an account's last key use is the newest of its keys'.
	lastKeyUse := map[int64]time.Time{}
	keyCount := map[int64]int{}
	for _, k := range in.keys {
		keyCount[k.UserID]++
		if k.LastUsed.After(lastKeyUse[k.UserID]) {
			lastKeyUse[k.UserID] = k.LastUsed
		}
		rk := access.ReviewKey{ID: k.ID, Name: k.Name, Prefix: k.Prefix, Owner: k.Email, Created: k.Created,
			LastUsed: ptr(k.LastUsed), AgeDays: int(now.Sub(k.Created).Hours() / 24)}
		switch k.Kind {
		case auth.KindAgent:
			rk.Kind, rk.Identity = "agent", "an agent, identified by the key it logs in with"
		case auth.KindRealtime:
			rk.Kind, rk.Identity = "realtime", "an application reading the change feed; no SQL"
		default:
			rk.Kind, rk.Identity = "account", "the account's owner, or an application acting as them"
		}
		rk.Reach = "what " + k.Email + " reaches"
		if k.Scope != "" {
			rk.Reach = "the branch " + k.Scope + " only"
		}
		switch {
		case k.LastUsed.IsZero() && k.Created.Before(cutoff):
			rk.Stale, rk.Why = true, fmt.Sprintf("never used, made %d days ago", rk.AgeDays)
		case !k.LastUsed.IsZero() && k.LastUsed.Before(cutoff):
			rk.Stale, rk.Why = true, fmt.Sprintf("last used %d days ago", int(now.Sub(k.LastUsed).Hours()/24))
		}
		if rk.Kind == "agent" {
			r.Summary.AgentKeys++
		}
		if rk.Stale {
			r.Summary.StaleKeys++
		}
		r.Keys = append(r.Keys, rk)
	}

	owns := map[int64][]string{}
	for b, id := range in.owners {
		owns[id] = append(owns[id], b)
	}
	for _, a := range in.accounts {
		ra := access.ReviewAccount{ID: a.ID, Email: a.Email, Created: time.Unix(a.Created, 0).UTC(),
			Admin: installAdmins[a.Email], Owns: owns[a.ID], OverrideOn: []string{}, Keys: keyCount[a.ID]}
		sort.Strings(ra.Owns)
		if ra.Owns == nil {
			ra.Owns = []string{}
		}
		for b, members := range in.admins {
			if b == "main" && ra.Admin {
				continue // that is what being an install admin is
			}
			for _, m := range members {
				if m == a.Email {
					ra.OverrideOn = append(ra.OverrideOn, b)
				}
			}
		}
		sort.Strings(ra.OverrideOn)
		switch {
		case ra.Admin:
			ra.Reaches = "every branch (an install admin)"
		case len(ra.Owns) > 0:
			ra.Reaches = fmt.Sprintf("main, and the %d branch(es) it owns", len(ra.Owns))
		default:
			ra.Reaches = "main"
		}
		ra.Unmasked = "everything the branches it reaches hold: no masking is in place (point 7)"
		ra.LastSignIn = ptr(in.signIns[a.Email])
		ra.LastKeyUse = ptr(lastKeyUse[a.ID])
		ra.LastQuery = ptr(in.queries[a.Email])
		var last time.Time
		for _, t := range []time.Time{in.signIns[a.Email], lastKeyUse[a.ID], in.queries[a.Email]} {
			if t.After(last) {
				last = t
			}
		}
		ra.LastActive = ptr(last)
		// A new account is not dormant; one older than the window with no
		// activity inside it is.
		ra.Dormant = ra.Created.Before(cutoff) && (last.IsZero() || last.Before(cutoff))
		if ra.Admin {
			r.Summary.Admins++
		}
		if ra.Dormant {
			r.Summary.Dormant++
		}
		r.Accounts = append(r.Accounts, ra)
	}

	notAsked := 0
	for _, b := range in.branches {
		if b.Name == "restore" || b.Name == "standby" {
			continue
		}
		rb := access.ReviewBranch{Name: b.Name, State: b.State, Admins: []string{}}
		if id, ok := in.owners[b.Name]; ok {
			rb.Owner = emails[id]
		}
		if m, ok := in.admins[b.Name]; ok {
			rb.Admins, rb.Asked = m, true
		} else {
			notAsked++
		}
		if rb.Owner == "" && b.Name != "main" {
			r.Summary.Unowned++
		}
		r.Branches = append(r.Branches, rb)
	}
	sort.Slice(r.Branches, func(i, j int) bool {
		if (r.Branches[i].Name == "main") != (r.Branches[j].Name == "main") {
			return r.Branches[i].Name == "main"
		}
		return r.Branches[i].Name < r.Branches[j].Name
	})

	r.Summary.Accounts, r.Summary.Keys, r.Summary.Branches = len(r.Accounts), len(r.Keys), len(r.Branches)
	r.Limits = append([]string{
		"No masking is in place yet (point 7), so there are no unmask rights to review: every account sees, unmasked, what the branches it reaches hold.",
		fmt.Sprintf("Last active is the newest of a console sign-in, a key's use (recorded to the minute) and a query kept in history. Dormant means no activity FoxByte saw in %d days: a role someone made directly in Postgres is not seen.", dormantDays),
		"Identity is what each credential is: an agent key marks an agent by how it logs in. A signed identity for each transaction (F1) is not in place yet.",
	}, in.limits...)
	if notAsked > 0 {
		r.Limits = append(r.Limits, fmt.Sprintf("%d branch(es) were not running, so who may override their guardrails was not read: a suspended branch is not woken for a report.", notAsked))
	}
	return r
}
