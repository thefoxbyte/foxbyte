// SPDX-License-Identifier: AGPL-3.0-or-later

package access

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// The access review report (point 4.8): every account, what it can reach and
// with which credentials, who may override the guardrails where, and who has
// gone quiet. Enterprise; enterprise/accessreview computes it. The types and
// the CSV are here, where the CLI and the API both reach them.

// DefaultDormantDays is how long without activity makes an account dormant,
// and a key stale, when not told.
const DefaultDormantDays = 90

// ReviewOptions is what a report is asked for.
type ReviewOptions struct {
	DormantDays int
	Now         time.Time // zero for now; the tests fix it
}

// Review is the report.
type Review struct {
	Generated   time.Time       `json:"generated"`
	DormantDays int             `json:"dormantDays"`
	Summary     ReviewSummary   `json:"summary"`
	Accounts    []ReviewAccount `json:"accounts"`
	Keys        []ReviewKey     `json:"keys"`
	Branches    []ReviewBranch  `json:"branches"`
	// Limits are what the report cannot claim, in sentences, as a
	// personal-data scan's are.
	Limits []string `json:"limits"`
}

// ReviewSummary is the counts a reader looks at first.
type ReviewSummary struct {
	Accounts  int `json:"accounts"`
	Admins    int `json:"admins"`
	Dormant   int `json:"dormant"`
	Keys      int `json:"keys"`
	AgentKeys int `json:"agentKeys"`
	StaleKeys int `json:"staleKeys"`
	Branches  int `json:"branches"`
	Unowned   int `json:"unowned"`
}

// ReviewAccount is one account and what it can reach.
type ReviewAccount struct {
	ID      int64     `json:"id"`
	Email   string    `json:"email"`
	Created time.Time `json:"created"`
	// Admin is an install admin: Manage on every branch, and the
	// guardrail override on main.
	Admin bool `json:"admin"`
	// Reaches says what the account can open, in a phrase.
	Reaches string `json:"reaches"`
	// Owns are the branches it owns (Manage on each).
	Owns []string `json:"owns"`
	// OverrideOn are the branches, other than through being an install
	// admin, where it may override the guardrails (a member of db_admin).
	OverrideOn []string `json:"overrideOn"`
	Keys       int      `json:"keys"`
	// Unmasked says what it can see without masking.
	Unmasked   string     `json:"unmasked"`
	LastSignIn *time.Time `json:"lastSignIn"`
	LastKeyUse *time.Time `json:"lastKeyUse"`
	LastQuery  *time.Time `json:"lastQuery"`
	LastActive *time.Time `json:"lastActive"`
	Dormant    bool       `json:"dormant"`
}

// ReviewKey is one credential.
type ReviewKey struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Prefix string `json:"prefix"`
	Owner  string `json:"owner"`
	// Kind is account, agent or realtime; Identity says what that means
	// for who is behind it.
	Kind     string     `json:"kind"`
	Identity string     `json:"identity"`
	Reach    string     `json:"reach"`
	Created  time.Time  `json:"created"`
	LastUsed *time.Time `json:"lastUsed"`
	AgeDays  int        `json:"ageDays"`
	Stale    bool       `json:"stale"`
	Why      string     `json:"why,omitempty"` // why it is stale
}

// ReviewBranch is one branch: who owns it and who may override its
// guardrails.
type ReviewBranch struct {
	Name   string   `json:"name"`
	State  string   `json:"state"`
	Owner  string   `json:"owner"`
	Admins []string `json:"admins"`
	// Asked is whether the branch was running, so its admins could be
	// read; a suspended branch is not woken to answer.
	Asked bool `json:"asked"`
}

var reviewer func(store *auth.Store, o ReviewOptions) (Review, error)

// SetReviewer installs the report. Called from enterprise/accessreview's init,
// and from nowhere else.
func SetReviewer(fn func(store *auth.Store, o ReviewOptions) (Review, error)) { reviewer = fn }

// ErrReviewNotLicensed is the report refused for want of a licence.
var ErrReviewNotLicensed = errors.New("this install is not licensed for " + edition.Describe(edition.AccessReview))

// ErrBadReview is a request the report cannot answer as asked.
var ErrBadReview = errors.New("invalid request")

// ProduceReview builds the report from the store and the branches.
func ProduceReview(store *auth.Store, o ReviewOptions) (Review, error) {
	if !edition.Has(edition.AccessReview) || reviewer == nil {
		return Review{}, ErrReviewNotLicensed
	}
	if o.DormantDays == 0 {
		o.DormantDays = DefaultDormantDays
	}
	if o.DormantDays < 1 || o.DormantDays > 3650 {
		return Review{}, fmt.Errorf("%w: dormant is 1 to 3650 days, not %d", ErrBadReview, o.DormantDays)
	}
	if store == nil {
		return Review{}, errors.New("the account store is not open")
	}
	return reviewer(store, o)
}

// LogLine is the security log's line for a report.
func (r Review) LogLine() string {
	return fmt.Sprintf("%d account(s), %d dormant after %d days; %d key(s), %d stale; %d branch(es), %d unowned",
		r.Summary.Accounts, r.Summary.Dormant, r.DormantDays, r.Summary.Keys, r.Summary.StaleKeys, r.Summary.Branches, r.Summary.Unowned)
}

// ReviewSections are the report's tables, each its own CSV.
var ReviewSections = []string{"accounts", "keys", "branches"}

// CSV writes one section of the report. Each value goes through csvCell, so
// a name a person chose cannot become a formula in a spreadsheet.
func (r Review) CSV(section string, w io.Writer) error {
	cw := csv.NewWriter(w)
	when := func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.UTC().Format(time.RFC3339)
	}
	yes := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	var rows [][]string
	switch section {
	case "accounts":
		rows = append(rows, []string{"email", "created", "admin", "reaches", "owns", "override_on", "keys", "unmasked",
			"last_sign_in", "last_key_use", "last_query", "last_active", "dormant"})
		for _, a := range r.Accounts {
			rows = append(rows, []string{a.Email, a.Created.UTC().Format(time.RFC3339), yes(a.Admin), a.Reaches,
				strings.Join(a.Owns, " "), strings.Join(a.OverrideOn, " "), strconv.Itoa(a.Keys), a.Unmasked,
				when(a.LastSignIn), when(a.LastKeyUse), when(a.LastQuery), when(a.LastActive), yes(a.Dormant)})
		}
	case "keys":
		rows = append(rows, []string{"id", "name", "prefix", "owner", "kind", "identity", "reach", "created", "last_used",
			"age_days", "stale", "why"})
		for _, k := range r.Keys {
			rows = append(rows, []string{k.ID, k.Name, k.Prefix, k.Owner, k.Kind, k.Identity, k.Reach,
				k.Created.UTC().Format(time.RFC3339), when(k.LastUsed), strconv.Itoa(k.AgeDays), yes(k.Stale), k.Why})
		}
	case "branches":
		rows = append(rows, []string{"branch", "state", "owner", "admins", "admins_read"})
		for _, b := range r.Branches {
			rows = append(rows, []string{b.Name, b.State, b.Owner, strings.Join(b.Admins, " "), yes(b.Asked)})
		}
	default:
		return fmt.Errorf("%w: a section is %s, not %q", ErrBadReview, strings.Join(ReviewSections, ", "), section)
	}
	for _, row := range rows {
		for i := range row {
			row[i] = csvCell(row[i])
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// csvCell neutralises a value a spreadsheet would run as a formula: a key's
// name or an email is whatever someone typed.
func csvCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
