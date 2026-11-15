// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// How many branches one account may have, and how fast it may make them.
//
// Every branch is a whole Postgres. Without a limit, one account — or one
// agent loop running under it — could make containers until the machine ran
// out, and would use up the install-wide agent cap (FOX_AGENT_MAX) that every
// other account's agents share. So each account may own a set number of
// branches (FOX_MAX_BRANCHES_PER_ACCOUNT, 20 by default, 0 for no limit), and
// may start a set number of creates, imports and point-in-time restores a
// minute (FOX_BRANCH_CREATES_PER_MINUTE, 10 by default, 0 for no limit).
//
// Admins are exempt, and so is the command line, which only an admin of the
// machine can run. The count is the owner records the account store keeps, so
// it is the same in every process that makes branches.

// ErrBranchQuota: the account owns as many branches as it may.
var ErrBranchQuota = errors.New("branch limit reached")

// ErrCreateRate: the account has made branches faster than it may.
var ErrCreateRate = errors.New("too many branches made too quickly")

const (
	EnvMaxBranchesPerAccount  = "MAX_BRANCHES_PER_ACCOUNT"
	EnvBranchCreatesPerMinute = "BRANCH_CREATES_PER_MINUTE"

	defaultMaxBranchesPerAccount  = 20
	defaultBranchCreatesPerMinute = 10
)

func envLimit(name string, def int) int {
	if v := strings.TrimSpace(brand.Getenv(name)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return def
}

// MaxBranchesPerAccount is the per-account branch limit; 0 means none.
func MaxBranchesPerAccount() int {
	return envLimit(EnvMaxBranchesPerAccount, defaultMaxBranchesPerAccount)
}

// BranchCreatesPerMinute is the per-account create rate; 0 means none.
func BranchCreatesPerMinute() int {
	return envLimit(EnvBranchCreatesPerMinute, defaultBranchCreatesPerMinute)
}

// ownedBranches counts an account's branches, a variable so a test can count
// without a store.
var ownedBranches = func(owner int64) (int, error) {
	st, err := auth.OpenFromEnv()
	if err != nil {
		return 0, err
	}
	defer st.Close()
	return st.OwnedBranchCount(owner)
}

// createRate is a sliding one-minute window of each account's creates. It is
// this process's own: the control plane, the Agent API and MCP each keep one,
// which bounds a burst through any one door; the branch limit, read from the
// shared store, is what bounds the total.
var createRate = struct {
	mu   sync.Mutex
	seen map[int64][]time.Time
	now  func() time.Time
}{seen: map[int64][]time.Time{}, now: time.Now}

// AllowBranchCreate says whether owner may start making one more branch now: a
// create, an import, or a point-in-time restore into a new branch. admin is
// whether the caller is an admin, who is never limited; owner 0 is the command
// line, which is not limited either. A creation that is allowed counts against
// the rate even if it then fails, so failing creates cannot be retried without
// pause.
//
// The error wraps ErrCreateRate (answer 429) or ErrBranchQuota.
func AllowBranchCreate(owner int64, admin bool) error {
	if admin || owner == 0 {
		return nil
	}
	if max := MaxBranchesPerAccount(); max > 0 {
		n, err := ownedBranches(owner)
		if err != nil {
			return fmt.Errorf("counting your branches: %w", err)
		}
		if n >= max {
			return fmt.Errorf("%w: this account owns %d branches and may own at most %d; delete one first (an admin can raise %s)",
				ErrBranchQuota, n, max, brand.EnvName(EnvMaxBranchesPerAccount))
		}
	}
	per := BranchCreatesPerMinute()
	if per <= 0 {
		return nil
	}
	createRate.mu.Lock()
	defer createRate.mu.Unlock()
	now := createRate.now()
	recent := createRate.seen[owner][:0]
	for _, t := range createRate.seen[owner] {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	if len(recent) >= per {
		createRate.seen[owner] = recent
		wait := time.Minute - now.Sub(recent[0])
		return fmt.Errorf("%w: at most %d a minute per account; try again in %ds",
			ErrCreateRate, per, int(wait.Seconds())+1)
	}
	createRate.seen[owner] = append(recent, now)
	return nil
}
