//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"fmt"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// Applying what Assess worked out.
//
// Nothing here decides anything: the ladder is in readiness.go and the
// statements are already written by the time they arrive. This is only the part
// that runs them, and the part that refuses to run the expensive one in bulk.

// Prepare runs a verdict's fixes against a branch.
//
// Every statement goes through the ordinary SQL path, which means the Blackbox
// records each one with the login behind it, like any other DDL. That is worth
// having rather than working around: "enabling realtime granted SELECT on these
// nine tables and set a replica identity on two" is exactly the question an
// auditor asks, and the answer already exists.
func Prepare(branchName string, v Verdict) error {
	if len(v.Fixes) == 0 {
		return nil
	}
	target := branch.ServingBranch(branchName)
	for _, f := range v.Fixes {
		if err := branch.ExecSQL(target, f.SQL); err != nil {
			return fmt.Errorf("%s: %w", strings.TrimSuffix(f.SQL, ";"), err)
		}
	}
	return nil
}

// PrepareAll runs the free fixes for every table that has some, and reports
// what it left alone.
//
// It never applies a costly fix. REPLICA IDENTITY FULL doubles the WAL a table
// writes for as long as it exists, and a bulk action is exactly where nobody
// reads the small print — so those tables come back as `skipped` for the caller
// to put in front of a person, one at a time, with the number attached.
func PrepareAll(branchName string, verdicts []Verdict, apply bool) (done []Verdict, skipped []Verdict, err error) {
	for _, v := range verdicts {
		if v.State != Fixable {
			continue
		}
		if v.Costly() {
			skipped = append(skipped, v)
			continue
		}
		if apply {
			if err := Prepare(branchName, v); err != nil {
				return done, skipped, err
			}
		}
		done = append(done, v)
	}
	return done, skipped, nil
}
