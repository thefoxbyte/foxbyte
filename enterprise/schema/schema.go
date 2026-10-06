//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

// Package schema installs the Blackbox objects only the paid edition creates:
// the checkpoint table behind signed anchors, the policy rule engine and its
// event trigger, and the impact-analysis functions.
//
// Per feature, not all-or-nothing. A licence covering anchors but not the rule
// engine installs the checkpoint table and not bb.policy_rules, which is the
// same line the commands draw.
package schema

import (
	_ "embed"
	"fmt"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// The schema objects only this edition creates. They live here rather than in
// internal/ledger because that directory is AGPL and these are not: a file's
// licence is its directory's, which is the rule internal/edition's boundary
// test enforces — and it caught this when checkpoints.sql was first written
// with the commercial header while still in internal/ledger.
var (
	//go:embed checkpoints.sql
	schemaCheckpoints string
	//go:embed policy.sql
	schemaPolicy string
	//go:embed impact.sql
	schemaImpact string
)

func init() { branch.SetSchemaInstaller(install) }

func install(name string) error {
	checkpoints, policy, impact := branch.PaidSchemaWanted()
	for _, s := range []struct {
		want bool
		what string
		sql  string
	}{
		// Tamper-evidence: the Merkle commitment the engine anchors outside
		// the database.
		{checkpoints, "Blackbox checkpoints", schemaCheckpoints},
		// The rule engine and its event trigger. The two default guardrails
		// are in datachanges.sql and are installed in every edition — they are
		// not rules, and blocking TRUNCATE is safety rather than compliance.
		{policy, "the Blackbox policy gate", schemaPolicy},
		// bb.blast_radius, which only reads the catalog.
		{impact, "Blackbox impact analysis", schemaImpact},
	} {
		if !s.want {
			continue
		}
		if err := branch.ExecScript(name, s.sql); err != nil {
			return fmt.Errorf("installing %s on %q: %w", s.what, name, err)
		}
	}
	return nil
}
