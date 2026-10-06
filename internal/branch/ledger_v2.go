// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"os"

	"github.com/thefoxbyte/foxbyte/internal/edition"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// installPaidSchema installs the schema objects only the paid edition creates,
// and is supplied by enterprise/schema in an Enterprise build.
//
// The schema lives in the database, not in the binary, and that is the whole
// shape of this. A branch keeps whatever it was given: one checkpointed or
// given policy rules before an install changed edition keeps those tables, and
// everything already recorded in them stays readable and verifiable. What an
// edition decides is only what gets *created* from here on.
var installPaidSchema func(name string) error

// SetSchemaInstaller installs it. Called from enterprise/schema's init, and
// from nowhere else.
func SetSchemaInstaller(fn func(name string) error) { installPaidSchema = fn }

// EnsureLedgerV2 installs (or upgrades) the Blackbox 2.0 additions on a
// branch. It is idempotent and needs the base ledger (InstallLedger) first.
func EnsureLedgerV2(name string) error {
	if name == "" {
		name = "main"
	}
	// The free half, in every edition.
	for _, s := range []struct {
		what string
		sql  string
	}{
		// Richer recording, keyed by ledger row id. Not proof — that is
		// checkpoints.sql, which is the paid half below.
		{"ledger 2.0 capture", ledger.SchemaExt},
		// Agent provenance (bb.agent_sessions). Free: the MCP server records a
		// session for every change an agent makes, `fox blackbox sessions`
		// reads them back, and agent branches carry one. Knowing which agent
		// did what is part of the guardrails, not part of the paid tier.
		{"Blackbox provenance", ledger.SchemaProvenance},
		// TRUNCATE and agents' data changes (datachanges.sql). The two default
		// guardrails, which are free and are not policy rules.
		{"Blackbox data-change capture", ledger.SchemaData},
	} {
		if err := psqlStdin(name, s.sql); err != nil {
			return fmt.Errorf("installing %s on %q: %w", s.what, name, err)
		}
	}
	// And the paid half, when this build has it and a licence covers it.
	if installPaidSchema == nil {
		return nil
	}
	return installPaidSchema(name)
}

// PaidSchemaWanted reports which paid schema objects this install may create.
// enterprise/schema asks, so the decision stays with internal/edition rather
// than being made twice.
func PaidSchemaWanted() (checkpoints, policy, impact bool) {
	return edition.Has(edition.Anchors), edition.Has(edition.Policy), edition.Has(edition.Impact)
}

// ensureLedgerV2BestEffort installs the 2.0 additions during engine start. 2.0
// must never stop the stack from coming up, so a failure is only reported.
func ensureLedgerV2BestEffort(name string) {
	if err := EnsureLedgerV2(name); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v — the base ledger is unaffected; retry with: fox ledger upgrade %s\n", err, name)
	}
}
