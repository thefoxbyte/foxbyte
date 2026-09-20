// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"os"

	"github.com/foxbyte/foxbyte/internal/ledger"
)

// EnsureLedgerV2 installs (or upgrades) the Blackbox 2.0 additions on a
// branch. It is idempotent and needs the base ledger (InstallLedger) first.
func EnsureLedgerV2(name string) error {
	if name == "" {
		name = "main"
	}
	if err := psqlStdin(name, ledger.SchemaV2); err != nil {
		return fmt.Errorf("installing ledger 2.0 on %q: %w", name, err)
	}
	// The policy gate (docs/policy-errors.md) builds on the 2.0 objects above.
	if err := psqlStdin(name, ledger.SchemaPolicy); err != nil {
		return fmt.Errorf("installing the Blackbox policy gate on %q: %w", name, err)
	}
	// Agent provenance (bb.agent_sessions) builds on the same 2.0 objects.
	if err := psqlStdin(name, ledger.SchemaProvenance); err != nil {
		return fmt.Errorf("installing Blackbox provenance on %q: %w", name, err)
	}
	// Impact analysis (bb.blast_radius) only reads the catalog.
	if err := psqlStdin(name, ledger.SchemaImpact); err != nil {
		return fmt.Errorf("installing Blackbox impact analysis on %q: %w", name, err)
	}
	return nil
}

// ensureLedgerV2BestEffort installs the 2.0 additions during engine start. 2.0
// must never stop the stack from coming up, so a failure is only reported.
func ensureLedgerV2BestEffort(name string) {
	if err := EnsureLedgerV2(name); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v — the base ledger is unaffected; retry with: fox ledger upgrade %s\n", err, name)
	}
}
