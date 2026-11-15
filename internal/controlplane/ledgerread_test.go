// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"net/url"
	"strings"
	"testing"
)

// The listing names the statement column exactly where ledgerPlan swaps it,
// so a reworded query cannot quietly start selecting it as a client again.
func TestLedgerPlanSwapsTheStatementColumn(t *testing.T) {
	q := ledgerSQL(url.Values{"with": {"chain,session"}})
	if !strings.Contains(q, " statement, ") {
		t.Fatalf("ledgerSQL no longer has ' statement, ' to swap:\n%s", q)
	}

	sql, how := ledgerPlan(false, false, q)
	if how != ledgerAsCaller || !strings.Contains(sql, ledgerStatementSQL) || strings.Contains(sql, " statement, ") {
		t.Errorf("a reader who does not manage the branch: how=%d\n%s", how, sql)
	}

	sql, how = ledgerPlan(false, true, q)
	if how != ledgerAsEngine || sql != q {
		t.Errorf("whoever manages the branch reads every statement as the engine: how=%d", how)
	}

	// Masked wins over managing: no statement text at all.
	sql, how = ledgerPlan(true, true, q)
	if how != ledgerMasked || !strings.Contains(sql, maskedStatementSQL) || strings.Contains(sql, ledgerStatementSQL) {
		t.Errorf("a masked account: how=%d\n%s", how, sql)
	}
}
