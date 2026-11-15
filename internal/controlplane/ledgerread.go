// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// ledgerStatementSQL is how a reader without the whole branch in their care
// gets a Blackbox entry's statement: through bb.ledger_statement, which gives
// a login the text of its own entries and nobody else's (audit PRIV-3). The
// text of a change can hold the values it wrote, and db_client may no longer
// read the column itself.
const ledgerStatementSQL = `bb.ledger_statement(bb.schema_ledger.id) AS statement`

// readLedger answers the console's Blackbox listing for one caller.
//
// Whoever manages the branch (an admin anywhere, or the owner of a branch
// that is not main) reviews every entry on it, its agents' included: that is
// what the Blackbox is for, and they could read those tables anyway. They read
// over the engine's own connection. Everybody else reads as their own login,
// and sees the statements of their own entries only; on main, which every
// account may use, that keeps one person's literals from the next. A masked
// account sees no statement text at all, as before.
func readLedger(r *http.Request, addr, name, q string) map[string]any {
	u, _ := auth.UserFrom(r.Context())
	masked := branch.AccountMaskedOn(name, u.Email)
	// Level is Manage for an admin anywhere and for a branch's owner; main has
	// no owner, so there it is admins only.
	manages := acl != nil && acl.Can(u, name, access.Manage)
	sql, how := ledgerPlan(masked, manages, q)
	switch how {
	case ledgerAsEngine:
		return readLedgerAsEngine(name, sql)
	case ledgerAsCaller:
		return runQuery(addr, sql, queryAs{Branch: name, Actor: u.Email})
	}
	return runQuery(addr, sql, queryAs{})
}

type ledgerRead int

const (
	ledgerMasked   ledgerRead = iota // shared client role, no statement text
	ledgerAsEngine                   // superuser: every statement
	ledgerAsCaller                   // the caller's own login: its own statements
)

// ledgerPlan is readLedger's decision, apart from any connection.
func ledgerPlan(masked, manages bool, q string) (string, ledgerRead) {
	switch {
	case masked:
		return strings.Replace(q, " statement, ", " "+maskedStatementSQL+" AS statement, ", 1), ledgerMasked
	case manages:
		return q, ledgerAsEngine
	}
	return strings.Replace(q, " statement, ", " "+ledgerStatementSQL+", ", 1), ledgerAsCaller
}

// readLedgerAsEngine runs the listing over the superuser connection, which
// reads the statement column directly. A variable so tests can stand in.
var readLedgerAsEngine = func(name, q string) map[string]any {
	ctx, cancel := context.WithTimeout(context.Background(), consoleStatementTimeout()+5*time.Second)
	defer cancel()
	conn, err := branch.OpenSuper(ctx, name)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	defer conn.Close(context.Background())
	return runOn(ctx, conn, q)
}
