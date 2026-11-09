// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"strings"
	"testing"
)

// The access paths (F5, Gate 1 step 4).

// A masked account's agent key reads what its account reads: its role is a
// masked reader's, still an agent to the Blackbox, and can reach db_client's
// rights neither by inheriting nor by SET ROLE.
func TestMaskedAgentKeyRoleSQL(t *testing.T) {
	m := maskedAgentKeyRoleSQL("agent:m@x.io", "pw")
	for _, want := range []string{
		"IN ROLE " + MaskedRole,
		"REVOKE db_client FROM",
		"GRANT " + AgentClientRole + " TO %I WITH INHERIT FALSE, SET FALSE",
		"SET role = " + MaskedRole,
		"SET search_path = " + MaskSchema + ", public",
		"SET log_min_error_statement = panic",
	} {
		if !strings.Contains(m, want) {
			t.Errorf("the masked agent role lacks %q", want)
		}
	}
	if strings.Contains(m, "IN ROLE db_client") || strings.Contains(m, "GRANT db_client") {
		t.Error("a masked agent role is put in db_client")
	}
	p := agentKeyRoleSQL("agent:m@x.io", "pw")
	for _, want := range []string{"REVOKE " + MaskedRole + " FROM", "RESET search_path", "GRANT db_client TO", "WITH INHERIT TRUE, SET TRUE", "SET role = db_client"} {
		if !strings.Contains(p, want) {
			t.Errorf("an agent role made ordinary again lacks %q", want)
		}
	}
}

// A masked account's agent is refused an agent branch's own role, which reads
// real values; an account not masked is not.
func TestEngineAgentLoginRefusesMasked(t *testing.T) {
	tempMaskFiles(t)
	if err := SaveMaskedAccounts([]MaskedAccount{{Email: "m@x.io"}}); err != nil {
		t.Fatal(err)
	}
	l := engineAgentLogin("agent-a1", "agent:m@x.io")
	if l.refused == nil || !errors.Is(l.refused, ErrInvalidRequest) || !strings.Contains(l.refused.Error(), "is masked") {
		t.Fatalf("a masked account's agent on an agent branch: %+v", l)
	}
	if !IsMaskedAccount("agent:M@X.IO") || IsMaskedAccount("p@x.io") {
		t.Error("IsMaskedAccount reads an agent key's account, in any case")
	}
	if AccountMaskedOn("dev", "agent:m@x.io") != accountMasked("dev", "m@x.io") {
		t.Error("AccountMaskedOn does not read the agent key's account")
	}
}

// Owning a branch no longer exempts a masked account (the way through it was
// the first thing the access-path suite found); only unmask lifts it.
func TestOwnerIsMaskedToo(t *testing.T) {
	tempMaskFiles(t)
	old := maskExempt
	defer func() { maskExempt = old }()
	maskExempt = func(b, e string) bool { return false } // not an admin
	if err := SaveMaskedAccounts([]MaskedAccount{{Email: "m@x.io"}}); err != nil {
		t.Fatal(err)
	}
	if !accountMasked("mine", "m@x.io") {
		t.Fatal("masked on a branch")
	}
	if err := changeUnmasks(func(UnmaskGrant) bool { return true }, &UnmaskGrant{Email: "m@x.io", Branch: "mine"}); err != nil {
		t.Fatal(err)
	}
	if accountMasked("mine", "m@x.io") || !accountMasked("main", "m@x.io") {
		t.Error("unmask on mine lifts it there only")
	}
}
