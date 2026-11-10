// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import (
	"strings"
	"testing"
)

// chainRowBody is bb.chain_row's source, as ledger.sql writes it.
func chainRowBody(t *testing.T) string {
	t.Helper()
	i := strings.Index(Schema, "CREATE OR REPLACE FUNCTION bb.chain_row()")
	if i < 0 {
		t.Fatal("bb.chain_row is gone")
	}
	body := Schema[i:]
	return body[:strings.Index(body, "$$;")]
}

// In REPEATABLE READ a snapshot can be older than the append lock, so the tail
// must not be read through it: two rows would chain off one parent and verify
// would call it tampering. The head row's UPDATE is what turns a stale snapshot
// into a serialization error. Proved against a real server; this guards the
// shape it rests on.
func TestChainHeadIsTakenByUpdateUnderTheLock(t *testing.T) {
	body := chainRowBody(t)
	lock := strings.Index(body, "pg_advisory_xact_lock(hashtext('bb.schema_ledger'))")
	head := strings.Index(body, "UPDATE bb.ledger_head SET last_id = last_id + 1 RETURNING last_id, last_hash INTO NEW.id, prev;")
	hash := strings.Index(body, "NEW.row_hash  := bb._ledger_hash(NEW);")
	if lock < 0 || head < 0 || hash < 0 || !(lock < head && head < hash) {
		t.Errorf("bb.chain_row must lock, then take the head, then hash (lock %d, head %d, hash %d)", lock, head, hash)
	}
	if strings.Contains(body, "ORDER BY id DESC") {
		t.Error("bb.chain_row reads the tail through the transaction's snapshot again")
	}
	if !strings.Contains(body, "UPDATE bb.ledger_head SET last_hash = NEW.row_hash;") {
		t.Error("bb.chain_row no longer moves the head to the row it wrote")
	}
}

// The upgrade: the head and the function that needs it arrive together, under
// the lock, seeded from the existing tail, and a re-run leaves a head that is
// already right alone. Nothing may rewrite a row that exists.
func TestChainHeadUpgradesAnExistingLedger(t *testing.T) {
	begin := strings.Index(Schema, "BEGIN;\nDO $$ BEGIN PERFORM pg_advisory_xact_lock(hashtext('bb.schema_ledger')); END $$;")
	table := strings.Index(Schema, "CREATE TABLE IF NOT EXISTS bb.ledger_head")
	fn := strings.Index(Schema, "CREATE OR REPLACE FUNCTION bb.chain_row()")
	commit := strings.Index(Schema, "FOR EACH ROW EXECUTE FUNCTION bb.chain_row();\nCOMMIT;")
	if begin < 0 || table < begin || fn < table || commit < fn {
		t.Errorf("the head and bb.chain_row must be installed in one locked transaction (begin %d, table %d, function %d, commit %d)", begin, table, fn, commit)
	}
	for _, want := range []string{
		"(SELECT id, row_hash FROM bb.schema_ledger ORDER BY id DESC LIMIT 1) t ON true",
		"ON CONFLICT (id) DO UPDATE SET last_id = EXCLUDED.last_id, last_hash = EXCLUDED.last_hash\n  WHERE EXCLUDED.last_id > bb.ledger_head.last_id;",
	} {
		if !strings.Contains(Schema, want) {
			t.Errorf("ledger.sql no longer contains %q", want)
		}
	}
}

// A masked branch's ledger is emptied by the engine, past the triggers
// (enterprise/masking, freshBlackboxSQL), and verify expects the first row of
// a ledger to link to nothing.
func TestChainRestartsOnAnEmptiedLedger(t *testing.T) {
	body := chainRowBody(t)
	head := strings.Index(body, "UPDATE bb.ledger_head SET last_id")
	empty := strings.Index(body, "IF NOT EXISTS (SELECT 1 FROM bb.schema_ledger) THEN\n    prev := '';")
	if empty < 0 || empty < head {
		t.Error("an emptied ledger must start a new chain, judged after the head was taken")
	}
}
