// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// Lines as PostgreSQL writes them with audit on (the shapes the F6 suite saw).
const (
	lineObject   = `{"timestamp":"2026-11-04 10:00:01.500 UTC","user":"alice@x.in","dbname":"appdb","pid":7,"remote_host":"172.18.0.5","session_id":"6ae8.1","line_num":1,"ps":"INSERT","vxid":"4/2","txid":0,"error_severity":"LOG","message":"AUDIT: OBJECT,1,1,WRITE,INSERT,TABLE,public.orders,<not logged>,<not logged>","application_name":"psql","backend_type":"client backend","query_id":0}`
	lineTxn      = `{"timestamp":"2026-11-04 10:00:01.600 UTC","user":"alice@x.in","session_id":"6ae8.1","vxid":"4/0","error_severity":"LOG","message":"AUDIT: TXN,4/2,COMMIT,asserted,shop,\"o'brien, p\""}`
	lineError    = `{"timestamp":"2026-11-04 10:00:02.000 UTC","user":"alice@x.in","session_id":"6ae8.1","vxid":"4/3","error_severity":"ERROR","state_code":"23505","message":"AUDIT: OUTCOME,ERROR,23505"}`
	lineSub      = `{"timestamp":"2026-11-04 10:00:03.000 UTC","user":"alice@x.in","session_id":"6ae8.1","vxid":"4/4","error_severity":"LOG","message":"AUDIT: TXN,4/4,SUBROLLBACK,2"}`
	lineForensic = `{"timestamp":"2026-11-04 10:00:04.000 UTC","user":"bob","session_id":"6ae8.2","vxid":"5/2","error_severity":"LOG","message":"AUDIT: OBJECT,3,1,WRITE,UPDATE,TABLE,public.orders,\"UPDATE orders SET a = 1, b = 'x'\",<none>"}`
)

func TestRecordFromLine(t *testing.T) {
	r, ok := recordFromLine("main", []byte(lineObject))
	if !ok || r.Kind != "statement" || r.Audit != "OBJECT" || r.Class != "WRITE" || r.Command != "INSERT" ||
		r.ObjectType != "TABLE" || r.Object != "public.orders" || r.Statement != 1 || r.Substatement != 1 ||
		r.Login != "alice@x.in" || r.Session != "6ae8.1" || r.VXID != "4/2" || r.Branch != "main" ||
		r.Time != "2026-11-04T10:00:01.5Z" || r.Text != "" {
		t.Fatalf("statement: %+v %v", r, ok)
	}
	// Kept: only section 5's fields. The client address, the application name
	// and the process id are not in a record at all.
	if b, _ := json.Marshal(r); strings.Contains(string(b), "172.18") || strings.Contains(string(b), "psql") ||
		strings.Contains(string(b), `"pid"`) {
		t.Fatalf("a record keeps more than section 5 allows: %s", b)
	}

	r, ok = recordFromLine("main", []byte(lineTxn))
	if !ok || r.Kind != "transaction" || r.Outcome != "COMMIT" || r.VXID != "4/2" ||
		r.For == nil || r.For.State != "asserted" || r.For.Issuer != "shop" || r.For.Actor != "o'brien, p" {
		t.Fatalf("transaction, with its own vxid and a quoted actor: %+v %+v %v", r, r.For, ok)
	}
	r, ok = recordFromLine("main", []byte(lineError))
	if !ok || r.Kind != "outcome" || r.Outcome != "ERROR" || r.SQLState != "23505" {
		t.Fatalf("outcome: %+v %v", r, ok)
	}
	r, ok = recordFromLine("main", []byte(lineSub))
	if !ok || r.Outcome != "SUBROLLBACK" || r.Undone != 2 || r.For != nil {
		t.Fatalf("subrollback: %+v %v", r, ok)
	}
	r, ok = recordFromLine("main", []byte(lineForensic))
	if !ok || r.Text != "UPDATE orders SET a = 1, b = 'x'" {
		t.Fatalf("forensic mode keeps the statement's text: %+v %v", r, ok)
	}

	for _, skip := range []string{
		`{"timestamp":"2026-11-04 10:00:00.000 UTC","error_severity":"LOG","message":"checkpoint complete: wrote 3 buffers"}`,
		`{"timestamp":"2026-11-04 10:00:00.000 UTC","user":"x","error_severity":"WARNING","message":"REDACTED,WARNING,01000"}`,
		`{"timestamp":"2026-11-04 10:00:00.000 UTC","error_severity":"LOG","message":"AUDIT: SOMETHING,1"}`,
		`{"timestamp":"not a time","error_severity":"LOG","message":"AUDIT: OBJECT,1,1,WRITE,INSERT,TABLE,t,x,y"}`,
		`not json`,
	} {
		if _, ok := recordFromLine("main", []byte(skip)); ok {
			t.Errorf("should not be a record: %s", skip)
		}
	}
}

func chainOf(t *testing.T, lines ...string) []AuditRecord {
	t.Helper()
	var out []AuditRecord
	prev, seq := "", int64(0)
	for _, l := range lines {
		r, ok := recordFromLine("main", []byte(l))
		if !ok {
			t.Fatalf("not a record: %s", l)
		}
		sealRecord(&r, seq+1, prev)
		seq, prev = r.Seq, r.Hash
		out = append(out, r)
	}
	return out
}

// The chain catches an edit, a removal and a reordering, and continues from
// the last record retention removed.
func TestVerifyChain(t *testing.T) {
	recs := chainOf(t, lineObject, lineTxn, lineError, lineSub)
	if rep := verifyChain(recs, 0, ""); !rep.Intact || rep.Records != 4 {
		t.Fatalf("intact: %+v", rep)
	}
	edited := append([]AuditRecord(nil), recs...)
	edited[1].For.Actor = "mallory"
	if rep := verifyChain(edited, 0, ""); rep.Intact || !strings.Contains(rep.Problems[0], "record 2 was changed") {
		t.Errorf("edit: %+v", rep)
	}
	removed := append(append([]AuditRecord(nil), recs[:1]...), recs[2:]...)
	if rep := verifyChain(removed, 0, ""); rep.Intact || !strings.Contains(rep.Problems[0], "missing") {
		t.Errorf("removal: %+v", rep)
	}
	swapped := []AuditRecord{recs[0], recs[2], recs[1], recs[3]}
	if rep := verifyChain(swapped, 0, ""); rep.Intact {
		t.Errorf("reorder: %+v", rep)
	}
	if rep := verifyChain(recs[2:], recs[1].Seq, recs[1].Hash); !rep.Intact || rep.First != 3 {
		t.Errorf("from a base: %+v", rep)
	}
	if rep := verifyChain(recs[2:], recs[0].Seq, recs[0].Hash); rep.Intact {
		t.Errorf("a wrong base should not verify: %+v", rep)
	}
}

// Statements are shown with how their transaction ended and whom it was for;
// transaction records are folded into them; filters by branch, login, table
// and time.
func TestJoinAudit(t *testing.T) {
	recs := chainOf(t, lineObject, lineTxn, lineError, lineForensic)
	got := joinAudit(recs, AuditQuery{})
	if len(got) != 3 || got[0].Kind != "statement" || got[0].Login != "bob" || got[1].Kind != "outcome" || got[2].Command != "INSERT" {
		t.Fatalf("newest first, transactions folded in: %+v", got)
	}
	if e := got[2]; e.TxnOutcome != "COMMIT" || e.TxnFor == nil || e.TxnFor.Actor != "o'brien, p" {
		t.Errorf("join: %+v", e)
	}
	if n := len(joinAudit(recs, AuditQuery{Login: "bob"})); n != 1 {
		t.Errorf("login filter: %d", n)
	}
	if n := len(joinAudit(recs, AuditQuery{Table: "orders"})); n != 2 {
		t.Errorf("table by name: %d", n)
	}
	if n := len(joinAudit(recs, AuditQuery{Table: "other.orders"})); n != 0 {
		t.Errorf("table by schema.name: %d", n)
	}
	if n := len(joinAudit(recs, AuditQuery{Branch: "feature"})); n != 0 {
		t.Errorf("branch filter: %d", n)
	}
	since, _ := time.Parse(time.RFC3339, "2026-11-04T10:00:03Z")
	if n := len(joinAudit(recs, AuditQuery{Since: since})); n != 1 {
		t.Errorf("since: %d", n)
	}
	if got := joinAudit(recs, AuditQuery{Kinds: []string{"outcome"}}); len(got) != 1 || got[0].SQLState != "23505" {
		t.Errorf("errors only: %+v", got)
	}
}

// A day's file is a stream of gzip members, one per batch; a crash after the
// append and before the state leaves it longer than the state says, and it is
// cut back; one the state does not know is removed. Then the chain verifies,
// and the store's end must be the collector's.
func TestStoreRoundTripAndRepair(t *testing.T) {
	dir := t.TempDir()
	old := AuditStoreDir
	AuditStoreDir = func() string { return dir }
	t.Cleanup(func() { AuditStoreDir = old })

	recs := chainOf(t, lineObject, lineTxn, lineError, lineSub)
	s := auditState{Raw: map[string]rawPos{}, Days: map[string]int64{}}
	size, err := appendDay("2026-11-04", recs[:2])
	if err != nil {
		t.Fatal(err)
	}
	s.Days["2026-11-04"] = size
	if size, err = appendDay("2026-11-04", recs[2:]); err != nil {
		t.Fatal(err)
	}
	s.Days["2026-11-04"] = size
	s.Seq, s.Head = recs[3].Seq, recs[3].Hash
	if err := saveAuditState(s); err != nil {
		t.Fatal(err)
	}
	back, err := readDay("2026-11-04")
	if err != nil || len(back) != 4 || back[3].Hash != recs[3].Hash {
		t.Fatalf("two members read as one stream: %d %v", len(back), err)
	}
	if rep, err := VerifyAudit(); err != nil || !rep.Intact || rep.Records != 4 {
		t.Fatalf("verify: %+v %v", rep, err)
	}

	// A batch appended and never recorded, and a day the state never knew.
	extra := chainOf(t, lineObject, lineTxn, lineError, lineSub, lineForensic)[4:]
	sealRecord(&extra[0], 5, recs[3].Hash)
	if _, err := appendDay("2026-11-04", extra); err != nil {
		t.Fatal(err)
	}
	if _, err := appendDay("2026-11-05", extra); err != nil {
		t.Fatal(err)
	}
	if err := repairDays(s); err != nil {
		t.Fatal(err)
	}
	if back, _ := readDay("2026-11-04"); len(back) != 4 {
		t.Errorf("the unrecorded batch should be cut off: %d records", len(back))
	}
	if _, err := os.Stat(dayPath("2026-11-05")); !os.IsNotExist(err) {
		t.Error("a day file the state does not know should be removed")
	}

	// Records removed from the end: the chain still holds, but the store
	// stops short of where the collector wrote.
	s.Seq = 9
	_ = saveAuditState(s)
	if rep, _ := VerifyAudit(); rep.Intact || !strings.Contains(strings.Join(rep.Problems, " "), "removed") {
		t.Errorf("a store cut short should not verify: %+v", rep)
	}
}

func TestRawFilesAndLines(t *testing.T) {
	files := parseRawListing("main/audit-Wed-10.json\t120\t1793000000.5\nfeature/audit-Wed-09.json\t0\t1792990000\n.store/x.json\t1\t1\nbad line\n")
	if len(files) != 2 || files[0].Key != "feature/audit-Wed-09.json" || files[1].Size != 120 {
		t.Fatalf("oldest first, the store and bad lines skipped: %+v", files)
	}
	lines, used := completeLines([]byte("{\"a\":1}\n{\"b\":2}\n{\"c\":"))
	if len(lines) != 2 || used != 16 {
		t.Errorf("a line still being written is left: %d %d", len(lines), used)
	}
	if lines, used := completeLines([]byte("{\"partial")); lines != nil || used != 0 {
		t.Error("no complete line, nothing used")
	}
	if firstLineKey([]byte("no newline yet")) != "" || firstLineKey([]byte("a\nb")) != firstLineKey([]byte("a\nbcd\n")) {
		t.Error("a file is known by its first line, which growing does not change")
	}
}

// Retention removes whole days, oldest first, and the chain still verifies
// from the last record removed.
func TestPruneDays(t *testing.T) {
	dir := t.TempDir()
	old := AuditStoreDir
	AuditStoreDir = func() string { return dir }
	t.Cleanup(func() { AuditStoreDir = old })

	recs := chainOf(t, lineObject, lineTxn, lineError, lineSub)
	s := auditState{Raw: map[string]rawPos{}, Days: map[string]int64{}}
	for i, day := range []string{"2025-10-01", "2025-10-02", "2026-11-03", "2026-11-04"} {
		size, err := appendDay(day, recs[i:i+1])
		if err != nil {
			t.Fatal(err)
		}
		s.Days[day] = size
	}
	s.Seq, s.Head = recs[3].Seq, recs[3].Hash
	n, err := pruneDays(&s, "2025-11-04")
	if err != nil || n != 2 || s.Base.Seq != 2 || s.Base.Hash != recs[1].Hash || len(storedDays()) != 2 {
		t.Fatalf("pruned %d (%v), base %+v, left %v", n, err, s.Base, storedDays())
	}
	if _, ok := s.Days["2025-10-01"]; ok {
		t.Error("a removed day stays in the state")
	}
	if err := saveAuditState(s); err != nil {
		t.Fatal(err)
	}
	if rep, err := VerifyAudit(); err != nil || !rep.Intact || rep.First != 3 || rep.Records != 2 {
		t.Errorf("after retention the chain verifies from the last record removed: %+v %v", rep, err)
	}
}

// An edited day file is not "repaired": cutting it would destroy the evidence.
// Only bytes beginning with a gzip member at the recorded size are a crash's.
func TestRepairLeavesAnEditedFile(t *testing.T) {
	dir := t.TempDir()
	old := AuditStoreDir
	AuditStoreDir = func() string { return dir }
	t.Cleanup(func() { AuditStoreDir = old })

	recs := chainOf(t, lineObject, lineTxn, lineError, lineSub)
	size, err := appendDay("2026-11-04", recs)
	if err != nil {
		t.Fatal(err)
	}
	s := auditState{Raw: map[string]rawPos{}, Days: map[string]int64{"2026-11-04": size}, Seq: 4, Head: recs[3].Hash}
	if err := saveAuditState(s); err != nil {
		t.Fatal(err)
	}
	// Edited and compressed again, longer than it was.
	edited := append([]AuditRecord(nil), recs...)
	edited[1].Login = "mallory, who wanted a longer name than anyone else"
	_ = os.Remove(dayPath("2026-11-04"))
	if _, err := appendDay("2026-11-04", edited); err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(dayPath("2026-11-04"), os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.Write(make([]byte, 64))
	f.Close()
	before, _ := os.Stat(dayPath("2026-11-04"))
	if err := repairDays(s); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(dayPath("2026-11-04"))
	if after.Size() != before.Size() {
		t.Fatalf("an edited file was cut from %d to %d bytes", before.Size(), after.Size())
	}
	rep, err := VerifyAudit()
	if err != nil || rep.Intact {
		t.Fatalf("verify should report the edit, not fail: %+v %v", rep, err)
	}
}
