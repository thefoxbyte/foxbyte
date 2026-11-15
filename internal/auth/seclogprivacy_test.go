// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func mustVerify(t *testing.T, s *Store) []SecurityEvent {
	t.Helper()
	evs, err := s.SecurityEvents(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if id, problems := VerifyEvents(evs); len(problems) > 0 {
		t.Fatalf("the log does not verify (first bad %d): %v", id, problems)
	}
	return evs
}

// rawExec changes the store the way someone with the file can: past the
// triggers.
func rawExec(t *testing.T, s *Store, qs ...string) {
	t.Helper()
	for _, q := range qs {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func aliceLog(t *testing.T, s *Store) {
	t.Helper()
	s.Audit(EvLoginOK, "alice@x.com", "alice@x.com", "10.0.0.1", "password")
	s.Audit(EvLoginFailed, "", "Alice@X.com", "10.0.0.2", "password")
	s.Audit(EvKeyCreated, "admin@x.com", "key for alice@x.com", "10.9.9.9", "made by admin@x.com for alice@x.com")
	s.Audit(EvLoginOK, "bob@x.com", "bob@x.com", "10.0.0.3", "password")
	s.Audit(EvLoginOK, "malice@x.com", "malice@x.com", "10.0.0.4", "password") // contains alice@x.com, is not her
}

func TestPseudonymiseKeepsTheChain(t *testing.T) {
	s := testStore(t)
	aliceLog(t, s)
	res, err := s.PseudonymiseSecurityLog("alice@x.com", "admin@x.com")
	if err != nil {
		t.Fatal(err)
	}
	if res.Events != 3 || !strings.HasPrefix(res.Pseudonym, "person:") {
		t.Fatalf("result %+v, want 3 events and a person: token", res)
	}
	evs := mustVerify(t, s)
	for _, e := range evs {
		all := strings.ToLower(e.Actor + "|" + e.Subject + "|" + e.Detail)
		if strings.Contains(all, "|alice@x.com") || strings.HasPrefix(all, "alice@x.com") || strings.Contains(all, " alice@x.com") {
			t.Errorf("event %d still names her: %+v", e.ID, e)
		}
	}
	if evs[0].Actor != res.Pseudonym || evs[0].Subject != res.Pseudonym || !strings.HasPrefix(evs[0].IP, "address:") {
		t.Errorf("her sign-in: %+v", evs[0])
	}
	if evs[1].Subject != res.Pseudonym || !strings.HasPrefix(evs[1].IP, "address:") {
		t.Errorf("the failed sign-in against her account: %+v", evs[1])
	}
	// The admin acted from their own address, which stays.
	if evs[2].Actor != "admin@x.com" || evs[2].IP != "10.9.9.9" || !strings.Contains(evs[2].Detail, res.Pseudonym) {
		t.Errorf("the admin's event: %+v", evs[2])
	}
	if evs[3].Actor != "bob@x.com" || evs[4].Actor != "malice@x.com" || evs[4].IP != "10.0.0.4" {
		t.Errorf("other people's events changed: %+v %+v", evs[3], evs[4])
	}
	last := evs[len(evs)-1]
	if last.Kind != EvSecurityLogPseudonymised || last.Subject != res.Pseudonym || last.ID != res.EventID {
		t.Errorf("the record of it: %+v", last)
	}
	// The same person maps to the same token, so events can still be linked.
	if p, _ := s.Pseudonym(" ALICE@x.com "); p != res.Pseudonym {
		t.Errorf("pseudonym %q, then %q", res.Pseudonym, p)
	}
	// Doing it again changes nothing and still verifies.
	if again, err := s.PseudonymiseSecurityLog("alice@x.com", "admin@x.com"); err != nil || again.Events != 0 {
		t.Errorf("a second time: %+v, %v", again, err)
	}
	mustVerify(t, s)
	// A second person on an event already sealed: it is sealed again, and the
	// first seal, which the first pseudonymisation's digest covers, stays.
	if res2, err := s.PseudonymiseSecurityLog("admin@x.com", "cli:root"); err != nil || res2.Events != 3 { // the key event, and both records of pseudonymising alice

		t.Fatalf("the admin too: %+v, %v", res2, err)
	}
	evs = mustVerify(t, s)
	if len(evs[2].Seals) != 2 || strings.Contains(evs[2].Actor, "@") {
		t.Errorf("the event both were on: %+v", evs[2])
	}

	// Ordinary updates and deletes are still refused.
	if _, err := s.db.Exec(`UPDATE security_events SET actor='x' WHERE id=4`); err == nil {
		t.Error("an event could be updated outside pseudonymisation")
	}
	if _, err := s.db.Exec(`DELETE FROM security_events WHERE id=4`); err == nil {
		t.Error("an event could be deleted outside a prune")
	}
}

// What pseudonymisation vouches for cannot be changed afterwards.
func TestPseudonymisedEventsStillCatchTampering(t *testing.T) {
	for name, tamper := range map[string][]string{
		"a sealed event edited": {
			`INSERT INTO security_log_unlock VALUES('pseudonymise')`,
			`UPDATE security_events SET detail='something else' WHERE id=1`,
			`DELETE FROM security_log_unlock`},
		"a seal removed": {`DELETE FROM security_event_seals WHERE event_id=2`},
		"a seal forged for an unsealed event": {
			`INSERT INTO security_log_unlock VALUES('pseudonymise')`,
			`UPDATE security_events SET actor='someone' WHERE id=4`,
			`DELETE FROM security_log_unlock`},
	} {
		t.Run(name, func(t *testing.T) {
			s := testStore(t)
			aliceLog(t, s)
			res, err := s.PseudonymiseSecurityLog("alice@x.com", "admin@x.com")
			if err != nil {
				t.Fatal(err)
			}
			rawExec(t, s, tamper...)
			if name == "a seal forged for an unsealed event" {
				evs, _ := s.SecurityEvents(3, 1)
				rawExec(t, s, `INSERT INTO security_event_seals VALUES(4, `+strconv.FormatInt(res.EventID, 10)+`, '`+SealHash(evs[0], res.EventID)+`')`)
			}
			evs, err := s.SecurityEvents(0, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, problems := VerifyEvents(evs); len(problems) == 0 {
				t.Error("verified after tampering")
			}
		})
	}
}

// An install that wrote its log before seals existed: its events keep their
// hashes, verify after the upgrade, and can be pseudonymised.
func TestOldEventsVerifyAfterUpgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	s, err := Open(Config{DBPath: path, WebOrigin: "http://x"})
	if err != nil {
		t.Fatal(err)
	}
	// Put the store back the way an older release left it.
	rawExec(t, s,
		`DROP TABLE security_event_seals`, `DROP TABLE security_log_unlock`,
		`DROP TRIGGER security_events_no_update`, `DROP TRIGGER security_events_no_delete`,
		`CREATE TRIGGER security_events_no_update BEFORE UPDATE ON security_events
		   BEGIN SELECT RAISE(ABORT, 'security_events is append-only'); END`,
		`CREATE TRIGGER security_events_no_delete BEFORE DELETE ON security_events
		   BEGIN SELECT RAISE(ABORT, 'security_events is append-only'); END`)
	aliceLog(t, s)
	before, _ := s.db.Query(`SELECT row_hash FROM security_events ORDER BY id`)
	var hashes []string
	for before.Next() {
		var h string
		_ = before.Scan(&h)
		hashes = append(hashes, h)
	}
	before.Close()
	s.Close()

	s, err = Open(Config{DBPath: path, WebOrigin: "http://x"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	mustVerify(t, s)
	if _, err := s.PseudonymiseSecurityLog("alice@x.com", "cli:root"); err != nil {
		t.Fatal(err)
	}
	evs := mustVerify(t, s)
	for i, h := range hashes {
		if evs[i].RowHash != h {
			t.Errorf("event %d's hash changed, which would break its anchors", evs[i].ID)
		}
	}
}

func TestPruneKeepsWhatIsLeftVerifiable(t *testing.T) {
	s := testStore(t)
	aliceLog(t, s)                                                      // 1–5
	res, err := s.PseudonymiseSecurityLog("alice@x.com", "admin@x.com") // 6
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		s.Audit(EvLoginOK, "bob@x.com", "bob@x.com", "10.0.0.3", "") // 7–10
	}
	soon := time.Now().Add(time.Second)

	// Bounded by maxID: what the caller has anchored.
	p, err := s.PruneSecurityEvents(soon, 2, "engine")
	if err != nil || p.Removed != 2 || p.UpTo != 2 {
		t.Fatalf("first prune: %+v, %v", p, err)
	}
	evs := mustVerify(t, s)
	if evs[0].ID != 3 {
		t.Fatalf("the log starts at %d, want 3", evs[0].ID)
	}
	// Events 1 and 2 were sealed by event 6, which is still here: its digest
	// still checks, because their seals were kept.
	if up, head := PrunedUpTo(evs); up != 2 || head != p.Head {
		t.Errorf("start %d %s, want 2 %s", up, head, p.Head)
	}
	// Again, past the pseudonymisation event: its seals go with it.
	p2, err := s.PruneSecurityEvents(soon, 8, "engine")
	if err != nil || p2.UpTo != 8 || p2.Removed != 6 {
		t.Fatalf("second prune: %+v, %v", p2, err)
	}
	mustVerify(t, s)
	var seals int
	_ = s.db.QueryRow(`SELECT count(*) FROM security_event_seals WHERE by_event = ?`, res.EventID).Scan(&seals)
	if seals != 0 {
		t.Errorf("%d seals of a removed pseudonymisation remain", seals)
	}
	// Nothing new enough is removed.
	if p3, err := s.PruneSecurityEvents(time.Now().Add(-time.Hour), 100, "engine"); err != nil || p3.Removed != 0 {
		t.Errorf("a prune with nothing old enough: %+v, %v", p3, err)
	}

	// Removing more from the start than the prune recorded is caught.
	rawExec(t, s, `INSERT INTO security_log_unlock VALUES('prune')`, `DELETE FROM security_events WHERE id = 9`,
		`DELETE FROM security_log_unlock`)
	evs, _ = s.SecurityEvents(0, 0)
	if _, problems := VerifyEvents(evs); len(problems) == 0 {
		t.Error("an event removed past the prune record verified")
	}
}

// A session counts as a recent sign-in only for a few minutes.
func TestSessionAge(t *testing.T) {
	s := testStore(t)
	u, err := s.CreateUser("a@x.com", "password1")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.createSession(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if age, ok := s.SessionAge(tok); !ok || age > time.Minute {
		t.Fatalf("a new session: %v, %v", age, ok)
	}
	rawExec(t, s, `UPDATE sessions SET expires = expires - 3600`)
	if age, ok := s.SessionAge(tok); !ok || age < 59*time.Minute {
		t.Fatalf("an hour-old session: %v, %v", age, ok)
	}
	if _, ok := s.SessionAge(""); ok {
		t.Fatal("no session has an age")
	}
	if !s.CheckPassword(u.ID, "password1") || s.CheckPassword(u.ID, "nope") {
		t.Fatal("CheckPassword")
	}
}

func TestParseRetention(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"": 0, "off": 0, "0": 0, "400d": 400 * 24 * time.Hour, "48h": 48 * time.Hour, " 30D ": 30 * 24 * time.Hour,
	} {
		if got, err := ParseRetention(in); err != nil || got != want {
			t.Errorf("%q: %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"400", "1h", "x d", "-3d"} {
		if _, err := ParseRetention(in); err == nil {
			t.Errorf("%q was accepted", in)
		}
	}
}

func TestReplaceEmailIsWholeWord(t *testing.T) {
	for in, want := range map[string]string{
		"alice@x.com":                 "T",
		"by ALICE@X.COM.":             "by T.",
		"malice@x.com":                "malice@x.com",
		"alice@x.com.au":              "alice@x.com.au",
		"alice@x.com, alice@x.com":    "T, T",
		"key for alice@x.com (admin)": "key for T (admin)",
	} {
		if got := replaceEmail(in, "alice@x.com", "T"); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
