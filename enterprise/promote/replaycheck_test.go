//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package promote

import (
	"errors"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// Every class the replay must refuse, in the forms a message can hide it in.
func TestReplayRefusal(t *testing.T) {
	for _, q := range []string{
		// Transaction control.
		"COMMIT", "commit;", "END", "END WORK", "ABORT", "ROLLBACK", "ROLLBACK TO SAVEPOINT s",
		"BEGIN", "BEGIN ISOLATION LEVEL SERIALIZABLE", "START TRANSACTION", "SAVEPOINT s", "RELEASE SAVEPOINT s",
		"PREPARE TRANSACTION 'x'", "COMMIT PREPARED 'x'", "ROLLBACK PREPARED 'x'",
		"SET TRANSACTION READ ONLY", "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY",
		// Role and session.
		"SET ROLE dbadmin", "set role none", "SET LOCAL ROLE dbadmin", "SET SESSION ROLE dbadmin", "SET role = dbadmin",
		`SET "role" TO dbadmin`, `SET "ROLE" TO dbadmin`, "RESET ROLE", "SET SESSION AUTHORIZATION dbadmin",
		"SET LOCAL SESSION AUTHORIZATION dbadmin", "SET session_authorization = dbadmin", "RESET SESSION AUTHORIZATION",
		"RESET session_authorization", "SET session_replication_role = replica",
		// Attribution and the guardrail's override.
		"SET bb.actor = 'x'", "SET LOCAL bb.actor_kind = 'human'", "set BB.ALLOW_DESTRUCTIVE = on", "SET bb . actor = 'x'",
		`SET "bb".actor = 'x'`, `SET "bb.actor" = 'x'`, `SET "BB"."Actor" = 'x'`, "RESET bb.actor", "RESET ALL",
		"SET application_name = 'x'", "SET bb.policy_allow = 'r1'",
		"SELECT set_config('bb.actor', 'x', true)", "SELECT pg_catalog.set_config('role', 'dbadmin', true)",
		`SELECT "set_config"('bb.session', 'x', false)`, "SELECT set_config('BB.Actor', 'x', true)",
		"SELECT set_config(lower('ROLE'), 'dbadmin', true)", "SELECT set_config(E'bb.actor', 'x', true)",
		// What changes how later statements are read.
		"SET standard_conforming_strings = off", "SET client_encoding = 'SJIS'", "SET NAMES 'SJIS'",
		// Behind comments, or where one seems to be.
		"/* hello */ COMMIT", "-- hello\nCOMMIT", "/* a /* nested */ b */ RESET ROLE", "COM/* */MIT;SET ROLE x",
		"-- a comment ended by a carriage return\rCOMMIT",
		"CREATE TABLE t (); /* */ COMMIT; --",
		// After a literal that seems to swallow it.
		"SELECT 'a'; COMMIT", "SELECT $$a$$; COMMIT", "SELECT $x$ $y$ $x$; COMMIT", `SELECT "a;"; COMMIT`,
		"SELECT 'it''s'; COMMIT", "SELECT E'it\\'s'; COMMIT",
		// E'' escapes carry across a continuation, so this string ends where it seems not to.
		"SELECT E'a'\n'\\''; COMMIT; --'",
		"SELECT E'a' -- comment\n'\\''; COMMIT; --'",
		// A dollar after a number starts a quote; inside a name it does not.
		"SELECT 1$$a$$; COMMIT",
		"SELECT a$b$; COMMIT; --$b$",
		// Multi-statement messages, wherever it falls.
		"CREATE TABLE t (id int); COMMIT; DROP TABLE u", "COMMIT; CREATE TABLE t (id int)",
		"CREATE TABLE t (id int);;\n;SET ROLE dbadmin",
		// BEGIN ATOMIC is only a body after CREATE FUNCTION, and ends at its END.
		"CREATE FUNCTION begin() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$; COMMIT",
		"CREATE FUNCTION f() RETURNS int BEGIN ATOMIC SELECT 1; END; COMMIT",
		// A DO block is not a way round.
		"DO $$ BEGIN SET ROLE dbadmin; END $$", "DO $$ BEGIN SET LOCAL bb.actor = 'x'; END $$",
		"DO $$ BEGIN PERFORM set_config('bb.actor', 'x', true); END $$",
		"DO $$ BEGIN EXECUTE 'SET ROLE dbadmin'; END $$", "DO LANGUAGE plpgsql 'BEGIN RESET ROLE; END'",
		// What cannot be read is not passed.
		"CREATE TABLE t (a text DEFAULT 'oops", `CREATE TABLE "t (a int)`, "CREATE TABLE t () /* open", "SELECT $x$ open",
		"SELECT 1\x00; COMMIT", `SET U&"r\006Fle" = dbadmin`, `CREATE TABLE U&"t!0041" UESCAPE '!' ()`,
	} {
		if replayRefusal(q) == "" {
			t.Errorf("not refused: %q", q)
		}
	}
}

// Ordinary changes, and the words above where they mean nothing.
func TestReplayAccepted(t *testing.T) {
	for _, q := range []string{
		"CREATE TABLE t (id int PRIMARY KEY, note text)", "ALTER TABLE t ADD COLUMN x int;", "DROP INDEX i",
		"CREATE INDEX ON t (id)", "GRANT SELECT ON t TO bb_audit", "COMMENT ON TABLE t IS 'do not COMMIT this; ROLLBACK later'",
		// Multi-statement without transaction control.
		"CREATE TABLE a (id int); CREATE VIEW v AS SELECT id FROM a; ALTER TABLE a ADD b text",
		"SET search_path = app; CREATE TABLE a (id int)", "SET LOCAL lock_timeout = '5s'; ALTER TABLE a ADD b int",
		"SELECT pg_catalog.set_config('search_path', '', false); CREATE TABLE a (id int)",
		// Only in comments or quoting.
		"CREATE TABLE t (id int) -- then COMMIT;", "/* SET ROLE x; */ CREATE TABLE t (id int)",
		"CREATE TABLE t (a text DEFAULT '; COMMIT; --')", "CREATE TABLE t (a text DEFAULT $$; RESET ROLE;$$)",
		`CREATE TABLE "commit" (id int)`, `CREATE TABLE t ("set role" int); ALTER TABLE t RENAME "set role" TO "begin"`,
		"ALTER TABLE t ADD COLUMN \"end\" int",
		// A string the E'' continuation really does keep going.
		"SELECT E'a'\n'\\'; COMMIT; --'",
		// PREPARE of a query, a column called role, a routine body with BEGIN and END.
		"PREPARE p AS SELECT 1; CREATE TABLE a (id int)",
		"UPDATE t SET role = 'x'; ALTER TABLE t ADD y int",
		"CREATE FUNCTION f() RETURNS int LANGUAGE plpgsql AS $$ BEGIN COMMIT; RETURN 1; END $$",
		"CREATE PROCEDURE p() LANGUAGE sql BEGIN ATOMIC SELECT 1; SELECT CASE WHEN true THEN 1 ELSE 2 END; END",
		"CREATE OR REPLACE FUNCTION f() RETURNS int BEGIN ATOMIC SELECT 1; END; CREATE TABLE a (id int)",
		"CREATE RULE r AS ON INSERT TO t DO ALSO (SELECT 1; NOTIFY x)",
		"DO $$ BEGIN CREATE TABLE a (id int); EXCEPTION WHEN duplicate_table THEN NULL; END $$",
		"DO $$ BEGIN UPDATE t SET role = 'x'; END $$",
		"DO $$ DECLARE r regclass := 't'::regclass; BEGIN EXECUTE format('GRANT SELECT ON %s TO bb_audit', r); END $$",
		`CREATE TABLE U&"plain" (id int)`,
	} {
		if r := replayRefusal(q); r != "" {
			t.Errorf("refused %q: %s", q, r)
		}
	}
}

// Refused by name, and before any container is looked for: this test has none.
func TestApplyRefusesAnUnsafeStatement(t *testing.T) {
	_, err := apply(1, "main", "someone@example.com", []branch.RequestEntry{
		entry(1, "a", "human", "CREATE TABLE", "public.t", "CREATE TABLE t (id int)"),
		entry(2, "a", "human", "CREATE TABLE", "public.u", "CREATE TABLE u (id int); COMMIT"),
	})
	if !errors.Is(err, branch.ErrNotReplayable) {
		t.Fatalf("err = %v", err)
	}
	for _, want := range []string{"entry 2", "public.u", "COMMIT", "Nothing was applied"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q does not say %q", err, want)
		}
	}
}
