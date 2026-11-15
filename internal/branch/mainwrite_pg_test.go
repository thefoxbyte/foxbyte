// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// TestMainWriteOnPostgres checks the privileges on a real Postgres, given one:
// FOX_TEST_MAINWRITE_DSN names a superuser connection to a database made for
// the test, which it fills with roles and tables. Never point it at a database
// that matters. Skipped without it.
func TestMainWriteOnPostgres(t *testing.T) {
	dsn := os.Getenv("FOX_TEST_MAINWRITE_DSN")
	if dsn == "" {
		t.Skip("FOX_TEST_MAINWRITE_DSN is not set")
	}
	ctx := context.Background()
	super, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer super.Close(ctx)
	exec := func(c *pgx.Conn, sql string) error {
		_, err := c.Exec(ctx, sql, pgx.QueryExecModeSimpleProtocol)
		return err
	}
	must := func(c *pgx.Conn, sql string) {
		t.Helper()
		if err := exec(c, sql); err != nil {
			t.Fatalf("%v\n%.300s", err, sql)
		}
	}
	// The Blackbox, as main has it: db_client, db_agent, the grants, the seal.
	must(super, ledger.Schema)
	must(super, `ALTER ROLE db_client WITH LOGIN PASSWORD 'clientpw'`)
	must(super, `CREATE TABLE IF NOT EXISTS public.orders (id serial PRIMARY KEY, v text)`) // as the superuser: an import
	must(super, `INSERT INTO public.orders(v) VALUES ('one')`)
	must(super, `SET ROLE db_client; CREATE TABLE IF NOT EXISTS public.client_made (id int); RESET ROLE`)
	must(super, `CREATE TABLE IF NOT EXISTS public.applied (id int); GRANT INSERT, SELECT ON public.applied TO db_client`)
	for _, e := range []string{"alice@x.com", "bob@x.com", "root@x.com"} {
		must(super, userRoleSQL(e, "pw-"+e))
	}
	must(super, agentKeyRoleSQL(AgentKeyRole("alice@x.com"), "pw-agent"))
	must(super, `DO $$ BEGIN IF to_regrole('db_admin') IS NULL THEN CREATE ROLE db_admin NOLOGIN; END IF; END $$; GRANT db_admin TO "root@x.com"`)

	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	as := func(user, pw string) *pgx.Conn {
		t.Helper()
		c := cfg.Copy()
		c.User, c.Password = user, pw
		conn, err := pgx.ConnectConfig(ctx, c)
		if err != nil {
			t.Fatalf("logging in as %s: %v", user, err)
		}
		return conn
	}
	n := 0
	next := func() int { n++; return n }
	denied := func(err error) bool {
		var pg *pgconn.PgError
		return errors.As(err, &pg) && pg.Code == "42501"
	}
	// may checks what a login can do now: read, insert, update, create.
	may := func(user, pw string, write bool) {
		t.Helper()
		c := as(user, pw)
		defer c.Close(ctx)
		for _, q := range []string{`SELECT count(*) FROM public.orders`, `SELECT count(*) FROM public.client_made`,
			`SELECT id, actor FROM bb.schema_ledger LIMIT 1`, `SELECT * FROM bb.ledger_verify()`} {
			if err := exec(c, q); err != nil {
				t.Errorf("%s cannot read: %s: %v", user, q, err)
			}
		}
		for _, q := range []string{`INSERT INTO public.orders(v) VALUES ('x')`, `UPDATE public.client_made SET id = 1`,
			`DELETE FROM public.orders WHERE v = 'none'`, fmt.Sprintf(`CREATE TABLE public.made_%d (id int)`, next()),
			`ALTER TABLE public.client_made ADD COLUMN IF NOT EXISTS extra int`} {
			err := exec(c, q)
			switch {
			case write && err != nil:
				t.Errorf("%s may write and was refused: %s: %v", user, q, err)
			case !write && err == nil:
				t.Errorf("%s may not write and was let: %s", user, q)
			case !write && !denied(err):
				t.Errorf("%s refused, but not for its privileges: %s: %v", user, q, err)
			}
		}
		// Nor may it become db_client.
		if !write {
			if err := exec(c, `SET ROLE db_client`); err == nil {
				t.Errorf("%s could SET ROLE db_client", user)
			}
		}
	}

	// Mode "all": today's privileges, everybody writes.
	must(super, MainWriteSQL(true, nil))
	may("alice@x.com", "pw-alice@x.com", true)

	// Mode "granted", bob granted, root an admin.
	must(super, MainWriteSQL(false, []string{"bob@x.com"}))
	may("alice@x.com", "pw-alice@x.com", false)
	may(AgentKeyRole("alice@x.com"), "pw-agent", false)
	may("bob@x.com", "pw-bob@x.com", true)
	may("root@x.com", "pw-root@x.com", true)

	// Promotion applies change requests logged in as db_client itself, and
	// the engine's other paths do too: it keeps every right.
	c := as("db_client", "clientpw")
	for _, q := range []string{`INSERT INTO public.orders(v) VALUES ('promoted')`, `CREATE TABLE IF NOT EXISTS public.promoted (id int)`,
		`INSERT INTO public.applied VALUES (1)`} {
		if err := exec(c, q); err != nil {
			t.Errorf("db_client (promotion) was refused: %s: %v", q, err)
		}
	}
	c.Close(ctx)
	// What a granted writer makes, an ungranted reader can read.
	must(super, `SET ROLE db_client; CREATE TABLE IF NOT EXISTS public.later (id int); RESET ROLE`)
	r := as("alice@x.com", "pw-alice@x.com")
	if err := exec(r, `SELECT * FROM public.later`); err != nil {
		t.Errorf("a reader cannot read a table made since: %v", err)
	}
	r.Close(ctx)

	// The role SQL every login runs leaves a reader a reader.
	must(super, userRoleSQL("alice@x.com", "pw-alice@x.com"))
	must(super, agentKeyRoleSQL(AgentKeyRole("alice@x.com"), "pw-agent"))
	may("alice@x.com", "pw-alice@x.com", false)
	may(AgentKeyRole("alice@x.com"), "pw-agent", false)

	// Granted: one account at a time.
	must(super, mainAccessSQL(false, []string{"bob@x.com", "alice@x.com"}, []string{"alice@x.com", AgentKeyRole("alice@x.com")}))
	may("alice@x.com", "pw-alice@x.com", true)
	may(AgentKeyRole("alice@x.com"), "pw-agent", true)
	// Revoked again, and a table she made goes to db_client.
	must(super, mainAccessSQL(false, []string{"bob@x.com"}, []string{"alice@x.com"}))
	may("alice@x.com", "pw-alice@x.com", false)

	// A branch cloned from main gives its roles write back.
	must(super, mainAccessSQL(true, nil, nil))
	may("alice@x.com", "pw-alice@x.com", true)
}
