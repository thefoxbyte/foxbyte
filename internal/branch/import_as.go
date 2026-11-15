// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/safego"
)

// As says whose import, or whose pipeline run, this is.
//
// The zero value is the operator: the CLI, or an admin in the console. Their
// loads run as the superuser, exactly as they always have. An admin can already
// do anything on this install, and a dump that needs an extension only a
// superuser may create still needs one.
//
// With Account set, the load belongs to an ordinary account, and everything
// that came from outside runs as that account's own role, the one the gateway
// logs it in as: an uploaded .sql script, the dump a source server produced,
// the rows a MySQL server sent, a pipeline's models and tests. So an import can
// do on its new branch what the account could do there through the gateway, and
// nothing more. Those psql sessions also have backslash commands switched off
// (\restrict), because a psql command is not SQL and no database role limits it.
//
// What FoxByte writes itself (the schema reset before a load, CSV and JSON
// loaders, the pipeline's staging step) is unchanged and still runs as the
// superuser: none of it executes text the source supplied.
type As struct {
	Account string
	// Pins holds an ordinary account's source to the addresses its names were
	// checked at, as "name:ip" (controlplane's import guard sets it). The tools
	// that reach a MySQL or MongoDB source run in throwaway containers, and each
	// gets these as --add-host entries: the name still goes out for TLS, but it
	// cannot resolve somewhere else between the check and the connection (DNS
	// rebinding). A Postgres source is held the same way by libpq's hostaddr,
	// which the guard writes into the connection string itself.
	Pins []string
}

func (a As) confined() bool { return a.Account != "" }

// addHosts is the docker run arguments that hold a source to Pins.
func (a As) addHosts() []string {
	var out []string
	for _, p := range a.Pins {
		out = append(out, "--add-host", p)
	}
	return out
}

// psqlRole is who a load's psql session logs in as.
func (a As) psqlRole() string {
	if a.confined() {
		return a.Account
	}
	return pgUser
}

// restrictKey is a fresh key for psql's \restrict. Nothing outside this process
// sees it, so nothing in the input can lift the restriction.
func restrictKey() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err)) // never happens on a supported OS
	}
	return hex.EncodeToString(b)
}

// dumpRestrict matches the first line a current pg_dump writes, and the line it
// ends with: a dump restricts itself with a key of its own.
var dumpRestrict = regexp.MustCompile(`^\\(un)?restrict [A-Za-z0-9]+\r?$`)

// restricted puts a confined load's input behind \restrict and leaves anyone
// else's alone.
//
// A script made by a current pg_dump already restricts itself: after its header
// comments comes its own \restrict, and it ends with the matching \unrestrict.
// Under ours, both would only print a complaint, so they are dropped; any other
// backslash command in the script is refused by psql and counted as a failed
// statement.
func (a As) restricted(r io.Reader) io.Reader {
	if !a.confined() {
		return r
	}
	pr, pw := io.Pipe()
	go func() {
		// A panic must still close the pipe, or psql would wait on it for ever.
		defer safego.Catch("import: confining a script", func(err error) { pw.CloseWithError(err) })
		br := bufio.NewReader(r)
		w := bufio.NewWriter(pw)
		fmt.Fprintf(w, "\\restrict %s\n", restrictKey())
		own, opened := "", false
		for {
			line, err := br.ReadString('\n')
			trimmed := strings.TrimSuffix(strings.TrimRight(line, "\n"), "\r")
			skip := false
			switch {
			case opened:
				skip = own != "" && trimmed == `\unrestrict `+own
			case strings.TrimSpace(trimmed) == "" || strings.HasPrefix(trimmed, "--"):
				// pg_dump's header: still before the first line that counts
			default:
				opened = true
				if dumpRestrict.MatchString(trimmed) && strings.HasPrefix(trimmed, `\restrict `) {
					own, skip = strings.TrimPrefix(trimmed, `\restrict `), true
				}
			}
			if !skip && line != "" {
				if _, werr := w.WriteString(line); werr != nil {
					pw.CloseWithError(werr)
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					w.Flush()
					pw.CloseWithError(err)
					return
				}
				break
			}
		}
		pw.CloseWithError(w.Flush())
	}()
	return pr
}

// checkRestrict refuses a confined load on a branch whose psql cannot switch
// its backslash commands off. \restrict arrived in PostgreSQL 16.10 and 18; an
// older client would print "invalid command" and carry on, which is exactly the
// case this exists to stop.
func checkRestrict(target string) error {
	cmd := execSudo("docker", "exec", "-i", container(target), "psql", "-q", "-U", pgUser, "-d", pgDatabase)
	cmd.Stdin = strings.NewReader("\\restrict foxprobe\n\\echo fox-unrestricted\n")
	out, _ := cmd.CombinedOutput()
	if s := string(out); strings.Contains(s, "fox-unrestricted") || !strings.Contains(s, "restricted") {
		return fmt.Errorf("branch %q runs a PostgreSQL client too old to load another account's SQL safely "+
			"(it has no \\restrict) — update this install with `fox update`, or ask an admin to run the import", target)
	}
	return nil
}

// beginAs readies a branch for a confined load and returns what undoes it.
//
// The account's role is made on the branch if main never had it. db_client is
// let create schemas and trusted extensions in this database for the length of
// the load, since a dump commonly does both, and the grant is taken back after
// unless the branch already had it. Neither reaches past this one branch.
func beginAs(target string, a As) (func(), error) {
	if !a.confined() {
		return func() {}, nil
	}
	if err := checkRestrict(target); err != nil {
		return nil, err
	}
	if err := EnsureUserRole(target, a.Account); err != nil {
		return nil, fmt.Errorf("prepare %s's role on %q: %w", a.Account, target, err)
	}
	had, err := capture("docker", "exec", container(target), "psql", "-U", pgUser, "-d", pgDatabase, "-tAc",
		"SELECT has_database_privilege('"+ClientRole+"', current_database(), 'CREATE')")
	if err != nil {
		return nil, err
	}
	if had == "t" {
		return func() {}, nil
	}
	if err := psqlAdmin(target, "GRANT CREATE ON DATABASE "+pgDatabase+" TO "+ClientRole+";"); err != nil {
		return nil, err
	}
	return func() { _ = psqlAdmin(target, "REVOKE CREATE ON DATABASE "+pgDatabase+" FROM "+ClientRole+";") }, nil
}

// psqlAdmin runs one statement of FoxByte's own as the superuser, with the
// guardrail override an import's own statements carry.
func psqlAdmin(target, sql string) error {
	return run("docker", "exec", "-e", pgImportOptions, container(target),
		"psql", "-q", "-U", pgUser, "-d", pgDatabase, "-v", "ON_ERROR_STOP=1", "-c", sql)
}

// explainAs adds what a failed confined load most likely ran into.
func explainAs(a As, err error) error {
	if err == nil || !a.confined() {
		return err
	}
	s := err.Error()
	for _, m := range []string{"permission denied", "must be superuser", "Must be superuser", "must be owner", "backslash commands are restricted"} {
		if strings.Contains(s, m) {
			return fmt.Errorf("%w\n  This import ran with %s's own privileges, as it would through the gateway. "+
				"A statement that needs a superuser (an extension only a superuser may create, for one) "+
				"or a psql backslash command needs an admin to run the import", err, a.Account)
		}
	}
	return err
}

// dumpRestrictFlag has a confined load's pg_dump restrict its own output with a
// key nobody else knows. A dump is the source server's text: this keeps it from
// carrying a psql command, and a pg_dump too old to know the flag refuses to
// run rather than dumping without it.
func dumpRestrictFlag(a As) string {
	if !a.confined() {
		return ""
	}
	return " --restrict-key=" + restrictKey()
}
