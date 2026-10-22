// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// Proving the backups restore.
//
// The engine took base backups, archived WAL and could restore to a point in
// time — and nothing ever checked that end to end on a real install. A backup
// that cannot be restored is not a backup, and point-in-time recovery is the most
// consequential thing FoxByte claims, so the claim needs a periodic answer rather
// than an argument from the code.
//
// The check is deliberately the whole path, not a piece of it: write a row on
// main, force the WAL segment holding it into the archive, restore the newest
// base backup into a container of its own, replay to the end, and look for that
// row. If it is there, then the base backup, the archive, the credentials, the
// image and the replay all worked a moment ago.

// probeTable lives in the Blackbox's schema, which the ledger's event triggers
// skip (bb._skip), so this leaves no entries in the record of schema changes.
var probeTable = ledger.SchemaName + ".restore_probe"

// RestoreCheck is what one check found, and what is written to disk for `fox
// check` and `fox status` to read.
type RestoreCheck struct {
	At         string `json:"at"`                    // when the check ran (RFC3339)
	OK         bool   `json:"ok"`                    //
	Token      string `json:"token,omitempty"`       // the row that had to survive
	BaseBackup string `json:"base_backup,omitempty"` //
	Seconds    int    `json:"seconds"`               // how long the whole check took
	Tables     int    `json:"tables"`                // user tables found in the restored copy
	Target     string `json:"target,omitempty"`      // where the backups were read from
	Err        string `json:"error,omitempty"`       //
}

const (
	// EnvRestoreCheckInterval is how often the control plane proves a restore
	// works ("off" to stop, a duration such as "168h" otherwise).
	EnvRestoreCheckInterval = "RESTORE_CHECK_INTERVAL"
	// restoreCheckContainer is its own container, so a person's `fox restore`
	// is never taken over by a check running in the background.
	restoreCheckContainer = "restore-check"
	// archiveWait is how long to wait for the probe's WAL segment to reach the
	// archive before giving up.
	archiveWait = 120 * time.Second
)

func restoreCheckPath() string { return brand.StatePath("restore-check.json") }

// LastRestoreCheck is the most recent result, and whether there is one.
func LastRestoreCheck() (RestoreCheck, bool) {
	b, err := os.ReadFile(restoreCheckPath())
	if err != nil {
		return RestoreCheck{}, false
	}
	var c RestoreCheck
	if err := json.Unmarshal(b, &c); err != nil {
		return RestoreCheck{}, false
	}
	return c, true
}

func saveRestoreCheck(c RestoreCheck) {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return
	}
	if err := os.WriteFile(restoreCheckPath(), b, 0o644); err != nil {
		log.Printf("restore check: recording the result: %v", err)
	}
}

// restoreCheckInterval is how often to run the check (0 = never). Weekly by
// default: it restores a full copy of main, which is real work, and a week is
// often enough to catch a backup path that has stopped working before the day it
// is needed.
func restoreCheckInterval() time.Duration {
	v := strings.ToLower(strings.TrimSpace(brand.Getenv(EnvRestoreCheckInterval)))
	switch v {
	case "off", "0", "false", "no":
		return 0
	case "":
		return 7 * 24 * time.Hour
	}
	if d, err := time.ParseDuration(v); err == nil && d >= time.Hour {
		return d
	}
	return 7 * 24 * time.Hour
}

// VerifyRestore runs the check once and records the result. logf receives the
// progress a person watching `fox backup verify` should see.
func VerifyRestore(logf func(string, ...any)) (RestoreCheck, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	started := time.Now()
	c := RestoreCheck{At: started.UTC().Format(time.RFC3339), Target: target().Describe()}
	finish := func(err error) (RestoreCheck, error) {
		c.Seconds = int(time.Since(started).Seconds())
		c.OK = err == nil
		if err != nil {
			c.Err = err.Error()
		}
		saveRestoreCheck(c)
		return c, err
	}

	primary := strings.TrimPrefix(PrimaryContainer(), containerPrefix)
	if ContainerState(primary) != "running" {
		return finish(fmt.Errorf("the primary is not running, so there is nothing to check"))
	}
	if ContainerState(restoreCheckContainer) != "absent" {
		removeContainer(container(restoreCheckContainer))
	}

	// 1. A row that can only have come from now.
	token, err := probeToken()
	if err != nil {
		return finish(err)
	}
	c.Token = token
	logf("Writing a probe row on %s …\n", primary)
	if err := SQL(primary, fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS %s (id bigserial PRIMARY KEY, token text NOT NULL, at timestamptz NOT NULL DEFAULT now());
		 INSERT INTO %s (token) VALUES (%s);`, probeTable, probeTable, quoteLiteral(token))); err != nil {
		return finish(fmt.Errorf("writing the probe row: %w", err))
	}

	// 2. Its WAL segment has to be in the archive, or a restore cannot replay it.
	//    The switch is its own statement: one psql -c is a single transaction, so a
	//    switch in the same string would run before the insert commits.
	logf("Waiting for its WAL segment to reach the archive …\n")
	if err := waitArchived(primary); err != nil {
		return finish(err)
	}

	// 3. Restore the newest base backup into a container of its own and replay.
	logf("Restoring the newest base backup into %s (this is the slow part) …\n", container(restoreCheckContainer))
	// "LATEST" is wal-g's sentinel, not a name anyone can look up, so the report
	// names the backup it actually means.
	if bs, err := Backups(); err == nil && len(bs) > 0 {
		c.BaseBackup = bs[0].Name + " (" + bs[0].FinishedAt + ")"
	} else if name, err := restoreBackupName("latest"); err == nil {
		c.BaseBackup = name
	}
	defer removeContainer(container(restoreCheckContainer))
	if err := restorePITRInto(restoreCheckContainer, "latest", false); err != nil {
		return finish(fmt.Errorf("restoring: %w", err))
	}

	// 4. The row has to be there. This is the whole check.
	got, err := probeQuery(fmt.Sprintf(
		"SELECT count(*) FROM %s WHERE token = %s", probeTable, quoteLiteral(token)))
	if err != nil {
		return finish(fmt.Errorf("reading the probe row back: %w: %s", err, firstLine(got)))
	}
	if strings.TrimSpace(got) != "1" {
		// The usual innocent cause: the backup target moved. Backups and WAL stay
		// where they were written, and a restore reads the target in force, so
		// until a base backup is taken on the new target a replay runs into the
		// gap and stops before the newest writes.
		return finish(fmt.Errorf("the restored copy does not hold the probe row written before the check "+
			"(psql said %q): the archive or the replay is not carrying the newest writes.\n"+
			"If the backup target changed recently, take a base backup on the target in force first "+
			"(`%s backup create`) — a restore reads only the target it is pointed at, and cannot replay "+
			"across WAL that was archived somewhere else", firstLine(got), brand.CLI))
	}
	if n, err := probeQuery(`SELECT count(*) FROM information_schema.tables
		WHERE table_schema NOT IN ('pg_catalog','information_schema','` + ledger.SchemaName + `','` + ledger.PrivateSchemaName + `')`); err == nil {
		c.Tables, _ = strconv.Atoi(strings.TrimSpace(n))
	}
	logf("The probe row is in the restored copy: the backups restore.\n")
	return finish(nil)
}

// probeQuery asks the restored copy one question, unaligned so the answer is the
// value itself, and keeps stderr: "relation does not exist" is the difference
// between a replay that stopped short and a psql that could not connect, and a
// check that cannot tell them apart is not worth running. (Query discards stderr;
// QueryText keeps it but prints a table with a header.)
func probeQuery(sql string) (string, error) {
	return captureCombined("docker", "exec", "--env-file", pgEnvFile(), container(restoreCheckContainer),
		"psql", "-h", "localhost", "-U", pgUser, "-d", pgDatabase, "-tAc", sql)
}

// probeToken is the value that has to survive the round trip.
func probeToken() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating a probe token: %w", err)
	}
	return "probe-" + hex.EncodeToString(b), nil
}

// waitArchived forces a WAL switch and waits until the archiver reports the
// segment it produced as archived.
func waitArchived(primary string) error {
	before, _ := Query(primary, "SELECT coalesce(last_archived_wal,'') FROM pg_stat_archiver")
	if err := SQL(primary, "SELECT pg_switch_wal()"); err != nil {
		return fmt.Errorf("switching WAL: %w", err)
	}
	deadline := time.Now().Add(archiveWait)
	for time.Now().Before(deadline) {
		out, err := Query(primary, `SELECT coalesce(last_archived_wal,'') || ' ' || coalesce(failed_count,0)::text
			FROM (SELECT last_archived_wal, failed_count FROM pg_stat_archiver) s`)
		if err == nil {
			parts := strings.Fields(out)
			if len(parts) > 0 && parts[0] != "" && parts[0] != strings.TrimSpace(before) {
				return nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	failed, _ := Query(primary, "SELECT coalesce(last_failed_wal,'') FROM pg_stat_archiver")
	if f := strings.TrimSpace(failed); f != "" {
		return fmt.Errorf("the WAL archive is not accepting segments (the archiver last failed on %s): "+
			"a restore cannot replay what was never archived", f)
	}
	return errors.New("the probe's WAL segment did not reach the archive within " + archiveWait.String())
}

// StartRestoreVerifier runs the check on a schedule in the control plane, the
// same way base backups are taken. It waits a while after start so it never
// competes with an install that is still coming up.
func StartRestoreVerifier() {
	iv := restoreCheckInterval()
	if iv == 0 {
		log.Printf("restore check: off (%s)", brand.EnvName(EnvRestoreCheckInterval))
		return
	}
	log.Printf("restore check: proving a restore works every %s", iv)
	go func() {
		time.Sleep(5 * time.Minute)
		for {
			if due(iv) {
				c, err := VerifyRestore(func(f string, a ...any) { log.Printf("restore check: "+strings.TrimRight(f, "\n"), a...) })
				if err != nil {
					log.Printf("restore check: FAILED after %ds: %v", c.Seconds, err)
				} else {
					log.Printf("restore check: the backups restore (%ds, from %s)", c.Seconds, c.BaseBackup)
				}
			}
			time.Sleep(time.Hour)
		}
	}()
}

// due reports whether the last check is older than the interval (or never ran).
func due(iv time.Duration) bool {
	last, ok := LastRestoreCheck()
	if !ok {
		return true
	}
	at, err := time.Parse(time.RFC3339, last.At)
	if err != nil {
		return true
	}
	return time.Since(at) >= iv
}
