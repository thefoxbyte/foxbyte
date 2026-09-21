// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// HAState summarises high-availability status for the dashboard/API.
type HAState struct {
	Enabled   bool   `json:"enabled"`
	Standby   string `json:"standby"`   // standby container state
	Streaming bool   `json:"streaming"` // primary has a streaming standby
	Primary   string `json:"primary"`   // branch name currently serving as primary
}

// HAInfo reports current HA status.
func HAInfo() HAState {
	st := HAState{Primary: "main"}
	if PrimaryContainer() == container("standby") {
		st.Primary = "standby"
	}
	cs := ContainerState("standby")
	if cs == "absent" {
		return st
	}
	st.Enabled = true
	st.Standby = cs
	out, _ := capture("docker", "exec", "-e", "PGPASSWORD="+pgPass(), PrimaryContainer(),
		"psql", "-U", pgUser, "-d", pgDatabase, "-tAc",
		"SELECT count(*) FROM pg_stat_replication WHERE state='streaming';")
	if n := strings.TrimSpace(out); n != "" && n != "0" {
		st.Streaming = true
	}
	return st
}

// High availability: a hot standby that streams WAL from the primary
// (asynchronous, so it adds no commit latency), plus a manual failover that
// promotes the standby. The proxy routes "main" to whichever container is the
// current primary (see PrimaryContainer), so a promoted standby serves clients
// through the same endpoint.
//
// Note: this is a single-VM demonstration of the mechanism (replication +
// promotion + rerouting). Production HA additionally needs multi-host
// deployment, automatic failure detection, and fencing to prevent split-brain.

const (
	standbyDataset = "dbpool/standby"
	standbyMount   = "/dbpool/standby"
)

// haDanger says what each HA action would do to a promoted standby.
var haDanger = map[string]string{
	"enable":   "delete it and rebuild the standby from scratch",
	"disable":  "delete it, and every write made since the failover",
	"failover": "stop the only primary",
}

// haGuard refuses HA actions that would destroy the live primary. After `fox ha
// failover` the promoted standby serves "main": enable and disable delete its
// storage, and another failover would stop it. Failback is the reverse — it only
// makes sense after a failover.
func haGuard(action, primary string) error {
	failedOver := primary == container("standby")
	if action == "failback" {
		if !failedOver {
			return fmt.Errorf("nothing to fail back: 'main' is served by %s, not by a promoted standby", primary)
		}
		return nil
	}
	if failedOver {
		return fmt.Errorf("refusing `fox ha %s`: 'main' is being served by the promoted standby since `fox ha failover`, and this would %s.\n"+
			"Run `fox ha failback` first to move 'main' back to its own container", action, haDanger[action])
	}
	return nil
}

// allowReplication lets standbys connect to a primary for streaming replication.
func allowReplication(primary string) error {
	quiet("docker", "exec", "-u", "postgres", primary, "bash", "-c",
		`grep -q '^host replication' "$PGDATA/pg_hba.conf" || echo 'host replication all all scram-sha-256' >> "$PGDATA/pg_hba.conf"`)
	return run("docker", "exec", "-e", "PGPASSWORD="+pgPass(), primary,
		"psql", "-U", pgUser, "-d", pgDatabase, "-c", "SELECT pg_reload_conf();")
}

// startStandbyContainer runs the standby's Postgres on its storage. Before a
// failover it streams from the primary named in its recovery settings; after a
// promotion the same container is a primary.
//
// It carries the same object-storage environment and archive settings as the
// primary (startContainer). archive_mode=on archives only when the server is
// out of recovery, so nothing is pushed while it is a standby -- the primary is
// already archiving those same segments -- and the moment it is promoted it
// continues the WAL archive on its own timeline. Without this a promoted
// standby ran with no archiving at all: `fox backup create` had nothing to
// anchor and a restore could not reach anything written after the failover.
// archive_mode is a postmaster setting, so it has to be here rather than
// reloaded at promotion time.
func startStandbyContainer(store storage) error {
	return run("docker", standbyRunArgs(store.standbyPath())...)
}

// standbyRunArgs builds the standby's `docker run` arguments. Separate from
// startStandbyContainer so a test can assert the archive settings are there.
func standbyRunArgs(dataPath string) []string {
	// Publish a host port so the proxy can route to it if it is later promoted.
	args := []string{"run", "-d",
		"--name", container("standby"), "--network", network,
		"-p", "0:5432",
		"-e", "PGPASSWORD=" + pgPass(), // used by the WAL receiver to authenticate
		"-e", "PGDATA=/var/lib/postgresql/data/pgdata",
		"-v", dataPath + ":/var/lib/postgresql/data",
	}
	args = append(args, walgEnv()...)
	args = append(args, "-e", "WALG_COMPRESSION_METHOD=lz4")
	return append(args, pgImage(), "postgres",
		"-c", "wal_level=replica",
		"-c", "archive_mode=on",
		"-c", "archive_command=wal-g wal-push %p",
		"-c", "archive_timeout=60",
		"-c", "listen_addresses=*")
}

// HAEnable provisions a hot standby streaming from the current primary.
func HAEnable() error {
	primary := PrimaryContainer()
	if err := haGuard("enable", primary); err != nil {
		return err
	}

	// 1. Allow replication connections on the primary, then reload.
	if err := allowReplication(primary); err != nil {
		return err
	}

	// 2. Fresh standby storage.
	quiet("docker", "rm", "-f", container("standby"))
	store := activeStorage()
	if err := store.resetStandby(); err != nil {
		return err
	}
	if err := run("chown", "-R", pgUID+":"+pgUID, store.standbyPath()); err != nil {
		return err
	}

	// 3. Base backup from the primary, with recovery config (-R) and streaming WAL.
	if err := run("docker", "run", "--rm", "--user", pgUID, "--network", network,
		"-e", "PGPASSWORD="+pgPass(),
		"-v", store.standbyPath()+":/data",
		pgImage(),
		"pg_basebackup", "-h", primary, "-U", pgUser, "-D", "/data/pgdata",
		"-R", "-X", "stream", "-c", "fast"); err != nil {
		return err
	}

	// 4. Start the standby — it streams from the primary named in primary_conninfo.
	if err := startStandbyContainer(store); err != nil {
		return err
	}
	return waitReady("standby")
}

// HAStatus prints replication status from both the primary and the standby.
func HAStatus() error {
	switch ContainerState("standby") {
	case "absent":
		fmt.Println("HA not enabled (no standby). Run: foxbyte ha enable")
		return nil
	case "running":
		// proceed
	default:
		fmt.Println("standby exists but is not running. Rebuild it with: foxbyte ha enable")
		return nil
	}
	fmt.Println("=== primary: connected standbys (pg_stat_replication) ===")
	_ = run("docker", "exec", "-e", "PGPASSWORD="+pgPass(), PrimaryContainer(),
		"psql", "-U", pgUser, "-d", pgDatabase, "-x", "-c",
		"SELECT application_name, client_addr, state, sync_state, replay_lag FROM pg_stat_replication;")
	fmt.Println("=== standby: recovery position ===")
	_ = run("docker", "exec", "-e", "PGPASSWORD="+pgPass(), container("standby"),
		"psql", "-U", pgUser, "-d", pgDatabase, "-c",
		"SELECT pg_is_in_recovery() AS in_recovery, pg_last_wal_receive_lsn() AS received, pg_last_wal_replay_lsn() AS replayed;")
	return nil
}

// HAFailover promotes the standby to primary and reroutes "main" to it. The old
// primary is stopped to avoid split-brain.
func HAFailover() error {
	old := PrimaryContainer()
	if err := haGuard("failover", old); err != nil {
		return err
	}
	if ContainerState("standby") != "running" {
		return fmt.Errorf("no running standby to promote — run 'foxbyte ha enable' first")
	}
	if err := run("docker", "exec", "-e", "PGPASSWORD="+pgPass(), container("standby"),
		"psql", "-U", pgUser, "-d", pgDatabase, "-c", "SELECT pg_promote();"); err != nil {
		return err
	}
	quiet("docker", "stop", old) // the old primary steps down
	if err := setPrimary("standby"); err != nil {
		return err
	}
	fmt.Println("failover complete: standby promoted; 'main' now routes to it via the proxy")
	fmt.Println("to move 'main' back to its own container later, keeping every write: fox ha failback")
	return nil
}

// HADisable tears down the standby and resets primary routing to "main".
func HADisable() error {
	if err := haGuard("disable", PrimaryContainer()); err != nil {
		return err
	}
	quiet("docker", "rm", "-f", container("standby"))
	activeStorage().destroyStandby()
	return setPrimary("main")
}

// ensurePromotedStandby is what `fox up` does after a failover: the promoted
// standby is the primary, so it is brought up (recreated from its storage if
// `fox stop` removed its container) and the stale old main is left stopped —
// starting it would make a second writable primary.
func ensurePromotedStandby() error {
	store := activeStorage()
	switch ContainerState("standby") {
	case "running":
	case "absent":
		if exec.Command("sudo", "test", "-d", store.standbyPath()+"/pgdata").Run() != nil {
			return fmt.Errorf("'main' is recorded as served by the promoted standby, but its data is missing (%s).\n"+
				"If you mean to go back to the old main and discard the writes made since the failover, delete ~/.fox/primary and run `fox up`", store.standbyPath())
		}
		if err := startStandbyContainer(store); err != nil {
			return err
		}
	default:
		if err := run("docker", "start", container("standby")); err != nil {
			return err
		}
	}
	if err := waitReady("standby"); err != nil {
		return err
	}
	fmt.Println("note: 'main' is served by the promoted standby since `fox ha failover` — run `fox ha failback` to move it back to its own container")
	// A standby created before archiving was set up here runs without it, and
	// `docker start` cannot add it (archive_mode needs a postmaster start), so
	// say so rather than leaving the gap silent.
	if haQuery(container("standby"), "SELECT current_setting('archive_mode')") == "off" {
		fmt.Println("note: this standby is not archiving WAL (it predates that change), so backups and point-in-time restore\n" +
			"      do not cover writes made since the failover — `fox ha failback` then `fox ha enable` rebuilds it with archiving")
	}
	return nil
}

// HAFailback moves "main" back to its own container after `fox ha failover`,
// keeping every write made on the promoted standby since. main is rebuilt as a
// replica of the standby, allowed to catch up, and promoted once the standby has
// stopped and main has replayed everything it wrote. Until that moment the
// standby stays the primary, so a failure part-way loses nothing.
func HAFailback() error {
	if err := haGuard("failback", PrimaryContainer()); err != nil {
		return err
	}
	if ContainerState("standby") != "running" {
		return fmt.Errorf("the promoted standby isn't running — bring it up with `fox up`, then run `fox ha failback` again")
	}
	standby := container("standby")
	store := activeStorage()

	// Before the standby is stopped: undo by removing the half-built main.
	stopped := func(cause error) error {
		quiet("docker", "rm", "-f", container("main"))
		return fmt.Errorf("failback stopped: %w\n'main' is still served by the standby and nothing was lost; fix the problem and run `fox ha failback` again", cause)
	}
	// After the standby is stopped, but before main is promoted: start it again.
	restart := func(cause error) error {
		quiet("docker", "rm", "-f", container("main"))
		if run("docker", "start", standby) == nil {
			_ = waitReady("standby")
		}
		return stopped(cause)
	}

	fmt.Println("1/5 copying the promoted standby into main…")
	if err := allowReplication(standby); err != nil {
		return stopped(err)
	}
	quiet("docker", "rm", "-f", container("main"))
	// Only the contents are replaced: branches are copy-on-write clones of main's
	// snapshots, so its dataset stays.
	if err := run("rm", "-rf", mountpoint("main")+"/pgdata"); err != nil {
		return stopped(err)
	}
	if err := run("chown", "-R", pgUID+":"+pgUID, mountpoint("main")); err != nil {
		return stopped(err)
	}
	if err := run("docker", "run", "--rm", "--user", pgUID, "--network", network,
		"-e", "PGPASSWORD="+pgPass(),
		"-v", mountpoint("main")+":/data",
		pgImage(),
		"pg_basebackup", "-h", standby, "-U", pgUser, "-D", "/data/pgdata",
		"-R", "-X", "stream", "-c", "fast"); err != nil {
		return stopped(err)
	}

	fmt.Println("2/5 starting main as a replica and letting it catch up…")
	if err := startContainer("main", true); err != nil {
		return stopped(err)
	}
	if err := waitReady("main"); err != nil {
		return stopped(err)
	}
	if err := pollUntil("main to catch up with the standby", 2*time.Minute, func() bool {
		n, _ := strconv.Atoi(haQuery(standby,
			"SELECT count(*) FROM pg_stat_replication WHERE state='streaming' AND replay_lsn >= pg_current_wal_lsn()"))
		return n > 0
	}); err != nil {
		return stopped(err)
	}

	fmt.Println("3/5 stopping the standby and waiting for main to replay its last writes…")
	// A clean shutdown sends all remaining WAL, up to the shutdown checkpoint, to
	// the connected replica before the server exits.
	if err := run("docker", "stop", standby); err != nil {
		return restart(err)
	}
	out, err := capture("docker", "run", "--rm", "--user", pgUID,
		"-v", store.standbyPath()+":/data", pgImage(), "pg_controldata", "/data/pgdata")
	if err != nil {
		return restart(fmt.Errorf("reading the standby's final WAL position: %w", err))
	}
	final, err := parseControlCheckpoint(out)
	if err != nil {
		return restart(err)
	}
	if err := pollUntil("main to replay the standby's WAL up to "+final, time.Minute, func() bool {
		return lsnAtLeast(haQuery(container("main"), "SELECT pg_last_wal_replay_lsn()"), final)
	}); err != nil {
		return restart(err)
	}

	fmt.Println("4/5 promoting main…")
	if err := run("docker", "exec", "-e", "PGPASSWORD="+pgPass(), container("main"),
		"psql", "-U", pgUser, "-d", pgDatabase, "-c", "SELECT pg_promote();"); err != nil {
		return restart(err)
	}
	// From here main is a primary: never start the standby again.
	if err := setPrimary("main"); err != nil {
		return err
	}
	if err := waitRecovered("main"); err != nil {
		return fmt.Errorf("main was promoted but isn't ready yet: %w — check `fox status`", err)
	}

	fmt.Println("5/5 removing the old standby…")
	quiet("docker", "rm", "-f", standby)
	store.destroyStandby()

	fmt.Println("failback complete: 'main' is served by its own container again, with every write made during the failover.")
	fmt.Println("  WAL archiving has resumed. Take a fresh base backup now: fox backup create")
	fmt.Println("  (point-in-time restore can't reach the time 'main' ran on the standby, which didn't archive WAL).")
	fmt.Println("  Run `fox ha enable` for a new standby.")
	return nil
}

// haQuery runs a single-value query on a container, returning "" on any error.
func haQuery(c, sql string) string {
	out, _ := capture("docker", "exec", "-e", "PGPASSWORD="+pgPass(), c,
		"psql", "-U", pgUser, "-d", pgDatabase, "-tAc", sql)
	return strings.TrimSpace(out)
}

// pollUntil checks ok every half second until it holds or the timeout passes.
func pollUntil(what string, timeout time.Duration, ok func() bool) error {
	deadline := time.Now().Add(timeout)
	for !ok() {
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for %s", timeout, what)
		}
		time.Sleep(500 * time.Millisecond)
	}
	return nil
}

// parseLSN reads a Postgres WAL position ("16/B374D848") as a number.
func parseLSN(s string) (uint64, bool) {
	hi, lo, ok := strings.Cut(strings.TrimSpace(s), "/")
	if !ok {
		return 0, false
	}
	h, err1 := strconv.ParseUint(hi, 16, 32)
	l, err2 := strconv.ParseUint(lo, 16, 32)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	return h<<32 | l, true
}

// lsnAtLeast reports whether WAL position a is at or past b (false if either
// can't be read).
func lsnAtLeast(a, b string) bool {
	x, ok1 := parseLSN(a)
	y, ok2 := parseLSN(b)
	return ok1 && ok2 && x >= y
}

// parseControlCheckpoint finds "Latest checkpoint location" in pg_controldata
// output — for a cleanly stopped server, the position of its shutdown checkpoint.
func parseControlCheckpoint(out string) (string, error) {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(k) == "Latest checkpoint location" {
			if v = strings.TrimSpace(v); lsnAtLeast(v, v) {
				return v, nil
			}
		}
	}
	return "", fmt.Errorf("pg_controldata didn't report the latest checkpoint location")
}
