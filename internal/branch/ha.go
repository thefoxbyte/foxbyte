// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// HAState summarises high-availability status for the dashboard/API.
type HAState struct {
	Enabled   bool   `json:"enabled"`
	Standby   string `json:"standby"`   // standby container state
	Streaming bool   `json:"streaming"` // primary has a streaming standby
	Primary   string `json:"primary"`   // branch name currently serving as primary
	// Sync is whether zero-data-loss mode was asked for, and SyncActive whether
	// the primary is actually waiting for the standby. They differ whenever
	// there is no standby to wait for — a failover, or a rebuild in progress —
	// and that difference is the thing worth showing rather than one bit.
	Sync       bool `json:"sync"`
	SyncActive bool `json:"sync_active"`
}

// HAInfo reports current HA status.
func HAInfo() HAState {
	st := HAState{Primary: "main", Sync: SyncOn()}
	if PrimaryContainer() == container("standby") {
		st.Primary = "standby"
	}
	cs := ContainerState("standby")
	if cs == "absent" {
		return st
	}
	st.Enabled = true
	st.Standby = cs
	// Both facts in one round trip, because this feeds the dashboard and the
	// status API: a second `docker exec psql` per call would double what the
	// page waits for to learn one extra bit.
	out, _ := capture("docker", "exec", "--env-file", pgEnvFile(), PrimaryContainer(),
		"psql", "-U", pgUser, "-d", pgDatabase, "-tAc",
		"SELECT (SELECT count(*) FROM pg_stat_replication WHERE state='streaming')::text"+
			" || '|' || (current_setting('synchronous_standby_names') <> '')::text")
	parts := strings.Split(strings.TrimSpace(out), "|")
	if len(parts) == 2 {
		st.Streaming = parts[0] != "" && parts[0] != "0"
		st.SyncActive = strings.HasPrefix(strings.ToLower(parts[1]), "t")
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

// allowReplication lets a standby connect to a primary for streaming
// replication: the role that may do it, and the one rule that admits it.
//
// This used to append `host replication all all` and let the standby connect as
// the superuser. See replicationrole.go for what that meant and what replaced
// it. The wide rule is removed rather than left below the narrow one, because
// pg_hba is first-match-wins and a wide rule anywhere still admits everyone it
// names.
func allowReplication(primary string) error {
	if err := EnsureReplicationRole(primary); err != nil {
		return err
	}
	peer := ""
	if e, ok := CurrentExposure(); ok {
		peer = e.Peer
	}
	if out, err := captureCombined("docker", "exec", "-u", "postgres", primary,
		"bash", "-c", hbaScript(peer)); err != nil {
		return fmt.Errorf("narrowing the replication rule on %s: %w\n%s", primary, err, strings.TrimSpace(out))
	}
	if out, err := captureCombined("docker", "exec", "--env-file", pgEnvFile(), primary,
		"psql", "-U", pgUser, "-d", pgDatabase, "-tAq", "-c", "SELECT pg_reload_conf()"); err != nil {
		return fmt.Errorf("reloading %s after narrowing the replication rule: %w\n%s", primary, err, strings.TrimSpace(out))
	}
	return nil
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
	// The slot the standby streams through, made here rather than at `ha
	// enable` so that every path which starts a standby has it: `ha enable`,
	// and the restart `realtime setup` does on an install that already has one.
	//
	// Skipped when this container *is* the primary — after a failover the
	// promoted standby is started by this same function, and a slot named
	// fox_standby on it would point a server at itself.
	if standbySlotWanted() {
		if primary := PrimaryContainer(); primary != container("standby") {
			if err := ensureStandbySlot(primary); err != nil {
				return err
			}
		}
	}
	return run("docker", standbyRunArgs(store.standbyPath())...)
}

// StandbyName is what this install calls its standby, and it is one word on
// purpose: it names the standby's physical replication slot on the primary, the
// standby's cluster_name, and therefore the application_name the primary sees
// in pg_stat_replication and the name synchronous_standby_names looks for.
// Three places Postgres keeps in different namespaces, one participant.
const StandbyName = "fox_standby"

// StandbySlot is the physical replication slot a standby holds on its primary.
//
// Deliberately outside SlotPrefix: the change feed's slots are swept, listed
// and dropped by name prefix, and this one must never be caught by any of that
// — losing it would leave the standby without the slot that slot
// synchronisation depends on.
const StandbySlot = StandbyName

// standbySlotWanted reports whether this install needs the physical slot, and
// it is the same switch as the rest of slot synchronisation on purpose.
//
// A physical slot is not free: it holds WAL on the primary for a standby that
// may be gone, and with the feed off there is no max_slot_wal_keep_size to
// bound it — so on an install that does not stream changes it would trade "a
// dead standby needs rebuilding" for "a dead standby fills the primary's
// disk". That is not a trade to make for a feature such an install does not
// use. With the feed on the budget is set and bounds it, and the slot is what
// synchronisation needs.
//
// So with the feed off, or on a major without failover-aware slots, a base
// backup is byte-for-byte the command it has always been.
func standbySlotWanted() bool { return RealtimeOn() && SlotSyncSupported() }

// baseBackupArgs is how a standby is built from its primary.
//
// conninfoDB asks for a database name in the recovery settings the backup
// writes; false gives the argument list this has always used, which is what an
// install without the change feed still gets.
//
// Why -d rather than -h/-U: pg_basebackup -R copies the parameters it connected
// with into primary_conninfo, and -h/-U produce a conninfo with no database
// name — checked, not assumed. Slot synchronisation needs one, because the
// worker on the standby connects to a database on the primary to read its
// slots; without it, it logs a warning and silently never syncs, which is the
// worst of both outcomes.
//
// What is deliberately NOT here is -S. The standby needs a physical slot, but
// pointing the *backup* at one makes the backup fail for a reason that has
// nothing to do with it:
//
//	pg_basebackup: error: could not send replication command "START_REPLICATION":
//	  ERROR: can no longer access replication slot "fox_standby"
//	  DETAIL: This replication slot has been invalidated due to "wal_removed".
//
// A slot that reserves write-ahead log from the moment it is made is subject to
// max_slot_wal_keep_size from that moment too, so on a busy primary with a
// small budget it can be invalidated in the seconds between being created and
// the backup's WAL streamer connecting — and then `ha enable` cannot build a
// standby at all. The standby is told its slot on its own command line
// instead (standbyRunArgs), and the slot reserves nothing until the standby
// connects to it. Pure, so both shapes are tested without a pool.
func baseBackupArgs(from, dataDir string, conninfoDB bool) []string {
	if !conninfoDB {
		return []string{
			"pg_basebackup", "-h", from, "-U", ReplicationRole, "-D", dataDir,
			"-R", "-X", "stream", "-c", "fast",
		}
	}
	conninfo := fmt.Sprintf("host=%s user=%s dbname=%s", from, ReplicationRole, pgDatabase)
	return []string{
		"pg_basebackup", "-d", conninfo, "-D", dataDir,
		"-R", "-X", "stream", "-c", "fast",
	}
}

// ensureStandbySlot creates the standby's physical slot on the server it
// streams from, if it is not already there.
//
// Idempotent because every caller can run twice: `ha enable` is how a standby
// is rebuilt, and `realtime setup` restarts the standby on an install that
// already has one.
//
// It reserves no write-ahead log until the standby connects (the `false`), and
// that is the whole point. A slot that reserves from creation is subject to
// max_slot_wal_keep_size from creation, which is how the first version of this
// made `ha enable` fail outright — see baseBackupArgs. Nothing is lost by
// waiting: the WAL the standby needs next is already in its own pg_wal, put
// there by the base backup's -X stream.
//
// server is a container name, reached the way allowReplication reaches it.
func ensureStandbySlot(server string) error {
	return slotSQL(server, "SELECT pg_create_physical_replication_slot('"+StandbySlot+"', false)"+
		" WHERE NOT EXISTS (SELECT 1 FROM pg_replication_slots WHERE slot_name = '"+StandbySlot+"')")
}

// dropStandbySlot removes it on teardown, and only while it is inactive —
// dropping one out from under a live walsender is Postgres's refusal to make,
// not ours. `fox up` sweeps nothing outside SlotPrefix, so this is the only
// thing that cleans it up.
func dropStandbySlot(server string) error {
	return slotSQL(server, "SELECT pg_drop_replication_slot('"+StandbySlot+"')"+
		" WHERE EXISTS (SELECT 1 FROM pg_replication_slots WHERE slot_name = '"+StandbySlot+"' AND NOT active)")
}

// dropStandbySlotIfUp is the same, and says nothing at all when there is no
// running primary to ask.
func dropStandbySlotIfUp(server string) error {
	if ContainerState("main") != "running" {
		return nil
	}
	return dropStandbySlot(server)
}

// slotSQL runs one statement on a container by name, the way allowReplication
// reaches one, and keeps psql's rendered result out of the way: these return a
// row and `ha enable` printed a two-line table for each in the middle of its
// own output. Captured rather than streamed, so a failure still carries the
// message Postgres gave.
func slotSQL(server, sql string) error {
	out, err := captureCombined("docker", "exec", "--env-file", pgEnvFile(), server,
		"psql", "-U", pgUser, "-d", pgDatabase, "-tAq", "-v", "ON_ERROR_STOP=1", "-c", sql)
	if err != nil {
		return fmt.Errorf("%w\n%s", err, strings.TrimSpace(out))
	}
	return nil
}

// standbyRunArgs builds the standby's `docker run` arguments. Separate from
// startStandbyContainer so a test can assert the archive settings are there.
func standbyRunArgs(dataPath string) []string {
	// No host port: the Gateway routes to a promoted standby by its address on
	// the docker network (BackendAddr), exactly as it does to main. A published
	// port only offered a way around the Gateway, with the superuser password.
	args := []string{"run", "-d",
		"--name", container("standby"), "--network", network,
		"--env-file", pgEnvFile(), // used by the WAL receiver to authenticate
		"-e", "PGDATA=/var/lib/postgresql/data/pgdata",
		"-v", dataPath + ":/var/lib/postgresql/data",
	}
	// Following a primary on another machine: the certificate its walreceiver
	// verifies, at the path primary_conninfo names. pg_basebackup -R recorded
	// sslrootcert as the path it saw during the copy, read later from inside
	// this container — so the two have to agree, and they do by using one
	// constant (nodejoin.go).
	args = append(args, joinedMount()...)
	// The standby streams from the primary and archives WAL after a failover, so
	// it is long-lived and must come back on its own like main (see restartPolicy).
	args = append(args, restartPolicy...)
	args = append(args, walgEnv()...)
	args = append(args, "-e", "WALG_COMPRESSION_METHOD=lz4")
	// The same settings the primary runs with, including the change feed's —
	// this standby is a primary in waiting, and one started without them would
	// come up after a failover unable to decode. Realtime would stop working at
	// the worst possible moment and for no visible reason.
	img := pgImage()
	args = append(args, img)
	args = append(args, postgresArgs(true, imageMajor(img))...)
	// The slot this standby streams through, which is what sync_replication_slots
	// needs in order to know how far the standby has got. On the command line
	// rather than written into PGDATA by pg_basebackup -R, because a backup that
	// streams through the slot fails when the slot is invalidated for falling
	// behind — see baseBackupArgs. A command-line setting also outranks
	// postgresql.auto.conf, so this is the one answer.
	if standbySlotWanted() {
		args = append(args, "-c", "primary_slot_name="+StandbySlot)
	}
	// And what this standby calls itself. Unconditional, because it costs
	// nothing and it is how the primary identifies the standby at all:
	// pg_basebackup -R writes no application_name, so without this the walreceiver
	// reports as `walreceiver` and zero-data-loss mode cannot name it.
	// cluster_name is fixed at postmaster start, which is why `ha sync on`
	// restarts a standby that predates this rather than asking for a rebuild.
	return append(args, "-c", "cluster_name="+StandbyName)
}

// HAEnable provisions a hot standby streaming from the current primary.
func HAEnable() error {
	primary := PrimaryContainer()
	if err := haGuard("enable", primary); err != nil {
		return err
	}
	// A standby of this install's own main and a standby of another install's
	// are the same container and the same storage. This would rebuild the
	// second from the first without saying so, and the machine would quietly
	// stop being a copy of anything that matters.
	if j, ok := CurrentJoin(); ok {
		return fmt.Errorf("this machine is a standby of %s:%d, and that standby is this container.\n"+
			"`%s ha enable` would rebuild it from this install's own main instead.\n"+
			"Run `%s node leave` first if this machine should stop following %s",
			j.Address, j.Port, brand.CLI, brand.CLI, j.Address)
	}

	// 1. Allow replication connections on the primary, then reload.
	if err := allowReplication(primary); err != nil {
		return err
	}

	// 2. Fresh standby storage.
	removeContainer(container("standby"))
	store := activeStorage()
	if err := store.resetStandby(); err != nil {
		return err
	}
	if err := run("chown", "-R", pgUID+":"+pgUID, store.standbyPath()); err != nil {
		return err
	}

	// 3. Base backup from the primary, with recovery config (-R) and streaming
	// WAL. The standby's replication slot is deliberately not involved here;
	// see baseBackupArgs.
	if err := run("docker", append([]string{"run", "--rm", "--user", pgUID, "--network", network,
		"--env-file", replicaEnvFile(),
		"-v", store.standbyPath() + ":/data",
		pgImage()},
		baseBackupArgs(primary, "/data/pgdata", standbySlotWanted())...)...); err != nil {
		return err
	}

	// 4. Start the standby — it streams from the primary named in
	// primary_conninfo, through the slot startStandbyContainer makes for it.
	if err := startStandbyContainer(store); err != nil {
		return err
	}
	if err := waitReady("standby"); err != nil {
		return err
	}
	// A standby exists again, so an install that asked for zero-data-loss mode
	// and lost it to a failover gets it back. Reports and carries on rather than
	// failing: a standby that is streaming is worth more than a setting.
	restoreSync()
	return nil
}

// RestartStandby recreates the standby's container on its existing storage, so
// it picks up a change to the arguments the primary runs with.
//
// A standby's command line is fixed when its container is made, and a standby
// is a primary in waiting. Turning the change feed on after `fox ha enable`
// therefore left the standby at wal_level=replica: it went on streaming,
// nothing looked wrong, and a failover promoted a primary that could not
// decode a thing -- with RealtimeHAGuard then refusing the `realtime setup`
// that would fix it until a failback, so the feed was stuck off at the worst
// possible moment.
//
// A restart rather than a rebuild: the recovery settings pg_basebackup -R wrote
// live in PGDATA, so the standby resumes streaming from where it had got to. A
// no-op when there is no standby.
func RestartStandby() error {
	if ContainerState("standby") == "absent" {
		return nil
	}
	removeContainer(container("standby"))
	if err := startStandbyContainer(activeStorage()); err != nil {
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
	if d := DescribeJoin(); d != "" {
		fmt.Printf("=== this machine ===\n%s\n", d)
		fmt.Printf("its own 'main' is idle while it follows that primary\n")
	}
	fmt.Println("=== durability ===")
	switch {
	case SyncActive() && syncQuorumMet():
		fmt.Printf("zero-data-loss mode is ON: a commit waits until %s has it on disk (RPO zero).\n", StandbyName)
	case SyncActive():
		fmt.Printf("zero-data-loss mode is ON but %s is NOT being counted — commits are waiting and\n"+
			"will not complete. Release them with: %s ha sync off\n", StandbyName, brand.CLI)
	case SyncOn():
		fmt.Printf("zero-data-loss mode was asked for but is not in effect. Put it back with: %s ha sync on\n", brand.CLI)
	default:
		fmt.Println("replication is asynchronous: commits never wait, and a lost machine costs")
		fmt.Println("up to archive_timeout (60s) of writes. `fox ha sync on` trades the first for the second.")
	}
	fmt.Println("=== accounts and keys ===")
	if s, err := auth.OpenFromEnv(); err == nil {
		fmt.Println(DescribeSharedState(s))
		_ = s.Close()
	} else {
		fmt.Printf("this node's account store could not be read: %v\n", err)
	}
	fmt.Println("=== reads ===")
	fmt.Println(DescribeStandbyReads())
	fmt.Println("=== primary: connected standbys (pg_stat_replication) ===")
	_ = run("docker", "exec", "--env-file", pgEnvFile(), PrimaryContainer(),
		"psql", "-U", pgUser, "-d", pgDatabase, "-x", "-c",
		"SELECT application_name, client_addr, state, sync_state, replay_lag FROM pg_stat_replication;")
	fmt.Println("=== standby: recovery position ===")
	_ = run("docker", "exec", "--env-file", pgEnvFile(), container("standby"),
		"psql", "-U", pgUser, "-d", pgDatabase, "-c",
		"SELECT pg_is_in_recovery() AS in_recovery, pg_last_wal_receive_lsn() AS received, pg_last_wal_replay_lsn() AS replayed;")
	return nil
}

// HAFailover promotes the standby to primary and reroutes "main" to it.
//
// The old primary is stopped first, which is the whole of fencing while both
// are containers on this machine. It is not enough when the primary is on
// another machine — see fenceRemotePrimary, which refuses rather than making a
// second one.
//
// force skips that refusal, for a primary an operator has already isolated by
// other means. It does not skip stopping the local one.
func HAFailover(force bool) error {
	old := PrimaryContainer()
	// Whether this promotion is of a copy taken from another install, which
	// decides whether its role passwords have to be rewritten. Read before the
	// promotion clears the join state.
	fromElsewhere := IsStandbyNode()
	if err := haGuard("failover", old); err != nil {
		return err
	}
	if ContainerState("standby") != "running" {
		return fmt.Errorf("no running standby to promote — run 'foxbyte ha enable' first")
	}
	// Before the promotion, not after: a refusal has to come while there is
	// still only one primary.
	if err := fenceRemotePrimary(force); err != nil {
		return err
	}
	if err := run("docker", "exec", "--env-file", pgEnvFile(), container("standby"),
		"psql", "-U", pgUser, "-d", pgDatabase, "-c", "SELECT pg_promote();"); err != nil {
		return err
	}
	quiet("docker", "stop", old) // the old primary steps down
	if err := setPrimary("standby"); err != nil {
		return err
	}
	// A promoted standby follows nobody: it is the primary now.
	//
	// Leaving the join behind would be a machine that holds the only copy of
	// the data while claiming to be a copy of something else — and the guards
	// built on that state would then refuse the right operations. `ha enable`
	// would refuse to give it a standby, and `node leave` would refuse to let
	// go of a primary it no longer follows. Cleared here, because a promotion
	// is exactly the moment it stops being true.
	if j, ok := CurrentJoin(); ok {
		if err := os.Remove(joinedPath()); err != nil && !os.IsNotExist(err) {
			fmt.Printf("\nWARNING: this machine was promoted but still records %s:%d as its primary (%v).\n"+
				"Remove %s by hand, or `%s ha enable` will refuse to give it a standby.\n\n",
				j.Address, j.Port, err, joinedPath(), brand.CLI)
		} else {
			fmt.Printf("this machine no longer follows %s:%d — it is the primary now, holding every\n"+
				"write that reached it.\n", j.Address, j.Port)
			fmt.Printf("  %s must NOT be started as a primary again: it would accept writes this\n"+
				"  machine never sees, and nothing could merge the two. Bring it back with\n"+
				"  `%s node join` against this machine, which replaces its copy.\n",
				j.Address, brand.CLI)
		}
	}
	// A copy from another install carries that install's role passwords, all of
	// them derived from a secret this machine does not have and must not be
	// given (rolepasswords.go). The gateway here derives its own, so without
	// this every client connection to the machine that just took over would
	// fail to authenticate — which phase 7 measured, and which is the other
	// half of what phase 2 exists to prevent.
	if fromElsewhere {
		touched, err := RewriteRolePasswords("standby")
		if err != nil {
			fmt.Printf("\nWARNING: the promotion succeeded, but the copy's role passwords are still the\n"+
				"other install's (%v). Clients will fail to authenticate until they are rewritten:\n"+
				"  %s ha repair-roles\n\n", err, brand.CLI)
		} else {
			fmt.Printf("rewrote %d role password(s) to this install's own — the copy was made with\n"+
				"another machine's secret, and nothing here knows it.\n", len(touched))
		}
	}
	// Zero-data-loss mode does not survive the promotion, and must not.
	//
	// ALTER SYSTEM writes postgresql.auto.conf and pg_basebackup copies PGDATA,
	// so a standby built while the mode was on carries the setting — checked, it
	// is in the copy. The promoted standby is now a primary with no standby of
	// its own, so the setting it inherited would make it wait for a server that
	// does not exist: every write would stop at the moment of a failover, which
	// is the moment it must not. The marker is left alone so `ha status` can
	// still say it was asked for, and `ha enable` puts it back.
	if SyncOn() || SyncActive() {
		if err := clearSyncOnPrimary(); err != nil {
			fmt.Printf("\nWARNING: the promoted standby still has synchronous_standby_names set (%v),\n"+
				"so it is waiting for a standby it does not have and writes will not complete.\n"+
				"Clear it now:\n  %s ha sync off\n\n", err, brand.CLI)
		} else {
			fmt.Printf("zero-data-loss mode is off while there is one copy: `%s ha enable` builds a new\n"+
				"standby and puts it back.\n", brand.CLI)
		}
	}
	fmt.Println("failover complete: standby promoted; 'main' now routes to it via the proxy")
	fmt.Println("to move 'main' back to its own container later, keeping every write: fox ha failback")
	return nil
}

// HADisable tears down the standby and resets primary routing to "main".
func HADisable() error {
	primary := PrimaryContainer()
	if err := haGuard("disable", primary); err != nil {
		return err
	}
	removeContainer(container("standby"))
	// The standby's slot, now that the standby it was holding WAL for is gone.
	// A slot nobody will consume holds write-ahead log that cannot be reclaimed.
	//
	// Only when the primary is up to be asked: `fox stop` then `fox ha disable`
	// is a reasonable thing to do, and warning there about a slot that cannot
	// even be looked for would be noise. Not fatal either, because the
	// walsender may take a moment to notice its container has gone, and failing
	// here would leave an install half torn down — so it is named instead.
	// haGuard has already refused a promoted standby, so the primary is main.
	if err := dropStandbySlotIfUp(primary); err != nil {
		fmt.Printf("The replication slot %q could not be dropped (%v). It holds write-ahead log\n"+
			"on the primary until it is gone. Drop it from `%s psql main` with:\n"+
			"  SELECT pg_drop_replication_slot('%s');\n",
			StandbySlot, err, brand.CLI, StandbySlot)
	}
	// No standby left to wait for. Clearing the setting is what keeps the
	// database writable; clearing the marker is honest, because `ha disable` is
	// somebody saying they do not want a second copy at all.
	if SyncOn() || SyncActive() {
		if err := SyncDisable(); err != nil {
			return fmt.Errorf("the standby is gone but commits are still waiting for it: %w\n"+
				"Clear it by hand: ALTER SYSTEM RESET synchronous_standby_names; SELECT pg_reload_conf();", err)
		}
	}
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
		removeContainer(container("main"))
		return fmt.Errorf("failback stopped: %w\n'main' is still served by the standby and nothing was lost; fix the problem and run `fox ha failback` again", cause)
	}
	// After the standby is stopped, but before main is promoted: start it again.
	restart := func(cause error) error {
		removeContainer(container("main"))
		if run("docker", "start", standby) == nil {
			_ = waitReady("standby")
		}
		return stopped(cause)
	}

	fmt.Println("1/5 copying the promoted standby into main…")
	if err := allowReplication(standby); err != nil {
		return stopped(err)
	}
	removeContainer(container("main"))
	// Only the contents are replaced: branches are copy-on-write clones of main's
	// snapshots, so its dataset stays.
	if err := run("rm", "-rf", mountpoint("main")+"/pgdata"); err != nil {
		return stopped(err)
	}
	if err := run("chown", "-R", pgUID+":"+pgUID, mountpoint("main")); err != nil {
		return stopped(err)
	}
	// No replication slot for this one. main is about to run as a temporary
	// standby of the promoted standby, started by startContainer, which does
	// not name a slot — so one made here would reserve WAL that nothing reads.
	// A failback is minutes long and ends with main as a primary again; the new
	// standby that `ha enable` then builds gets the slot.
	if err := run("docker", append([]string{"run", "--rm", "--user", pgUID, "--network", network,
		"--env-file", replicaEnvFile(),
		"-v", mountpoint("main") + ":/data",
		pgImage()},
		baseBackupArgs(standby, "/data/pgdata", standbySlotWanted())...)...); err != nil {
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
	if err := run("docker", "exec", "--env-file", pgEnvFile(), container("main"),
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
	removeContainer(standby)
	store.destroyStandby()
	// main is a primary again with no standby, so nothing may be waiting for
	// one. The marker stays: `ha enable` below puts the mode back.
	if SyncActive() {
		if err := clearSyncOnPrimary(); err != nil {
			fmt.Printf("\nWARNING: 'main' is still waiting for a standby that has been removed (%v).\n"+
				"Writes will not complete until this is cleared:\n  %s ha sync off\n\n", err, brand.CLI)
		}
	}

	fmt.Println("failback complete: 'main' is served by its own container again, with every write made during the failover.")
	fmt.Println("  WAL archiving has resumed. Take a fresh base backup now: fox backup create")
	fmt.Println("  (point-in-time restore can't reach the time 'main' ran on the standby, which didn't archive WAL).")
	fmt.Println("  Run `fox ha enable` for a new standby.")
	return nil
}

// haQuery runs a single-value query on a container, returning "" on any error.
func haQuery(c, sql string) string {
	out, _ := capture("docker", "exec", "--env-file", pgEnvFile(), c,
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
