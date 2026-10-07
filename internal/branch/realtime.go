// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// Whether this install runs its databases ready for a change feed, and what
// that costs when it does.
//
// This half is free and in the core on purpose. It decides how a container is
// started, which is the core's job; the feed itself — decoding, fan-out, the
// wire format — is the paid half in enterprise/realtime. The split is the same
// one the rest of the editions follow: the engine runs the database, the paid
// code does the thing you bought.

// realtimeMarker records that someone opted in. A file rather than a setting on
// a branch, because it governs how *every* container is started and has to be
// readable before any database is running.
//
// A variable so a test can point it somewhere harmless. brand.StateDir is
// resolved once per process and cached, so setting HOME in a test does not move
// it — which made the first version of realtime_test.go write the marker into
// whichever directory happened to win the race, and pass or fail by test order.
var realtimeMarker = func() string { return brand.StatePath("realtime") }

// RealtimeOn reports whether this install starts its databases with logical
// decoding available.
//
// Off unless somebody asked. A Standard install should not pay extra WAL volume
// for a feature it does not have, and an existing install must not have its
// databases restarted by a routine upgrade — `fox realtime setup` is the one
// way in, and it says what it will do first.
func RealtimeOn() bool {
	_, err := os.Stat(realtimeMarker())
	return err == nil
}

// SetRealtimeOn records the choice. It does not restart anything: the caller
// says what is about to happen and does it, because a function that silently
// bounced every database would be the wrong place to decide that.
func SetRealtimeOn(on bool) error {
	if !on {
		if err := os.Remove(realtimeMarker()); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(realtimeMarker()), 0o700); err != nil {
		return err
	}
	return os.WriteFile(realtimeMarker(), []byte("on\n"), 0o600)
}

// WALKeepSize is how much WAL a branch may hold for a subscriber that has
// stopped reading.
//
// This setting is the whole reason durable replay is safe here. A replication
// slot with nobody draining it pins WAL forever, and on a pool shared with
// `main` that is how a closed laptop takes a database read-only. Past this
// budget Postgres invalidates the slot instead of holding more: the subscriber
// is told to resync, which is a worse answer than replay and a far better one
// than a full disk.
//
// Tunable, because the right number depends on how much the database writes and
// how long a subscriber may reasonably be away — but only through this variable
// and `fox realtime setup`. The engine passes the setting on Postgres's command
// line, and a command-line setting takes precedence over ALTER SYSTEM: an
// operator who reaches for ALTER SYSTEM will have it accepted and then silently
// ignored.
func WALKeepSize() string {
	if v := strings.TrimSpace(brand.Getenv("REALTIME_WAL_KEEP")); v != "" {
		return v
	}
	return "1GB"
}

// SlotPrefix is how a feed's replication slots are named, so they can be found
// and swept without a record of them. `fox_rt_<branch>_<subscription>`.
const SlotPrefix = "fox_rt_"

// SlotName is the slot for one subscription on one branch.
func SlotName(branchName, subscription string) string {
	return SlotPrefix + sanitiseSlotPart(branchName) + "_" + sanitiseSlotPart(subscription)
}

// Postgres slot names allow lower-case letters, digits and underscore, and no
// more than 63 bytes. Branch and subscription names are checked elsewhere, so
// this is the last line rather than the only one.
func sanitiseSlotPart(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if len(out) > 24 {
		out = out[:24]
	}
	return out
}

// ServingBranch is the branch whose container actually answers for a name.
//
// Everything in this file reaches Postgres by container name, and after
// `fox ha failover` the container serving "main" is the promoted standby while
// pg-main is stopped. RealtimeDSN already resolved this by address, and these
// did not — so a feed on "main" after a failover could not be read at all: the
// decoder's first step execs into a container that is not running, fails, and
// retries until it gives up, with nothing on the stream to say why. A failover
// is exactly the situation nobody wants to be debugging a change feed in.
//
// A variable for the lookup, so a test can say where "main" is without writing
// to the state directory brand resolves once per process.
var servingPrimary = primaryBranch

func ServingBranch(name string) string {
	if name == "" || name == "main" {
		return servingPrimary()
	}
	return name
}

// RealtimeActive reports whether any subscriber is currently attached to a
// branch, asked of Postgres rather than of this process.
//
// The reaper that suspends idle branches runs in the gateway and a decoder runs
// in the control plane, so process-local state would be useless — a branch
// would be suspended out from under its subscribers. Postgres is the one thing
// both can see.
func RealtimeActive(name string) (bool, error) {
	lines, err := LedgerQuery(ServingBranch(name), `SELECT EXISTS (SELECT 1 FROM pg_replication_slots
	  WHERE slot_name LIKE '`+SlotPrefix+`%' AND active)`)
	if err != nil {
		return false, err
	}
	return len(lines) > 0 && strings.HasPrefix(strings.ToLower(lines[0]), "t"), nil
}

// RealtimeSlot is one replication slot the feed owns.
type RealtimeSlot struct {
	Name     string `json:"name"`
	Branch   string `json:"branch"`
	Active   bool   `json:"active"`
	WALBytes int64  `json:"wal_bytes"` // held for this slot, and so unreclaimable
	// Status is Postgres's own: reserved, extended, unreserved, or lost. `lost`
	// means the slot fell further behind than max_slot_wal_keep_size allows and
	// Postgres invalidated it rather than hold more — the budget doing its job.
	// A lost slot can never be resumed from.
	Status string `json:"status"`
}

// Lost reports whether this slot is past saving, so a subscriber must refetch
// rather than resume.
func (s RealtimeSlot) Lost() bool { return s.Status == "lost" }

// RealtimeSlots lists the feed's slots on a branch, with how much WAL each is
// holding. `fox realtime slots` prints it and `fox check` warns on it: a slot
// nobody is draining is the one failure of this design that costs disk.
func RealtimeSlots(name string) ([]RealtimeSlot, error) {
	lines, err := LedgerQuery(ServingBranch(name), `SELECT slot_name || '|' || active::text || '|' ||
	    coalesce(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)::bigint, 0)::text
	    || '|' || coalesce(wal_status, '')
	  FROM pg_replication_slots WHERE slot_name LIKE '`+SlotPrefix+`%' ORDER BY slot_name`)
	if err != nil {
		return nil, err
	}
	out := make([]RealtimeSlot, 0, len(lines))
	for _, l := range lines {
		parts := strings.Split(l, "|")
		if len(parts) < 4 {
			continue
		}
		n, _ := strconv.ParseInt(parts[2], 10, 64)
		out = append(out, RealtimeSlot{
			Name:     parts[0],
			Branch:   name,
			Active:   strings.HasPrefix(strings.ToLower(parts[1]), "t"),
			WALBytes: n,
			Status:   parts[3],
		})
	}
	return out, nil
}

// DropRealtimeSlot removes one slot by name. An active slot is refused by
// Postgres, which is the right answer: dropping one out from under a live
// subscriber would lose its place silently.
func DropRealtimeSlot(name, slot string) error {
	if !strings.HasPrefix(slot, SlotPrefix) {
		return fmt.Errorf("%w: %q is not one of the change feed's slots", ErrInvalidRequest, slot)
	}
	_, err := LedgerQuery(ServingBranch(name), "SELECT pg_drop_replication_slot("+QuoteLiteral(slot)+")")
	return err
}

// RealtimeHAGuard refuses a setup or teardown while a promoted standby is
// serving main.
//
// Both restart `main`, and after a failover `main` is the standby — restarting
// it with different settings is not a 15-second blip but the only copy of the
// data going down and coming back changed. `fox ha failback` first, which is
// the same answer haGuard gives for every other action that touches the
// primary.
func RealtimeHAGuard(action string) error {
	if ServingBranch("main") != "standby" {
		return nil
	}
	return fmt.Errorf("refusing `%s realtime %s`: 'main' is being served by the promoted standby "+
		"since `%s ha failover`, and this restarts it.\nRun `%s ha failback` first",
		brand.CLI, action, brand.CLI, brand.CLI)
}

// RestartPrimary stops and starts main so it picks up a changed command line.
//
// Deliberately the whole container rather than a reload: wal_level and
// max_slot_wal_keep_size are not reloadable settings, and a reload that
// appeared to work while changing nothing would be the worst outcome — the feed
// would be "on" and silently undecodable.
func RestartPrimary() error {
	name := primaryBranch()
	if err := startContainer(name, true); err != nil {
		return err
	}
	return waitReady(name)
}

// DropRealtimeObjects removes every publication and replication slot the feed
// made, on every branch that has one.
//
// Run before turning the feed off, because a slot outlives the setting: one
// left behind holds WAL that nothing will ever read, and on a shared pool that
// is how the disk fills. Best-effort per branch — a branch that is down cannot
// be cleaned now and is swept by SweepRealtimeSlots when it next starts.
func DropRealtimeObjects() error {
	names, err := RunningBranches()
	if err != nil {
		return err
	}
	var failed []string
	for _, n := range names {
		slots, err := RealtimeSlots(n)
		if err != nil {
			failed = append(failed, n+" (not reachable)")
			continue
		}
		for _, s := range slots {
			if err := DropRealtimeSlot(n, s.Name); err != nil {
				why := "could not be dropped"
				if s.Active {
					why = "a subscriber is still attached"
				}
				failed = append(failed, fmt.Sprintf("%s on %s: %s", s.Name, n, why))
			}
		}
		if _, err := LedgerQuery(n, `DO $$ DECLARE p record; BEGIN
		  FOR p IN SELECT pubname FROM pg_publication WHERE pubname LIKE '`+PublicationPrefix+`%' LOOP
		    EXECUTE format('DROP PUBLICATION %I', p.pubname);
		  END LOOP; END $$`); err != nil {
			failed = append(failed, n+"/publications")
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("could not clean up on: %s", strings.Join(failed, ", "))
	}
	return nil
}

// SweepRealtimeSlots drops the feed's slots that can never be used again.
//
// Only the lost ones. An earlier version dropped every slot nobody was
// currently holding, which was wrong in a way that quietly removed the feature
// this design was chosen for: a durable slot is exactly what a subscriber
// resumes from, and Up() runs on every engine start, so a restart between a
// disconnect and a reconnect threw the subscriber's position away. There was
// nothing to see — the next connection simply started from "now", with a silent
// gap where the missed changes should have been.
//
// An idle slot does not need sweeping, because max_slot_wal_keep_size already
// bounds what it can cost: past that budget Postgres invalidates it and marks
// it lost, and *that* is the slot worth dropping — it holds a catalog entry and
// can never be resumed from.
func SweepRealtimeSlots() {
	if !RealtimeOn() {
		return
	}
	names, err := RunningBranches()
	if err != nil {
		return
	}
	for _, n := range names {
		slots, err := RealtimeSlots(n)
		if err != nil {
			continue
		}
		for _, s := range slots {
			if s.Active || !s.Lost() {
				continue
			}
			if err := DropRealtimeSlot(n, s.Name); err != nil {
				log.Printf("change feed: could not drop the lost slot %s on %s: %v", s.Name, n, err)
			} else {
				log.Printf("change feed: dropped %s on %s — it had fallen further behind than %s allows",
					s.Name, n, WALKeepSize())
			}
		}
	}
}

// RealtimeRole is the role a decoder connects as.
const RealtimeRole = "db_realtime"

// EnsureRealtimeRole creates the role a change feed decodes with.
//
// LOGIN REPLICATION, and nothing else: no table grants, and deliberately *not*
// a member of db_client. It can open a replication connection and decode the
// write-ahead log, and it cannot run a query — so a leaked decoder credential
// reads the tables somebody explicitly published and nothing more. NOBYPASSRLS
// for the same reason db_client has it, even though the preflight already
// refuses an RLS table: two independent reasons a policy cannot be sidestepped
// are better than one.
func EnsureRealtimeRole(name, password string) error {
	return ExecSQL(ServingBranch(name), fmt.Sprintf(`DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %s) THEN
    EXECUTE format('CREATE ROLE %%I LOGIN REPLICATION NOSUPERUSER NOBYPASSRLS NOINHERIT', %s);
  END IF;
  EXECUTE format('ALTER ROLE %%I PASSWORD %%L', %s, %s);
END $$`, QuoteLiteral(RealtimeRole), QuoteLiteral(RealtimeRole),
		QuoteLiteral(RealtimeRole), QuoteLiteral(password)))
}

// RealtimeRolePassword is the decode role's password, derived from the install
// secret like every other role's — so it is never stored, and a decoder on this
// machine can always work it out while nothing off it can.
func RealtimeRolePassword() string { return rolePassword("realtime", RealtimeRole) }

// PublicationPrefix is what every one of the feed's publications starts with.
const PublicationPrefix = SlotPrefix + "pub"

// PublicationFor is the publication that carries a given set of events.
//
// One per event set, not one per feed, because Postgres's `publish` option is a
// property of the *publication* rather than of a table in it. A single
// publication would mean the first table anyone enabled silently decided which
// events every later table got — which is exactly what happened the first time
// the integration suite ran: a table enabled with --events=insert made the next
// table's updates and deletes disappear, with nothing to show for it.
func PublicationFor(events []string) string {
	sorted := append([]string(nil), events...)
	sort.Strings(sorted)
	return PublicationPrefix + "_" + strings.Join(sorted, "_")
}

// Publications lists the feed's publications on a branch, for a decoder that
// has to subscribe to all of them.
func Publications(name string) ([]string, error) {
	return LedgerQuery(ServingBranch(name), `SELECT pubname FROM pg_publication
	  WHERE pubname LIKE '`+PublicationPrefix+`%' ORDER BY pubname`)
}

// RealtimeDSN is how a decoder reaches a branch: the replication connection
// string, as the decode role.
//
// replication=database is what makes it a *logical* connection. The
// `replication` lines in pg_hba match only physical replication, so this falls
// through to the ordinary host line and authenticates with a password like any
// other client — checked against a live database before the feed was designed,
// because the alternative was widening pg_hba, which nobody wants to do.
func RealtimeDSN(name, password string) (string, error) {
	// BackendAddr, not the container's name: the control plane runs as a
	// process on the host, where a docker container name does not resolve. It
	// also knows that after a failover `main` is the promoted standby, which a
	// name built from the branch would get wrong in exactly the situation
	// nobody wants to debug.
	addr, err := BackendAddr(name)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("postgres://%s:%s@%s/%s?replication=database&sslmode=disable",
		RealtimeRole, url.QueryEscape(password), addr, pgDatabase), nil
}

// PublishedTables is what a branch's feed currently carries.
func PublishedTables(name string) ([]string, error) {
	return LedgerQuery(ServingBranch(name), `SELECT DISTINCT schemaname || '.' || tablename FROM pg_publication_tables
	  WHERE pubname LIKE '`+PublicationPrefix+`%' ORDER BY 1`)
}
