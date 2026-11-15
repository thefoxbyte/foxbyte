// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// A failover drill: end the primary without warning, recover, and report what
// it cost in writes and in seconds.
//
// Phase 6 of docs/FOX_HA_Plan.md, where the drill is the deliverable rather
// than the standby: "we fail over in about a minute" is a claim, and a dated
// report from a real failover is evidence. Section 5 of that plan says not to
// quote RPO and RTO figures until something measures them, which is this.
//
// Three things make it a drill rather than a demonstration.
//
// It kills the primary rather than stopping it. `docker stop` sends SIGTERM,
// Postgres does a fast shutdown, and a fast shutdown flushes its remaining WAL
// to the standby before it exits — so a stopped primary loses nothing and the
// number would be a flattering fiction. A machine that dies does not say
// goodbye, so the drill sends SIGKILL.
//
// It kills it with writes in flight. A drill run against an idle database
// measures an idle database.
//
// And it recovers through the real path: the measured time is HAFailover, the
// same function `fox ha failover` calls, not a promotion written for the test.

// DrillResult is one drill. The report is rendered from it, so the rendering is
// a pure function of the measurement and can be read in a test.
type DrillResult struct {
	At     time.Time `json:"at"`
	Writes int       `json:"writes"` // rows the drill tried to write

	// Acked is the highest row the server told the client was committed, and
	// Survived the highest of those that was on the promoted standby. The gap
	// is the only honest definition of data loss: a write the client was told
	// had happened, which then had not.
	Acked    int64 `json:"acked"`
	Survived int64 `json:"survived"`
	LostRows int64 `json:"lost_rows"`

	// WritesPerSecond turns rows into seconds, because "11 rows" means nothing
	// without the rate that produced them.
	WritesPerSecond float64 `json:"writes_per_second"`

	// TimeToService is from the kill to a write succeeding on the new primary.
	// It does not include noticing the failure or deciding to act: both are a
	// person today, which is what phase 3 is for, and a drill that pretended
	// otherwise would be the fiction this exists to replace.
	TimeToService time.Duration `json:"time_to_service"`

	// The configuration that produced the numbers. A drill measures one sample;
	// the configuration is what may be promised, and the two are reported side
	// by side so nobody quotes the sample.
	SyncMode       bool   `json:"sync_mode"`
	ArchiveTimeout int    `json:"archive_timeout_seconds"`
	Target         string `json:"target"`
	TargetRemote   bool   `json:"target_remote"`
	PGMajor        string `json:"pg_major"`

	// The topology this drill actually ran in, and who noticed the failure.
	//
	// These exist because the report used to disclaim three things in every
	// copy of it — losing a machine, noticing, and a second site — and after
	// phases 1, 3 and 7 all three can be true instead. A report that goes on
	// saying "there is only one site" when there were two is as misleading as
	// one that claims a site it did not have, and the second kind of mistake
	// is the only one anybody checks for.
	Topology  string `json:"topology"`  // "one host" | "two machines"
	Detection string `json:"detection"` // "manual" | "automatic"

	// Takeover marks a drill measured from the surviving machine rather than
	// from the one that was killed. It changes what can be measured at all:
	// RTO then includes noticing, and RPO cannot be measured from this side
	// because the writer was on the machine that went away.
	Takeover bool `json:"takeover"`

	// LastReceived is how far the copy had got when the primary stopped
	// answering — the only thing a surviving machine can say about what it
	// might be missing.
	LastReceived string `json:"last_received_lsn,omitempty"`

	// Primary is the address that went away, for a takeover drill.
	Primary string `json:"primary,omitempty"`

	// Notes carries anything that happened during the drill that the numbers do
	// not show, so a report is never quietly incomplete.
	Notes []string `json:"notes,omitempty"`

	// Ran is whether the drill got as far as ending the primary. A drill
	// refused before it started — no standby, already failed over — has nothing
	// to report, and printing a document of zeroes for it would be worse than
	// printing the refusal.
	Ran bool `json:"ran"`
}

// Measured reports whether there is anything worth writing down.
func (r DrillResult) Measured() bool { return r.Ran }

// DrillOptions are the knobs. Writes defaults to 400, which at the rate one
// psql session sustains is a few seconds of traffic — long enough to have
// writes in flight at the moment of the kill.
type DrillOptions struct {
	Writes   int
	Failback bool
	// Takeover measures from the surviving machine instead (DrillTakeover).
	Takeover bool
	// Wait is how long a takeover drill waits for each step: for the primary
	// to stop answering, and then for this machine to serve writes. It is a
	// person pulling a plug on one side and a watcher deciding on the other,
	// so the default is generous.
	Wait time.Duration
}

// archiveTimeoutSeconds is how often the primary closes a WAL segment and ships
// it, and so the most a lost machine can cost once the archive is somewhere that
// machine's failure cannot reach. One constant because the drill report quotes
// it as the bound a buyer may be promised, and a report that disagreed with the
// setting would be worse than no report.
const archiveTimeoutSeconds = 60

// drillSchema is where the drill writes. A schema of its own rather than a
// table in public: it is obviously ours, it cannot collide with anything, and
// it goes away in one statement afterwards.
const drillSchema = "fox_drill"

// What a drill can have been, named rather than spelled out at each use.
const (
	TopologyOneHost     = "one host"
	TopologyTwoMachines = "two machines"
	DetectionManual     = "manual"
	DetectionAutomatic  = "automatic"
)

// drillTopology reports whether the copy this install would promote is on this
// machine or another one.
//
// Read from the join record rather than from pg_stat_replication's client_addr:
// the record is what `node join` wrote and `ha failover` clears, so it is the
// same fact every other guard in the engine acts on. A drill that disagreed
// with the fence about where the primary is would be describing a different
// install.
func drillTopology() string {
	if IsStandbyNode() {
		return TopologyTwoMachines
	}
	return TopologyOneHost
}

// promotedByWatcher reports whether the last promotion was made by `ha watch`
// rather than by a person, by asking the security log — which is where the
// watcher records it, and which phase 2 deliberately keeps on each node so the
// machine that took over can still be asked.
func promotedByWatcher(since time.Time) bool {
	s, err := auth.OpenFromEnv()
	if err != nil {
		return false
	}
	defer s.Close()
	return s.HasRecentEvent(auth.EvFailoverPromoted, since)
}

// watcherRecordWait is how long a takeover drill waits for `ha watch` to record
// a promotion it has already seen take effect.
//
// The watcher writes its record when HAFailover returns, and HAFailover goes on
// for seconds after the copy starts taking writes: it rewrites the copy's role
// passwords and resets zero-data-loss mode. The drill sees the copy serving in
// that window, and asking the log there and then found nothing, and credited a
// person with the watcher's promotion (integration §6b failed so, about one
// run in two). A person's own `ha failover` records nothing, so the only way to
// tell is to give the watcher's record time to arrive.
var watcherRecordWait = 30 * time.Second

// waitForWatcher asks check until it answers yes or wait has passed.
func waitForWatcher(check func() bool, wait, every time.Duration) bool {
	deadline := time.Now().Add(wait)
	for {
		if check() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(every)
	}
}

// Drill runs one. It is destructive of service and not of data: the primary is
// killed and the standby promoted, which is what `fox ha failover` does on
// purpose, and every write the standby received survives.
func Drill(o DrillOptions) (DrillResult, error) {
	r := DrillResult{At: time.Now().UTC(), Writes: o.Writes}
	if r.Writes <= 0 {
		r.Writes = 400
	}
	if err := drillReady(); err != nil {
		return r, err
	}
	// A local drill kills this machine's primary and promotes the copy beside
	// it. On a machine that follows a primary elsewhere there is no local
	// primary to kill — its own `main` is idle — and the copy here is the one
	// the *other* machine would lose. Refused rather than attempted, because
	// what it would actually measure is nothing and what it would report is a
	// failure that is not one. The site drill is run from here instead, and it
	// is the other machine that stops.
	if IsStandbyNode() {
		j, _ := CurrentJoin()
		return r, fmt.Errorf("this machine follows the primary at %s:%d, so there is no primary here to "+
			"end — a site failover is measured from the surviving machine: stop %s and run "+
			"`%s ha drill --takeover` here", j.Address, j.Port, j.Address, brand.CLI)
	}
	primary := PrimaryContainer()
	r.Topology, r.Detection = drillTopology(), DetectionManual
	r.SyncMode = SyncActive()
	r.ArchiveTimeout = archiveTimeoutSeconds
	r.PGMajor = imageMajor(pgImage())
	if t, err := CurrentTarget(); err == nil {
		r.Target, r.TargetRemote = t.Describe(), t.Remote()
	}

	if err := drillPrepare(primary); err != nil {
		return r, err
	}

	// Writes in flight, then the machine dies under them. From here there has
	// been an outage, so whatever happens next is worth a report.
	r.Ran = true
	acked, rate, killedAt, err := drillWriteUntilKilled(primary, r.Writes)
	r.Acked, r.WritesPerSecond = acked, rate
	if err != nil {
		r.Notes = append(r.Notes, "the writer stopped early: "+err.Error())
	}
	if acked == 0 {
		return r, fmt.Errorf("the drill could not write anything to %s, so there is nothing to measure", primary)
	}

	// Recovery, through the command an operator would run.
	// The drill killed the local primary itself, so there is nothing left to
	// fence and nothing to force past.
	if err := HAFailover(false); err != nil {
		return r, fmt.Errorf("the drill killed the primary and the failover failed: %w\n"+
			"The install is mid-failover; `%s ha status` says where it is", err, brand.CLI)
	}
	now := PrimaryContainer()
	if err := pollUntil("the promoted standby to accept a write", 2*time.Minute, func() bool {
		return drillWrite(now, -1) == nil
	}); err != nil {
		return r, err
	}
	r.TimeToService = time.Since(killedAt)

	// What arrived before the machine died.
	r.Survived = drillHighest(now)
	r.LostRows = r.Acked - r.Survived
	if r.LostRows < 0 {
		// The standby had rows the client was never told about: a commit that
		// reached the standby and whose acknowledgement never reached the
		// client. Not data loss — the opposite — but worth saying rather than
		// reporting a negative.
		r.Notes = append(r.Notes, fmt.Sprintf(
			"the promoted standby held %d row(s) beyond the last one acknowledged to the client, "+
				"which is a commit that arrived but whose reply did not", -r.LostRows))
		r.LostRows = 0
	}
	drillCleanup(now)

	if o.Failback {
		start := time.Now()
		if err := HAFailback(); err != nil {
			r.Notes = append(r.Notes, "the failback failed: "+err.Error())
		} else {
			r.Notes = append(r.Notes, fmt.Sprintf("returned to normal running in %s, and the standby "+
				"has to be rebuilt with `%s ha enable`", time.Since(start).Round(time.Second), brand.CLI))
		}
	}
	return r, nil
}

// drillReady refuses a drill that could not measure anything, before it kills
// anything.
// DrillTakeover measures a site failover from the machine that survives it.
//
// The local drill (Drill) kills the primary itself and measures from the kill,
// which is the only thing one machine can do and which deliberately excludes
// noticing. Across machines neither of those holds: the primary is somebody
// else's process, so this waits for it to stop answering, and the clock
// therefore includes detection — which is the number phase 3 exists to make
// small, and the number a buyer actually experiences.
//
// What it cannot measure is RPO. The writer was on the machine that went away,
// so nothing here knows what that machine acknowledged to a client in its last
// moments; the report says so rather than printing a zero that would read as a
// guarantee. The last WAL position this copy received is reported instead,
// because it is the one true thing a survivor can say about what it might be
// missing.
func DrillTakeover(o DrillOptions) (DrillResult, error) {
	r := DrillResult{At: time.Now().UTC(), Takeover: true, Detection: DetectionManual}
	j, ok := CurrentJoin()
	if !ok {
		return r, fmt.Errorf("this machine is not following a primary, so there is no takeover to "+
			"measure — `%s ha drill` measures a failover between containers on one host, and "+
			"`--takeover` measures one between machines, run from the survivor", brand.CLI)
	}
	if ContainerState("standby") != "running" {
		return r, fmt.Errorf("this machine has no running copy to take over with — `%s ha status` says "+
			"what it is doing", brand.CLI)
	}
	r.Topology, r.Primary = TopologyTwoMachines, fmt.Sprintf("%s:%d", j.Address, j.Port)
	r.ArchiveTimeout = archiveTimeoutSeconds
	r.PGMajor = imageMajor(pgImage())
	r.SyncMode = SyncOn()
	if t, err := CurrentTarget(); err == nil {
		r.Target, r.TargetRemote = t.Describe(), t.Remote()
	}

	cont := container("standby")
	fmt.Printf("watching %s. Stop it now — pull its power, or `%s stop` there — and this will\n",
		r.Primary, brand.CLI)
	fmt.Printf("measure what the takeover costs from this side.\n\n")
	if err := pollUntil(fmt.Sprintf("%s to stop answering", r.Primary), o.Wait, func() bool {
		return !RemotePrimaryAnswering(j, 3*time.Second)
	}); err != nil {
		return r, fmt.Errorf("%w — nothing was measured and nothing was changed", err)
	}
	downAt := time.Now()
	// Read before the promotion, because promoting ends recovery and with it
	// the view that can answer this.
	r.LastReceived = haQuery(cont, "SELECT coalesce(pg_last_wal_receive_lsn()::text, '')")
	r.Ran = true
	fmt.Printf("%s stopped answering. Waiting for this machine to serve writes …\n", r.Primary)

	// Whoever promotes it: `ha watch` if it is running, or a person. This only
	// measures; a drill that promoted the copy itself would be measuring its
	// own call and not the recovery anybody will have.
	if err := pollUntil("this machine to accept a write", o.Wait, func() bool {
		return !IsStandbyNode() && drillServing(PrimaryContainer())
	}); err != nil {
		r.Notes = append(r.Notes, "nothing promoted this machine: "+err.Error())
		return r, fmt.Errorf("%w\nIt is still a copy. `%s ha watch --witness <url> --accept-unfenced` promotes it "+
			"unattended, or `%s ha failover` by hand", err, brand.CLI, brand.CLI)
	}
	r.TimeToService = time.Since(downAt)
	// After the clock: waiting for the watcher's record is not time a client
	// waited.
	fmt.Println("serving. Checking whether `" + brand.CLI + " ha watch` recorded the promotion …")
	if waitForWatcher(func() bool { return promotedByWatcher(downAt) }, watcherRecordWait, 500*time.Millisecond) {
		r.Detection = DetectionAutomatic
	}
	// No Survived and no LostRows: the writer was on the machine that went
	// away, so the rows in this table are the drill's own and comparing them to
	// anything would be inventing a figure. The report says so where a number
	// would otherwise be.
	drillCleanup(PrimaryContainer())
	return r, nil
}

// drillServing reports whether this machine's primary is out of recovery and
// takes a write.
//
// It prepares the drill's schema here rather than up front, which the local
// drill can do and this cannot: until the promotion the copy is in recovery and
// refuses every write, including the CREATE that would prepare it. So the
// preparation is part of the question — and a machine that cannot be prepared
// is not serving, which is the answer either way.
func drillServing(cont string) bool {
	if haQuery(cont, "SELECT pg_is_in_recovery()") != "f" {
		return false
	}
	if err := drillPrepare(cont); err != nil {
		return false
	}
	return drillWrite(cont, -1) == nil
}

func drillReady() error {
	if ContainerState("standby") == "absent" {
		return fmt.Errorf("a drill needs a standby to fail over to, and this install has none.\n"+
			"Run `%s ha enable` first", brand.CLI)
	}
	if PrimaryContainer() == container("standby") {
		return fmt.Errorf("'main' is already being served by the promoted standby since `%s ha failover`.\n"+
			"Run `%s ha failback` first, so the drill has somewhere to fail over to", brand.CLI, brand.CLI)
	}
	if !HAInfo().Streaming {
		return fmt.Errorf("the standby is not streaming, so a drill would measure a failover to a stale copy.\n"+
			"Check `%s ha status` and run the drill once it is caught up", brand.CLI)
	}
	return nil
}

func drillPrepare(primary string) error {
	// Created, never dropped, and emptied with a WHERE clause.
	//
	// The engine's own guardrails refuse DROP TABLE and unqualified DML by
	// default — the two that stay free in every edition — and they refused this
	// when it was written as a DROP, which is the guardrails working. A drill
	// does not get an exemption from the product's own rules, so preparing
	// needs none: the one place that overrides anything is the cleanup at the
	// end, and it says so.
	out, err := captureCombined("docker", "exec", "--env-file", pgEnvFile(), primary,
		"psql", "-U", pgUser, "-d", pgDatabase, "-tAq", "-v", "ON_ERROR_STOP=1",
		"-c", "CREATE SCHEMA IF NOT EXISTS "+drillSchema,
		"-c", "CREATE TABLE IF NOT EXISTS "+drillSchema+".log (id bigint primary key, at timestamptz default now())",
		"-c", "DELETE FROM "+drillSchema+".log WHERE id IS NOT NULL")
	if err != nil {
		return fmt.Errorf("preparing the drill table: %w\n%s", err, strings.TrimSpace(out))
	}
	return nil
}

// drillWriteUntilKilled writes one row per transaction through a single session,
// reads back what the server acknowledged, and kills the primary part way
// through so that writes are in flight when it dies.
//
// One session fed statement by statement rather than a batch: the point is the
// client's own view of what was committed, and a batch would only tell us about
// the last one. It returns the highest acknowledged row, the rate it managed,
// and the instant the kill was sent — which is where the clock for recovery
// starts.
func drillWriteUntilKilled(primary string, writes int) (int64, float64, time.Time, error) {
	cmd, _, cancel := sudoCmd(execLong, "docker", "exec", "-i", "--env-file", pgEnvFile(), primary,
		"psql", "-U", pgUser, "-d", pgDatabase, "-tAq", "-v", "ON_ERROR_STOP=1")
	defer cancel()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return 0, 0, time.Now(), err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, 0, time.Now(), err
	}
	if err := cmd.Start(); err != nil {
		return 0, 0, time.Now(), err
	}
	defer func() { _ = cmd.Wait() }()

	// Killed at the half-way mark, so the second half is what the failure
	// interrupts.
	killAfter := writes / 2
	var acked int64
	killedAt := time.Time{}
	start := time.Now()
	lines := bufio.NewScanner(stdout)
	for i := 1; i <= writes; i++ {
		if _, err := fmt.Fprintf(stdin, "INSERT INTO %s.log (id) VALUES (%d) RETURNING %d;\n",
			drillSchema, i, i); err != nil {
			break // the session is gone, which after the kill is expected
		}
		if !lines.Scan() {
			break
		}
		if strings.TrimSpace(lines.Text()) != fmt.Sprint(i) {
			break
		}
		acked = int64(i)
		if i == killAfter {
			killedAt = time.Now()
			// SIGKILL: a machine that dies does not flush its WAL to the
			// standby on the way out, and `docker stop` would.
			quiet("docker", "kill", "-s", "KILL", primary)
		}
	}
	_ = stdin.Close()
	if killedAt.IsZero() {
		// Fewer writes got through than the half-way mark, so nothing has been
		// killed yet and the drill still has to end the primary.
		killedAt = time.Now()
		quiet("docker", "kill", "-s", "KILL", primary)
	}
	rate := 0.0
	if d := killedAt.Sub(start).Seconds(); d > 0 {
		rate = float64(acked) / d
	}
	return acked, rate, killedAt, nil
}

// drillWrite writes one row, and is how "is it serving again" is asked: a
// read would be answered by a standby still in recovery.
func drillWrite(server string, id int64) error {
	_, err := captureCombined("docker", "exec", "--env-file", pgEnvFile(), server,
		"psql", "-U", pgUser, "-d", pgDatabase, "-tAq", "-v", "ON_ERROR_STOP=1", "-c",
		fmt.Sprintf("INSERT INTO %s.log (id) VALUES (%d) ON CONFLICT DO NOTHING", drillSchema, id))
	return err
}

func drillHighest(server string) int64 {
	out, err := capture("docker", "exec", "--env-file", pgEnvFile(), server,
		"psql", "-U", pgUser, "-d", pgDatabase, "-tAc",
		"SELECT coalesce(max(id), 0) FROM "+drillSchema+".log WHERE id > 0")
	if err != nil {
		return 0
	}
	var n int64
	if _, err := fmt.Sscan(strings.TrimSpace(out), &n); err != nil {
		return 0
	}
	return n
}

// drillCleanup removes the schema the drill wrote, which needs the same
// override a person would use: dropping a table is one of the two things the
// Blackbox guardrails refuse by default, and a drill does not get an exemption
// from the product's own rules.
func drillCleanup(server string) {
	quiet("docker", "exec", "--env-file", pgEnvFile(), server,
		"psql", "-U", pgUser, "-d", pgDatabase, "-tAq", "-c",
		"SET bb.allow_destructive=on; DROP SCHEMA IF EXISTS "+drillSchema+" CASCADE")
}

// Report renders the drill as a dated document, which is the deliverable.
//
// Pure, so what it says can be read in a test rather than inferred from a run.
// The shape is deliberate: what was measured, then what may be promised, then
// what was not tested. The third section exists because the first is the one
// that gets quoted, and a single-machine drill is not evidence of surviving a
// site.
func (r DrillResult) Report() string {
	var b strings.Builder
	p := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }

	p("# Failover drill — %s\n\n", r.At.Format(time.RFC3339))
	if r.Takeover {
		p("A real site failover, measured from the machine that survived it: %s stopped\n", r.Primary)
		p("answering and this machine took over. Nothing here stopped it and nothing here\n")
		p("promoted itself — both are what the drill was watching for.\n\n")
	} else {
		p("A real failover: the primary was killed with SIGKILL half way through %d writes, with\n", r.Writes)
		p("more still arriving, and the standby was promoted through `%s ha failover`.\n\n", brand.CLI)
	}

	p("## Measured\n\n")
	p("| | |\n|---|---|\n")
	if r.Takeover {
		// No acknowledged-writes figure and no RPO: the writer was on the
		// machine that went away, so nothing here knows what it told a client
		// in its last moments. A "0" would read as a guarantee of none, which
		// is the one thing a survivor cannot know.
		p("| Unreachable to serving writes here (RTO) | **%s** |\n", r.TimeToService.Round(100*time.Millisecond))
		if r.Detection == DetectionAutomatic {
			p("| Who noticed | `%s ha watch`, with a witness agreeing |\n", brand.CLI)
		} else {
			p("| Who noticed | a person |\n")
		}
		p("| Last WAL position this copy had received | %s |\n", lsnOrUnknown(r.LastReceived))
		p("| Acknowledged writes lost (RPO) | **not measurable from this side** |\n")
		p("\nRTO above starts when the primary stopped answering, so it *includes* noticing —\n")
		p("unlike a drill run on one host, which starts at a kill it performed itself. This is\n")
		p("the number a client experiences.\n\n")
		p("RPO cannot be measured here and is not guessed at. The writer was on the machine\n")
		p("that went away; what it acknowledged in its last moments is known only to it and,\n")
		p("for whatever it managed to ship, to the archive. The WAL position above is the one\n")
		p("true thing this machine can say about what it might be missing.\n\n")
	} else {
		p("| Writes acknowledged to the client | %d, at %.0f/s |\n", r.Acked, r.WritesPerSecond)
		p("| Acknowledged writes lost (RPO) | **%d** |\n", r.LostRows)
		if r.LostRows > 0 && r.WritesPerSecond > 0 {
			p("| …which at that rate is | **%.1fs** of writes |\n",
				float64(r.LostRows)/r.WritesPerSecond)
		}
		p("| Kill to a write on the new primary (RTO) | **%s** |\n", r.TimeToService.Round(100*time.Millisecond))
		p("\nRTO above starts at the kill. It does not include noticing the failure or deciding\n")
		p("to fail over, both of which are a person today.\n\n")
	}

	p("## The configuration that produced those numbers\n\n")
	p("| | |\n|---|---|\n")
	if r.SyncMode {
		p("| Durability | zero-data-loss mode **on**: a commit waits for the standby |\n")
	} else {
		p("| Durability | asynchronous: commits never wait for the standby |\n")
	}
	p("| WAL archived at least every | %ds |\n", r.ArchiveTimeout)
	p("| Backups and WAL go to | %s |\n", r.Target)
	p("| PostgreSQL | %s |\n", r.PGMajor)
	p("\n")

	p("## What may be quoted\n\n")
	if r.Takeover {
		// A takeover measured one number and refused to invent the other, so
		// this section is about the one it has. The local drill's reasoning
		// about lost rows does not apply: there were no rows to lose here.
		p("**The time above, and it is the honest kind.** %s is from the primary going\n",
			r.TimeToService.Round(100*time.Millisecond))
		p("unreachable to this machine taking a write, so it already contains the part a\n")
		p("drill on one host leaves out: noticing. It is what a client waited.\n\n")
		if r.Detection == DetectionAutomatic {
			p("It also holds without anybody awake, which is the claim worth having: the\n")
			p("promotion was made by `%s ha watch` after a witness agreed the primary had gone.\n\n", brand.CLI)
		} else {
			p("A person noticed and promoted, so the number includes however long that took\n")
			p("this time and promises nothing about the next. `%s ha watch` with a witness is\n", brand.CLI)
			p("what makes it repeatable.\n\n")
		}
		if r.SyncMode {
			p("**RPO zero** may be quoted, but not because of this drill: zero-data-loss mode was\n")
			p("on, so a commit was never acknowledged until this copy had it. That is a property\n")
			p("of the configuration, and it is the only reason anything about loss can be said\n")
			p("from here at all.\n\n")
		} else {
			p("**Nothing about data loss.** Replication was asynchronous and the writer was on\n")
			p("the machine that went away. What it acknowledged in its last moments is not\n")
			p("knowable from here; the archive is the only other place those writes could be,\n")
			p("and WAL is shipped at least every %ds. `%s ha sync on` is what turns this into a\n",
				r.ArchiveTimeout, brand.CLI)
			p("guarantee of zero, at the cost of making every commit wait for the second machine.\n\n")
		}
	} else if r.SyncMode {
		p("**RPO zero**, and it is a property of the configuration rather than of this sample:\n")
		p("with zero-data-loss mode on, a commit is not acknowledged until the standby has it,\n")
		p("so there is no window in which an acknowledged write can be lost. The %d above is a\n", r.LostRows)
		p("confirmation, not the evidence.\n\n")
	} else if r.LostRows == 0 {
		// The dangerous result. Nothing was lost, and nothing about the
		// configuration promises that — on one host with a standby microseconds
		// behind it is the usual outcome, and it is the number somebody will
		// want to put in a tender.
		p("**Nothing, on the strength of this.** Nothing was lost, and asynchronous replication\n")
		p("does not promise that: the standby was simply keeping up at %.0f writes/s on a machine\n", r.WritesPerSecond)
		p("it shares with the primary. A busier primary, a slower link or a standby doing anything\n")
		p("else would all lose writes, and nothing in this configuration bounds how many.\n\n")
		p("What can be promised is the archive: WAL is shipped at least every %ds, so a lost\n", r.ArchiveTimeout)
		p("machine costs at most that much once the archive is somewhere the machine's failure\n")
		p("cannot reach. And `%s ha sync on` makes zero a guarantee rather than an observation,\n", brand.CLI)
		p("at the cost of making every commit wait for the standby.\n\n")
	} else {
		p("**Not the number above.** Asynchronous replication has no bound on how far the standby\n")
		p("may be behind, so %d lost row(s) is what this workload cost at %.0f writes/s on this\n", r.LostRows, r.WritesPerSecond)
		p("machine, and a busier primary or a slower link would lose more. What can be promised\n")
		p("is the archive: WAL is shipped at least every %ds, so a lost machine costs at most that\n", r.ArchiveTimeout)
		p("much once the archive is somewhere the machine's failure cannot reach.\n\n")
		p("`%s ha sync on` turns that number into a guarantee of zero, at the cost of making every\n", brand.CLI)
		p("commit wait for the standby.\n\n")
	}
	if !r.TargetRemote {
		p("**The archive is on this machine.** One disk or host failure takes the database and\n")
		p("every backup of it at the same time, so nothing above is a disaster-recovery figure\n")
		p("until `%s backup target set` points it somewhere else.\n\n", brand.CLI)
	}

	p("## What this drill did not test\n\n")
	left := 0
	if r.Topology != TopologyTwoMachines {
		left++
		p("- **Losing a machine.** The standby is a container on this host, sharing its disk and\n")
		p("  its power. This measures promotion and rerouting, not survival of the host.\n")
		p("- **A second site.** There is only one.\n")
	}
	if r.Detection != DetectionAutomatic {
		left++
		p("- **Noticing.** Detection and the decision to fail over were manual.\n")
	}
	switch {
	case left == 0:
		p("Nothing it set out to. The primary was on another machine, it was not stopped by\n")
		p("this drill, and nobody decided to fail over: `%s ha watch` noticed and a witness\n", brand.CLI)
		p("agreed. What is left is the part no drill can test — whether the witness is where\n")
		p("the clients are, which is why it is a placement an operator chooses rather than a\n")
		p("default.\n")
	case r.Topology == TopologyTwoMachines:
		p("\nAutomatic detection is what phase 3 of the HA plan is for: `%s ha watch` with a\n", brand.CLI)
		p("witness measures the same failover without anybody awake.\n")
	case r.Detection == DetectionAutomatic:
		p("\nSurviving a machine is what phase 1 of the HA plan is for: `%s node join` puts the\n", brand.CLI)
		p("copy on a second machine, and this same drill then measures a site failure.\n")
	default:
		p("\nThe first and third are what phase 1 of the HA plan is for, and the second phase 3.\n")
	}
	if len(r.Notes) > 0 {
		p("\n## Notes\n\n")
		for _, n := range r.Notes {
			p("- %s\n", n)
		}
	}
	return b.String()
}

// DrillReportDir is where reports are kept: in the state directory, beside the
// licence and the primary pointer, because a drill report is a record of the
// install rather than a document somebody happened to produce.
func DrillReportDir() string { return brand.StatePath("drills") }

// SaveDrillReport writes the report and returns where it went.
//
// Named for the instant the drill began rather than for when it finished, so a
// report sorts by the event it describes.
func SaveDrillReport(r DrillResult) (string, error) {
	dir := DrillReportDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, r.At.Format("20060102T150405Z")+".md")
	if err := os.WriteFile(path, []byte(r.Report()), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// lsnOrUnknown keeps an empty WAL position from printing as a blank cell in a
// report somebody is reading to decide something.
func lsnOrUnknown(lsn string) string {
	if strings.TrimSpace(lsn) == "" {
		return "could not be read"
	}
	return lsn
}
