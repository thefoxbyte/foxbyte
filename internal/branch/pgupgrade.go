// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"
)

// `fox pg upgrade` moves an install from the PostgreSQL major its data was
// created with to the one this fox ships (PGMajor), keeping every database, its
// roles, settings and Blackbox history.
//
// It dumps and reloads rather than running pg_upgrade. pg_upgrade needs both
// majors' binaries side by side, and the engine image carries one; its fast
// --link mode cannot cross the dataset boundary between branches; and it keeps
// indexes built under the old collation library. A reload rebuilds every index
// and needs nothing beyond the new image, whose pg_dump reads the old server.
//
// Nothing old is deleted. Every branch dataset moves, untouched, into a holding
// area outside the branch namespace (storage.stash), the carried branches are
// reloaded into new datasets, and the old ones stay until `--finalize`. So
// `--rollback` is a move back, and any failure while upgrading is undone the
// same way before the command returns.

// upgradeLot is the holding area for the datasets an upgrade from `from` left.
func upgradeLot(from string) string { return "pre-upgrade-pg" + from }

// UpgradePlan is everything checked before an upgrade moves anything.
type UpgradePlan struct {
	From, To     string            // installed major, and the one this fox ships
	All          []string          // every branch dataset
	Carry        []string          // branches reloaded on the new major
	Majors       map[string]string // each branch's data major
	HA           bool              // a standby exists
	FailedOver   bool              // the standby is serving main
	MainRunning  bool
	HeldLot      string            // a previous upgrade's holding area, still kept
	LedgerErrors map[string]string // carried branch -> why its Blackbox does not verify
	Notes        []PGNote
	Applies      map[string][]string // note ID -> branches its probe matched
	Used, Avail  string
}

// UpToDate reports an install already on the major this fox ships.
func (p UpgradePlan) UpToDate() bool { return p.From != "" && p.From == p.To }

// Refusals are the reasons not to start. Each says what to do instead.
func (p UpgradePlan) Refusals() []string {
	var r []string
	switch {
	case p.From == "":
		r = append(r, "no PostgreSQL data was found in main — there is nothing to upgrade")
	case majorNum(p.From) > majorNum(p.To):
		r = append(r, fmt.Sprintf("this install's data is PostgreSQL %s, newer than the %s this %s ships — update %s first", p.From, p.To, cliName(), cliName()))
	}
	if !p.MainRunning {
		r = append(r, fmt.Sprintf("main is not running — start the stack first (`%s start`)", cliName()))
	}
	if p.FailedOver {
		r = append(r, fmt.Sprintf("main is served by the HA standby since a failover — run `%s ha failback` first", cliName()))
	} else if p.HA {
		r = append(r, fmt.Sprintf("high availability is on — run `%s ha disable`, upgrade, then `%s ha enable` to rebuild the standby on the new major", cliName(), cliName()))
	}
	if p.HeldLot != "" {
		r = append(r, fmt.Sprintf("the databases kept by an earlier upgrade (%s) are still held — `%s pg upgrade --finalize` deletes them, `%s pg upgrade --rollback` returns to them", p.HeldLot, cliName(), cliName()))
	}
	var mixed []string
	for _, b := range p.All {
		if m := p.Majors[b]; m != "" && m != p.From {
			mixed = append(mixed, fmt.Sprintf("%s (%s)", b, m))
		}
	}
	if len(mixed) > 0 {
		r = append(r, fmt.Sprintf("these branches are on a different major from main (%s): %s — delete or restore them first", p.From, strings.Join(mixed, ", ")))
	}
	for _, b := range p.Carry {
		if e, bad := p.LedgerErrors[b]; bad {
			r = append(r, fmt.Sprintf("the Blackbox on %s does not verify (%s) — an upgrade would carry a broken chain into a new cluster, where the cause could never be traced", b, e))
		}
	}
	return r
}

// Render prints the plan: what moves, what changes for the user, and the
// PostgreSQL changes crossed, the ones found in their databases first.
func (p UpgradePlan) Render(w io.Writer) {
	fmt.Fprintf(w, "%s pg upgrade — PostgreSQL %s → %s\n\n", cliName(), orDash(p.From), p.To)
	if p.UpToDate() {
		fmt.Fprintf(w, "This install already runs PostgreSQL %s. Nothing to do.\n", p.To)
		return
	}
	fmt.Fprintln(w, "This install")
	for _, b := range p.All {
		what := "carried: dumped, then reloaded into a new PostgreSQL " + p.To + " cluster"
		if !slices.Contains(p.Carry, b) {
			what = "not carried (agent branch); kept in the rollback copy until --finalize"
		}
		fmt.Fprintf(w, "  %-18s PostgreSQL %-4s %s\n", b, orDash(p.Majors[b]), what)
	}
	if p.Used != "" {
		fmt.Fprintf(w, "  storage: %s used, %s free\n", p.Used, p.Avail)
	}

	fmt.Fprintln(w, "\nWhat changes for you")
	for _, s := range []string{
		"Every database is offline while this runs.",
		fmt.Sprintf("Point-in-time restore cannot reach a moment before the upgrade. The base backups and WAL archived by PostgreSQL %s stay in object storage, and come back with --rollback.", orDash(p.From)),
		"Each carried branch becomes a full copy: it stops sharing blocks with main until it is re-created from it.",
		"The old databases are kept, untouched, until you run `" + cliName() + " pg upgrade --finalize`. Until then they use their space, and `" + cliName() + " pg upgrade --rollback` returns to them — deleting anything created after the upgrade.",
	} {
		fmt.Fprintf(w, "  ! %s\n", wrap(s, 72, "    "))
	}

	found := 0
	for _, n := range p.Notes {
		if len(p.Applies[n.ID]) > 0 {
			found++
		}
	}
	fmt.Fprintf(w, "\nPostgreSQL %s → %s: %d changes, %d found in your databases\n", orDash(p.From), p.To, len(p.Notes), found)
	notes := slices.Clone(p.Notes)
	slices.SortStableFunc(notes, func(a, b PGNote) int {
		return boolRank(len(p.Applies[b.ID]) > 0) - boolRank(len(p.Applies[a.ID]) > 0)
	})
	for _, n := range notes {
		mark, where := "-", ""
		if bs := p.Applies[n.ID]; len(bs) > 0 {
			mark, where = "!", " [found in "+strings.Join(bs, ", ")+"]"
		}
		fmt.Fprintf(w, "  %s %s%s\n", mark, n.Headline, where)
		fmt.Fprintf(w, "    %s\n", wrap(n.Detail, 70, "    "))
	}
	if len(p.Notes) > 0 {
		fmt.Fprintf(w, "  Release notes: %s\n", strings.Join(noteDocs(p.Notes), " , "))
	}

	if r := p.Refusals(); len(r) > 0 {
		fmt.Fprintln(w, "\nRefusing to upgrade:")
		for _, s := range r {
			fmt.Fprintf(w, "  ✗ %s\n", wrap(s, 72, "    "))
		}
		return
	}
	fmt.Fprintln(w, "\nBefore starting")
	fmt.Fprintf(w, "  ✓ the Blackbox verifies on %s\n", strings.Join(p.Carry, ", "))
}

func noteDocs(ns []PGNote) []string {
	var out []string
	for _, n := range ns {
		if !slices.Contains(out, n.DocURL) {
			out = append(out, n.DocURL)
		}
	}
	return out
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// wrap folds text at width, indenting continuation lines.
func wrap(s string, width int, indent string) string {
	var b strings.Builder
	n := 0
	for i, word := range strings.Fields(s) {
		if i > 0 && n+1+len(word) > width {
			b.WriteString("\n" + indent)
			n = 0
		} else if i > 0 {
			b.WriteByte(' ')
			n++
		}
		b.WriteString(word)
		n += len(word)
	}
	return b.String()
}

// PlanUpgrade gathers the facts for an upgrade to PGMajor. It changes nothing.
func PlanUpgrade() (UpgradePlan, error) {
	p := UpgradePlan{To: PGMajor, From: dataMajor("main"), Majors: map[string]string{},
		LedgerErrors: map[string]string{}, Applies: map[string][]string{}}
	all, err := allBranches()
	if err != nil {
		return p, err
	}
	slices.Sort(all)
	p.All = all
	for _, b := range all {
		p.Majors[b] = dataMajor(b)
	}
	if p.Carry, err = exportBranches(all, nil); err != nil {
		p.Carry = nil
	}
	ha := HAInfo()
	p.HA, p.FailedOver = ha.Enabled, ha.Primary != "main"
	p.MainRunning = ContainerState("main") == "running"
	if p.From != "" {
		if names, _ := activeStorage().stashed(upgradeLot(p.From)); names != nil {
			p.HeldLot = upgradeLot(p.From)
		}
	}
	p.Used, p.Avail, _ = activeStorage().capacity()
	if p.UpToDate() || p.From == "" {
		return p, nil
	}
	p.Notes = NotesBetween(p.From, p.To)
	for _, b := range p.Carry {
		if ContainerState(b) != "running" {
			continue // a suspended branch is checked when the upgrade wakes it
		}
		if _, err := LedgerVerify(b); err != nil {
			p.LedgerErrors[b] = err.Error()
		}
		for _, n := range p.Notes {
			if n.Probe != "" && probeMatches(b, n.Probe) {
				p.Applies[n.ID] = append(p.Applies[n.ID], b)
			}
		}
	}
	return p, nil
}

// probeMatches reports whether a note's probe returns a row on a branch. A probe
// that cannot run says nothing, rather than stopping the plan.
func probeMatches(branch, sql string) bool {
	out, err := capture("docker", "exec", "-e", "PGPASSWORD="+pgPass(), container(branch),
		"psql", "-U", pgUser, "-d", pgDatabase, "-tAc", sql)
	return err == nil && strings.TrimSpace(out) != ""
}

// ApplyUpgrade performs the upgrade the plan describes. It takes no questions:
// the caller has already shown the plan, confirmed it, and taken an export.
func ApplyUpgrade() error {
	p, err := PlanUpgrade()
	if err != nil {
		return err
	}
	if p.UpToDate() {
		fmt.Printf("This install already runs PostgreSQL %s.\n", p.To)
		return nil
	}
	if r := p.Refusals(); len(r) > 0 {
		return fmt.Errorf("refusing to upgrade: %s", strings.Join(r, "; "))
	}
	newImage := PostgresImageFor(p.To)
	if err := ensureImageRef(newImage); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "fox-upgrade-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	// 1. Dump everything carried, with the new major's pg_dump. Nothing has
	// changed yet, so a failure here needs no undoing.
	var dumped []ExportedBranch
	for _, b := range p.Carry {
		fmt.Printf("Dumping %s…\n", b)
		eb, err := dumpCarried(b, newImage, dir)
		if err != nil {
			return fmt.Errorf("%s: %w (nothing was changed)", b, err)
		}
		dumped = append(dumped, eb)
	}
	slices.SortStableFunc(dumped, func(a, b ExportedBranch) int { return boolRank(b.Name == "main") - boolRank(a.Name == "main") })

	// 2. Stop Postgres and move every branch into the holding area.
	stopPostgres(p.All)
	lot := upgradeLot(p.From)
	store := activeStorage()
	var moved, created []string
	undo := func(cause error) error {
		fmt.Printf("Upgrade failed: %v\nPutting the PostgreSQL %s databases back…\n", cause, p.From)
		stopPostgres(created)
		for _, b := range created {
			if err := store.destroy(b); err != nil {
				fmt.Printf("  could not remove the new %s: %v\n", b, err)
			}
		}
		for _, b := range moved {
			if err := store.unstash(b, lot); err != nil {
				return fmt.Errorf("%w — and putting %s back failed too (%v); it is kept in %s, and `%s pg upgrade --rollback` retries", cause, b, err, lot, cliName())
			}
		}
		_ = store.dropStash(lot)
		if err := Init(); err != nil {
			return fmt.Errorf("%w — the databases are back, but restarting main failed: %v", cause, err)
		}
		return fmt.Errorf("%w — nothing was lost: the PostgreSQL %s databases are back as they were", cause, p.From)
	}
	for _, b := range p.All {
		if err := store.stash(b, lot); err != nil {
			return undo(fmt.Errorf("moving %s aside: %w", b, err))
		}
		moved = append(moved, b)
	}

	// 3. Reload each carried branch into a new dataset on the new major, main
	// first: it decides which image every later start uses.
	prefix := fmt.Sprintf("pg%s-%s", p.To, strings.ToLower(time.Now().UTC().Format("20060102t150405z")))
	for _, eb := range dumped {
		fmt.Printf("Restoring %s on PostgreSQL %s…\n", eb.Name, p.To)
		if err := store.createEmpty(eb.Name); err != nil {
			return undo(fmt.Errorf("creating %s: %w", eb.Name, err))
		}
		created = append(created, eb.Name)
		if err := run("chown", "-R", pgUID+":"+pgUID, mountpoint(eb.Name)); err != nil {
			return undo(err)
		}
		if eb.Name == "main" {
			if err := writeRoot(mountpoint("main"), walArchiveFile, prefix+"\n"); err != nil {
				return undo(fmt.Errorf("recording the new WAL archive location: %w", err))
			}
		}
		if err := startContainer(eb.Name, eb.Name == "main"); err != nil {
			return undo(err)
		}
		if err := waitReady(eb.Name); err != nil {
			return undo(err)
		}
		if err := restoreInto(eb.Name, dir, eb); err != nil {
			return undo(fmt.Errorf("restoring %s: %w", eb.Name, err))
		}
		if eb.Suspended {
			quiet("docker", "stop", container(eb.Name))
		}
	}
	if err := Init(); err != nil {
		return undo(err)
	}

	// 4. A base backup for the new cluster: until one exists, point-in-time
	// restore has nothing to start from.
	fmt.Println("Taking a base backup of the new cluster…")
	backupErr := Backup()

	fmt.Printf("\nUpgraded to PostgreSQL %s: %s.\n", p.To, strings.Join(p.Carry, ", "))
	if backupErr != nil {
		fmt.Printf("  ! The first base backup failed (%v). Run `%s backup create` before relying on point-in-time restore.\n", backupErr, cliName())
	}
	fmt.Printf("  The PostgreSQL %s databases are kept in %s.\n", p.From, lot)
	fmt.Printf("  Once you have checked everything: `%s pg upgrade --finalize` deletes them.\n", cliName())
	fmt.Printf("  To go back: `%s pg upgrade --rollback`.\n", cliName())
	return nil
}

// dumpCarried wakes a suspended branch, checks its Blackbox — the plan could not,
// while it slept — dumps it, and puts it back to sleep, recording that the
// restored branch should sleep too.
func dumpCarried(b, image, dir string) (ExportedBranch, error) {
	asleep := ContainerState(b) != "running"
	if asleep {
		if _, err := EnsureRunning(b); err != nil {
			return ExportedBranch{}, err
		}
		defer quiet("docker", "stop", container(b))
	}
	if _, err := LedgerVerify(b); err != nil {
		return ExportedBranch{}, fmt.Errorf("the Blackbox does not verify: %w", err)
	}
	eb, err := dumpBranch(b, image, dir)
	if err != nil {
		return eb, fmt.Errorf("dumping: %w", err)
	}
	eb.Suspended = asleep
	return eb, nil
}

// stopPostgres removes the Postgres containers of the named branches, and the
// standby's; the object store keeps running.
func stopPostgres(branches []string) {
	for _, b := range append(slices.Clone(branches), "standby") {
		quiet("docker", "rm", "-f", container(b))
	}
}

// writeRoot writes a small file into a dataset's root, outside PGDATA.
func writeRoot(dir, name, content string) error {
	cmd := execSudo("tee", dir+"/"+name)
	cmd.Stdin = strings.NewReader(content)
	cmd.Stdout = io.Discard
	return cmd.Run()
}

// heldUpgrade finds the holding area an upgrade left, if any.
func heldUpgrade() (lot string, names []string) {
	for _, m := range append([]string{"9.6", "10", "11", "12", "13", "14", "15"}, SupportedPGMajors...) {
		if n, _ := activeStorage().stashed(upgradeLot(m)); len(n) > 0 {
			return upgradeLot(m), n
		}
	}
	return "", nil
}

// RollbackPlan describes what `--rollback` would do: the branches it returns,
// and those it deletes because they did not exist before the upgrade.
type RollbackPlan struct {
	Lot      string
	Restore  []string
	Delete   []string // current branches that are new since the upgrade
	Replaces []string // current branches that the rollback replaces with their old selves
}

// PlanRollback reads the holding area. It changes nothing.
func PlanRollback() (RollbackPlan, error) {
	lot, held := heldUpgrade()
	if lot == "" {
		return RollbackPlan{}, fmt.Errorf("there is no earlier upgrade to go back to")
	}
	current, err := allBranches()
	if err != nil {
		return RollbackPlan{}, err
	}
	r := RollbackPlan{Lot: lot, Restore: held}
	for _, b := range current {
		if b == "standby" {
			continue
		}
		if slices.Contains(held, b) {
			r.Replaces = append(r.Replaces, b)
		} else {
			r.Delete = append(r.Delete, b)
		}
	}
	return r, nil
}

// Render prints a rollback plan.
func (r RollbackPlan) Render(w io.Writer) {
	fmt.Fprintf(w, "%s pg upgrade --rollback — back to the databases kept in %s\n\n", cliName(), r.Lot)
	fmt.Fprintf(w, "  Returns:  %s\n", strings.Join(r.Restore, ", "))
	fmt.Fprintf(w, "  ! Discards the upgraded copies of %s, and every change made to them since the upgrade.\n", strings.Join(r.Replaces, ", "))
	if len(r.Delete) > 0 {
		fmt.Fprintf(w, "  ! Deletes %s: created after the upgrade, they have no older copy.\n", strings.Join(r.Delete, ", "))
	}
	fmt.Fprintln(w, "  Base backups taken since the upgrade stay in object storage but belong to the discarded cluster.")
}

// RollbackUpgrade returns to the databases an upgrade kept.
func RollbackUpgrade() error {
	r, err := PlanRollback()
	if err != nil {
		return err
	}
	if HAInfo().Enabled {
		return fmt.Errorf("high availability is on — run `%s ha disable` first", cliName())
	}
	store := activeStorage()
	current := clonesFirst(append(slices.Clone(r.Replaces), r.Delete...))
	stopPostgres(current)
	for _, b := range current {
		if !store.exists(b) {
			continue // went with a dataset it was cloned from
		}
		if err := store.destroy(b); err != nil {
			return fmt.Errorf("removing the upgraded %s: %w", b, err)
		}
	}
	for _, b := range r.Restore {
		if err := store.unstash(b, r.Lot); err != nil {
			return fmt.Errorf("returning %s: %w (the rest are still in %s; run --rollback again)", b, err, r.Lot)
		}
	}
	_ = store.dropStash(r.Lot)
	if err := Init(); err != nil {
		return err
	}
	fmt.Printf("Back on PostgreSQL %s: %s.\n", orDash(dataMajor("main")), strings.Join(r.Restore, ", "))
	return nil
}

// ShowFinalize prints what `--finalize` would delete, or fails when there is
// nothing kept to delete.
func ShowFinalize(w io.Writer) error {
	lot, held := heldUpgrade()
	if lot == "" {
		return fmt.Errorf("no databases are kept from an upgrade — nothing to finalize")
	}
	fmt.Fprintf(w, "%s pg upgrade --finalize — delete the databases kept by the upgrade (%s)\n\n", cliName(), lot)
	fmt.Fprintf(w, "  ! Deletes: %s, as they were before the upgrade.\n", strings.Join(held, ", "))
	fmt.Fprintf(w, "  ! After this, `%s pg upgrade --rollback` is no longer possible.\n", cliName())
	fmt.Fprintln(w, "  Base backups from before the upgrade stay in object storage.")
	return nil
}

// clonesFirst orders branches for deletion with main last. A branch made after
// the upgrade is a clone of the new main, and destroying main first would take
// it along (zfs destroy -R) and then fail to find it.
func clonesFirst(branches []string) []string {
	out := slices.Clone(branches)
	slices.SortStableFunc(out, func(a, b string) int { return boolRank(a == "main") - boolRank(b == "main") })
	return out
}

// FinalizeUpgrade deletes the databases an upgrade kept.
func FinalizeUpgrade() error {
	lot, held := heldUpgrade()
	if lot == "" {
		fmt.Println("Nothing to finalize: no databases are kept from an upgrade.")
		return nil
	}
	if err := activeStorage().dropStash(lot); err != nil {
		return err
	}
	fmt.Printf("Deleted the databases kept by the upgrade (%s): %s.\n", lot, strings.Join(held, ", "))
	fmt.Println("Base backups from before the upgrade stay in object storage.")
	return nil
}

// PGStatus prints which PostgreSQL this install and each branch run.
func PGStatus(w io.Writer) error {
	all, err := allBranches()
	if err != nil {
		return err
	}
	slices.Sort(all)
	main := dataMajor("main")
	fmt.Fprintf(w, "This %s:      PostgreSQL %s for a fresh install (runs %s)\n", cliName(), PGMajor, strings.Join(SupportedPGMajors, ", "))
	fmt.Fprintf(w, "This install: PostgreSQL %s\n", orDash(main))
	for _, b := range all {
		fmt.Fprintf(w, "  %-18s %s\n", b, orDash(dataMajor(b)))
	}
	if lot, held := heldUpgrade(); lot != "" {
		fmt.Fprintf(w, "Kept by an upgrade (%s): %s — `%s pg upgrade --finalize` deletes, `--rollback` returns\n", lot, strings.Join(held, ", "), cliName())
	}
	if main != "" && majorNum(main) < majorNum(PGMajor) {
		fmt.Fprintf(w, "PostgreSQL %s is available: `%s pg upgrade --dry-run` shows what moving would change.\n", PGMajor, cliName())
	}
	return nil
}
