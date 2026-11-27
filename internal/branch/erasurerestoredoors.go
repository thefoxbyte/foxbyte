// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// The restore doors' halves of the erasure guard (erasurerestore.go): the
// restore copy, an export tar restored into a branch, and an upgrade rolled
// back. Branch-before asks it in branch_before.go.

// restoreCopy is the restore copy's name: container pg-restore, port 5433.
const restoreCopy = "restore"

// restoreVolume holds a restore copy kept closed while an erasure is applied
// to it again, so the same data can be started again listening.
func restoreVolume() string { return container(restoreCopy) + "-data" }

// RestoreAfter is Restore with the erasure guard: a copy of main from before
// an applied erasure is refused, or, with the admin's decision, made closed,
// applied the erasure again, and only then started on port 5433.
func RestoreAfter(ts string, after AfterErasure) error {
	// The volume a closed copy used, if one is left: the copy below is new.
	quiet("docker", "volume", "rm", "-f", restoreVolume())
	if strings.TrimSpace(ts) == "latest" {
		// The end of the archive holds every erasure applied so far.
		return Restore(ts)
	}
	at, ok := parseRestoreTime(ts)
	if !ok {
		return Restore(ts) // which says why it cannot read the time
	}
	g, err := guardRestore("restore", "main", at, ts, after)
	if err != nil {
		return err
	}
	if g == nil {
		return Restore(ts)
	}
	defer g.close()
	if err := g.open(restoreCopy, false); err != nil {
		return err
	}
	if err := restorePITRClosed(ts); err != nil {
		g.abandon(err)
		removeRestoreCopy()
		return err
	}
	fmt.Printf("restored to %q, closed (no port): applying erasure request(s) %s again before it opens\n", ts, g.requests())
	done, err := g.reapply()
	if err != nil {
		removeRestoreCopy()
		return fmt.Errorf("%w; the restore copy was removed", err)
	}
	if err := reopenRestoreCopy(ts); err != nil {
		removeRestoreCopy()
		return fmt.Errorf("the erasure was applied again to the restore copy, but starting it on port 5433 failed, so it was removed: %w", err)
	}
	for _, d := range done {
		fmt.Printf("  erasure request #%d applied again: %d row(s) changed%s\n", d.Request, d.Result.Rows, reapplyBlackboxNote(d))
	}
	fmt.Printf("ready as container %s (port 5433). Query it with:\n  sudo docker exec %s psql -U dbadmin -d appdb -c 'SELECT ...'\n",
		container(restoreCopy), container(restoreCopy))
	return nil
}

func reapplyBlackboxNote(d ReapplyDone) string {
	if d.Result.Blackbox == nil || d.Result.Blackbox.Redacted == 0 {
		return ""
	}
	return fmt.Sprintf("; %d Blackbox entr(ies) redacted", d.Result.Blackbox.Redacted)
}

// restorePITRClosed is restorePITRInto for a copy that must not be reached:
// no port published, its data on a volume of its own so it can be started
// again once the erasure is applied.
func restorePITRClosed(ts string) error {
	backup, err := restoreBackupName(ts)
	if err != nil {
		return err
	}
	if backup != "LATEST" {
		fmt.Printf("starting from base backup %s (the newest one that precedes %s)\n", backup, ts)
	}
	removeRestoreCopy()
	if out, err := captureCombined("docker", "volume", "create", "--label", managedLabel, restoreVolume()); err != nil {
		return fmt.Errorf("making the restore copy's volume: %w\n%s", err, out)
	}
	args := []string{"run", "-d", "--name", container(restoreCopy), "--network", network, "--label", managedLabel}
	args = append(args, walgEnv()...)
	args = append(args,
		"-e", "PGDATA=/var/lib/postgresql/data/pgdata",
		"-e", "RECOVERY_TARGET_TIME="+ts,
		"-e", "BACKUP_NAME="+backup,
		"-v", restoreVolume()+":/var/lib/postgresql/data",
		"--entrypoint", "bash",
		pgImage(), "-c", restorePITRScript,
	)
	if out, err := captureCombined("docker", args...); err != nil {
		return fmt.Errorf("starting the restore container: %w\n%s", err, strings.TrimSpace(out))
	}
	return waitRecovered(restoreCopy)
}

// reopenRestoreCopy starts the recovered copy again, on port 5433 (loopback
// only, as every restore copy).
func reopenRestoreCopy(ts string) error {
	quiet("docker", "stop", "-t", "60", container(restoreCopy))
	// -v removes anonymous volumes only: the named one, the copy, is kept.
	removeContainer(container(restoreCopy))
	args := []string{"run", "-d", "--name", container(restoreCopy), "--network", network, "--label", managedLabel}
	args = append(args, walgEnv()...)
	args = append(args,
		"-e", "PGDATA=/var/lib/postgresql/data/pgdata",
		"-e", "RECOVERY_TARGET_TIME="+ts,
		"-p", loopbackPort("5433", "5432"),
		"-v", restoreVolume()+":/var/lib/postgresql/data",
		"--entrypoint", "bash",
		pgImage(), "-c", restorePITRScript,
	)
	if out, err := captureCombined("docker", args...); err != nil {
		return fmt.Errorf("%w\n%s", err, strings.TrimSpace(out))
	}
	return waitRecovered(restoreCopy)
}

func removeRestoreCopy() {
	removeContainer(container(restoreCopy))
	quiet("docker", "volume", "rm", "-f", restoreVolume())
}

// RestoreExportAfter is RestoreExport with the erasure guard: an export made
// before an erasure was applied to the branch it holds is refused, or, with
// the admin's decision, restored into a branch closed until each request is
// applied to it again.
func RestoreExportAfter(archive, from, into string, after AfterErasure) ([]ReapplyDone, error) {
	created, err := exportCreated(archive)
	if err != nil {
		return nil, err
	}
	g, err := guardRestore("backup restore", from, created, "the export of "+created.Local().Format("2006-01-02 15:04"), after)
	if err != nil {
		return nil, err
	}
	if g == nil {
		return nil, RestoreExport(archive, from, into)
	}
	defer g.close()
	if !validName(into) {
		return nil, fmt.Errorf("invalid branch name %q", into)
	}
	if activeStorage().exists(into) {
		return nil, fmt.Errorf("branch %q already exists — restore into a new name", into)
	}
	if err := g.open(into, true); err != nil {
		return nil, err
	}
	fmt.Printf("The export is from before erasure request(s) %s: %q stays closed until they are applied to it again.\n", g.requests(), into)
	if err := RestoreExport(archive, from, into); err != nil {
		if !activeStorage().exists(into) {
			g.abandon(err)
			return nil, err
		}
		// Left for inspection, as RestoreExport says, and closed.
		return nil, g.fail(0, err)
	}
	return g.reapply()
}

// exportCreated reads when an export was made, from its manifest.
func exportCreated(archive string) (time.Time, error) {
	m, err := ReadExport(archive, "")
	if err != nil {
		return time.Time{}, err
	}
	return m.Created, nil
}

// --- the upgrade's rollback ---------------------------------------------------

// upgradeLotsPath records when each upgrade kept its databases, so a
// rollback knows which erasures it would undo. A lot kept before this was
// recorded reads as from before every erasure.
var upgradeLotsPath = func() string { return brand.StatePath("upgrade-lots.json") }

func recordUpgradeLot(lot string) {
	m := map[string]time.Time{}
	if b, err := os.ReadFile(upgradeLotsPath()); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	m[lot] = time.Now().UTC()
	if b, err := json.MarshalIndent(m, "", "  "); err == nil {
		_ = os.WriteFile(upgradeLotsPath(), b, 0o600)
	}
}

func upgradeLotTime(lot string) time.Time {
	m := map[string]time.Time{}
	if b, err := os.ReadFile(upgradeLotsPath()); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m[lot]
}

// rollbackGuards asks the guard for each branch a rollback returns. Every
// one is asked before anything changes; one refusal refuses the rollback.
func rollbackGuards(r RollbackPlan, after AfterErasure) ([]*restoreGuard, error) {
	at := upgradeLotTime(r.Lot)
	point := "before the upgrade"
	if !at.IsZero() {
		point = "before the upgrade of " + at.Local().Format("2006-01-02 15:04")
	}
	var gs []*restoreGuard
	for _, b := range r.Restore {
		g, err := guardRestore("pg rollback", b, at, point, after)
		if err != nil {
			for _, x := range gs {
				x.close()
			}
			return nil, err
		}
		if g != nil {
			gs = append(gs, g)
		}
	}
	return gs, nil
}

// RollbackUpgradeAfter is RollbackUpgrade with the erasure guard: the
// databases an upgrade kept are from before every erasure applied since, so
// the rollback is refused, or, with the admin's decision, each branch it
// returns is closed until each request is applied to it again.
func RollbackUpgradeAfter(after AfterErasure) error {
	r, err := PlanRollback()
	if err != nil {
		return err
	}
	gs, err := rollbackGuards(r, after)
	if err != nil {
		return err
	}
	if len(gs) == 0 {
		return RollbackUpgrade()
	}
	defer func() {
		for _, g := range gs {
			g.close()
		}
	}()
	for _, g := range gs {
		if err := g.open(g.source, true); err != nil {
			return err
		}
	}
	if err := RollbackUpgrade(); err != nil {
		for _, g := range gs {
			g.abandon(err)
		}
		return err
	}
	var failed []string
	for _, g := range gs {
		if err := wakeForReapply(g.target); err != nil {
			failed = append(failed, g.fail(0, err).Error())
			continue
		}
		done, err := g.reapply()
		if err != nil {
			failed = append(failed, err.Error())
			continue
		}
		for _, d := range done {
			fmt.Printf("  erasure request #%d applied again to %s: %d row(s) changed%s\n", d.Request, g.target, d.Result.Rows, reapplyBlackboxNote(d))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("the rollback is done, but %s", strings.Join(failed, "; "))
	}
	return nil
}

// RollbackErasures says what a rollback would undo, for its plan: nothing,
// or the requests and what it takes to go ahead. Changes nothing.
func RollbackErasures(r RollbackPlan) error {
	_, err := rollbackGuardsPreview(r)
	return err
}

func rollbackGuardsPreview(r RollbackPlan) ([]*restoreGuard, error) {
	gs, err := rollbackGuards(r, AfterErasure{})
	for _, g := range gs {
		g.close()
	}
	return gs, err
}

// wakeForReapply starts a closed branch for its re-apply, past the check
// that keeps everyone else out.
func wakeForReapply(name string) error {
	if name == "main" || ContainerState(name) == "running" {
		return nil
	}
	if err := startContainer(name, false); err != nil {
		return err
	}
	return waitReady(name)
}
