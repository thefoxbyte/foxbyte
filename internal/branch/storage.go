// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// The branching engine needs one thing from the filesystem: instant
// copy-on-write clones of a Postgres data directory. ZFS provides it with
// snapshot+clone; btrfs provides it with subvolume snapshots.
//
// Both are supported because neither works everywhere:
//
//   - ZFS is out-of-tree. Its module must match the running kernel exactly, so
//     on Windows every WSL kernel needs its own prebuilt module, and Microsoft
//     ships new kernels often. Users on an uncovered kernel simply cannot
//     install.
//   - btrfs is in-tree. It is already in the stock WSL kernel, so it works on
//     every WSL kernel, past and future, with nothing to prebuild.
//
// So Windows uses btrfs and macOS/Linux keep ZFS, which is proven there and
// where the module is a solved problem. The launcher selects the driver with
// FOX_STORAGE; the default is ZFS, so nothing changes for an existing
// install that does not ask for otherwise.

// envStorage selects the driver. "zfs" (default) or "btrfs".
const envStorage = "FOX_STORAGE"

// branchUsage is one branch's space accounting: used is what the branch costs
// on top of what it shares, refer is what it appears to contain.
type branchUsage struct {
	Name  string
	Used  string
	Refer string
}

// storage is the copy-on-write substrate the engine branches on.
type storage interface {
	// name identifies the driver in messages.
	name() string
	// ensureReady makes the substrate usable: the pool/filesystem and the base
	// directory branches live under. Idempotent.
	ensureReady() error
	// exists reports whether a branch is present.
	exists(branch string) bool
	// createEmpty makes a new empty branch (used for main and the HA standby).
	createEmpty(branch string) error
	// clone makes dst an instant copy-on-write copy of src.
	clone(src, dst string) error
	// destroy removes a branch and anything created to support it.
	destroy(branch string) error
	// list prints a human-readable listing to stdout.
	list() error
	// usage reports per-branch space, for the status view.
	usage() ([]branchUsage, error)
	// capacity reports total used and available for the whole substrate.
	capacity() (used, avail string, err error)
	// standbyPath is the host directory holding the HA standby's data. It is a
	// sibling of the branches under ZFS and a subvolume beside them under btrfs,
	// so the path is the driver's to decide.
	standbyPath() string
	// resetStandby discards any existing standby storage and makes it afresh.
	resetStandby() error
	// destroyStandby removes the standby storage. Best effort: tearing down HA
	// must not fail because there was nothing to tear down.
	destroyStandby()
	// protectPrimary applies any driver-specific guard that keeps the primary
	// writable when branches grow (a ZFS reservation). Idempotent, best-effort.
	protectPrimary()

	// A holding area outside the branch namespace, for data that must be kept
	// but must not be a branch: `fox pg upgrade` moves every branch into one so
	// a rollback is a move back rather than a restore. Nothing that lists or
	// routes to branches can see into it.
	//
	// stash moves a branch into the holding area `lot`, unstash moves it back,
	// stashed lists what a lot holds (nil for a lot that does not exist), and
	// dropStash deletes a lot and everything in it.
	stash(branch, lot string) error
	unstash(branch, lot string) error
	stashed(lot string) ([]string, error)
	dropStash(lot string) error
}

// activeStorage returns the configured driver.
func activeStorage() storage {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envStorage))) {
	case "btrfs":
		return btrfsStorage{}
	default:
		return zfsStorage{}
	}
}

// --- per-branch space limits (ZFS) ---
//
// Branches and the primary share one pool. Without a limit, a runaway branch —
// exactly what the Agent Branch API invites — can fill the pool and take main
// read-only. Two guards: a reservation guarantees main some writable space no
// matter what branches do, and an optional per-branch refquota caps how much any
// one branch can grow.

const (
	envBranchRefquota  = "FOX_BRANCH_REFQUOTA"  // cap a branch's referenced space (e.g. "20G"); unset = uncapped
	envMainReservation = "FOX_MAIN_RESERVATION" // guarantee main this much writable space
	defaultMainReserve = "2G"
)

// setBranchRefquota caps how much a branch dataset may reference. Opt-in: unset
// or "none" leaves branches uncapped, because a clone references its parent's
// blocks, so a cap smaller than the parent would refuse creation — the operator
// sizes it to their data.
func setBranchRefquota(ds string) error {
	q := envOr(envBranchRefquota, "")
	if q == "" || strings.EqualFold(q, "none") {
		return nil
	}
	return run("zfs", "set", "refquota="+q, ds)
}

// reserveMain reserves pool space for the primary so branches filling the rest
// of the pool cannot take main read-only. Best-effort — a reservation that can't
// be set (e.g. the pool is already full) is a warning, not a startup failure.
// "none" disables it.
func reserveMain() {
	r := envOr(envMainReservation, defaultMainReserve)
	if r == "" || strings.EqualFold(r, "none") {
		return
	}
	if err := run("zfs", "set", "reservation="+r, dataset("main")); err != nil {
		fmt.Printf("note: could not reserve %s for main (%v); branches could still crowd it out\n", r, err)
	}
}

// ---------------------------------------------------------------- ZFS

// zfsStorage is the original substrate, unchanged. Every command here is the
// one the engine issued before the drivers existed, so macOS and Linux behave
// exactly as they did.
type zfsStorage struct{}

func (zfsStorage) name() string { return "zfs" }

// ensureReady guarantees the pool and the base branches dataset exist, creating
// the pool on a loopback file (or a given block device) if absent.
func (z zfsStorage) ensureReady() error {
	if _, err := exec.LookPath("zfs"); err != nil {
		return fmt.Errorf("ZFS is not installed — install zfsutils and retry")
	}
	if poolExists() {
		if !datasetExists(datasetBase) {
			return run("zfs", "create", "-p", datasetBase)
		}
		return nil
	}

	vdev := envOr(envZpoolDevice, defaultZpoolFile)
	// A file vdev is created on demand; a real block device is used as-is.
	if !strings.HasPrefix(vdev, "/dev/") {
		if _, err := os.Stat(vdev); os.IsNotExist(err) {
			fmt.Printf("Creating a %s ZFS pool image at %s (first run only)…\n",
				envOr(envZpoolSize, defaultZpoolSize), vdev)
			if err := run("truncate", "-s", envOr(envZpoolSize, defaultZpoolSize), vdev); err != nil {
				return fmt.Errorf("creating pool image: %w", err)
			}
		}
	}
	fmt.Printf("Creating ZFS pool %q on %s…\n", pool, vdev)
	if err := run("zpool", "create", "-f", pool, vdev); err != nil {
		return fmt.Errorf("creating ZFS pool: %w", err)
	}
	return run("zfs", "create", "-p", datasetBase)
}

func (zfsStorage) exists(branch string) bool {
	return exec.Command("sudo", "zfs", "list", "-H", "-o", "name", dataset(branch)).Run() == nil
}

func (zfsStorage) createEmpty(branch string) error {
	if err := run("zfs", "create", "-p", dataset(branch)); err != nil {
		return err
	}
	if branch == "main" || branch == "standby" {
		return nil // the primary and the HA standby are not capped
	}
	return setBranchRefquota(dataset(branch))
}

func (zfsStorage) protectPrimary() { reserveMain() }

func (zfsStorage) clone(src, dst string) error {
	snap := snapFor(src, dst)
	// A snapshot left over from an earlier branch of this name (a crash, or a
	// version that didn't clean it up) would make the snapshot below fail. The
	// branch doesn't exist yet (Create checks), so nothing depends on it.
	quiet("zfs", "destroy", snap)
	if err := run("zfs", "snapshot", snap); err != nil {
		return fmt.Errorf("snapshotting %s: %w", src, err)
	}
	if err := run("zfs", "clone", snap, dataset(dst)); err != nil {
		return fmt.Errorf("cloning into %s: %w", dst, err)
	}
	// A clone shares the parent's blocks, so cap only after it exists.
	return setBranchRefquota(dataset(dst))
}

func (zfsStorage) destroy(branch string) error {
	// A clone's origin is the snapshot it was made from, <parent>@for-<branch>.
	// Read it before the clone goes: the parent isn't always main (branch create
	// --from), and a leftover snapshot of that parent made re-creating a branch
	// of the same name from it fail.
	origin, _ := capture("zfs", "get", "-H", "-o", "value", "origin", dataset(branch))
	if err := run("zfs", "destroy", "-R", dataset(branch)); err != nil {
		return err
	}
	if o := strings.TrimSpace(origin); isOriginSnapshotFor(o, branch) {
		quiet("zfs", "destroy", o)
	}
	quiet("zfs", "destroy", snapFor("main", branch)) // branches made before origins were read
	return nil
}

// isOriginSnapshotFor reports whether a snapshot is the one made to clone this
// branch (snapFor) — the only snapshot destroy may remove.
func isOriginSnapshotFor(snapshot, branch string) bool {
	return strings.HasPrefix(snapshot, datasetBase+"/") && strings.HasSuffix(snapshot, "@for-"+branch) &&
		!strings.Contains(strings.TrimSuffix(snapshot, "@for-"+branch), "@")
}

// stashDataset is a lot's dataset: a sibling of the branches, so it mounts
// outside mountBase and no branch listing reaches it.
func stashDataset(lot string) string { return pool + "/" + lot }

// stash renames the branch's dataset into the lot. Clones stay valid across a
// rename (their origin follows the snapshot), so main and its branches can be
// moved in any order.
func (zfsStorage) stash(branch, lot string) error {
	if err := run("zfs", "create", "-p", stashDataset(lot)); err != nil {
		return err
	}
	return run("zfs", "rename", dataset(branch), stashDataset(lot)+"/"+branch)
}

func (zfsStorage) unstash(branch, lot string) error {
	return run("zfs", "rename", stashDataset(lot)+"/"+branch, dataset(branch))
}

func (zfsStorage) stashed(lot string) ([]string, error) {
	out, err := capture("zfs", "list", "-H", "-o", "name", "-d", "1", stashDataset(lot))
	if err != nil {
		return nil, nil // no such lot
	}
	var names []string
	for _, ln := range strings.Fields(out) {
		if ln != stashDataset(lot) {
			names = append(names, filepath.Base(ln))
		}
	}
	return names, nil
}

// dropStash destroys the lot recursively. -R also takes the snapshots the old
// branches were cloned from, which live under the lot's copy of main; nothing
// outside the lot depends on them, because whatever replaced those branches
// was created empty.
func (zfsStorage) dropStash(lot string) error {
	if !datasetExists(stashDataset(lot)) {
		return nil
	}
	return run("zfs", "destroy", "-R", stashDataset(lot))
}

func (zfsStorage) list() error {
	return run("zfs", "list", "-r", "-o", "name,used,refer,mountpoint", datasetBase)
}

func (zfsStorage) usage() ([]branchUsage, error) {
	out, err := capture("zfs", "list", "-H", "-o", "name,used,refer", "-r", datasetBase)
	if err != nil {
		return nil, err
	}
	var us []branchUsage
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) != 3 || f[0] == datasetBase {
			continue
		}
		us = append(us, branchUsage{Name: filepath.Base(f[0]), Used: f[1], Refer: f[2]})
	}
	return us, nil
}

func (zfsStorage) standbyPath() string { return standbyMount }

func (zfsStorage) resetStandby() error {
	quiet("zfs", "destroy", "-r", standbyDataset)
	return run("zfs", "create", standbyDataset)
}

func (zfsStorage) destroyStandby() { quiet("zfs", "destroy", "-r", standbyDataset) }

func (zfsStorage) capacity() (string, string, error) {
	out, err := capture("zfs", "list", "-H", "-o", "used,avail", pool)
	if err != nil {
		return "", "", err
	}
	f := strings.Fields(out)
	if len(f) != 2 {
		return "", "", fmt.Errorf("unexpected zfs output: %q", out)
	}
	return f[0], f[1], nil
}

// ---------------------------------------------------------------- btrfs

// btrfsStorage backs branches with btrfs subvolumes.
//
// It exists for Windows, where ZFS cannot be relied on: the module is
// out-of-tree and must match the running WSL kernel exactly. btrfs is in the
// stock kernel, so nothing has to be prebuilt or matched, and a WSL update can
// never strand a user.
//
// It is also simpler underneath. ZFS on WSL could not use a plain file as a
// vdev, so the pool needed a loop device, which brought its own failure modes
// (a detached device suspends the pool, and a suspended pool can wedge the VM).
// btrfs makes a filesystem on the file directly.
type btrfsStorage struct{}

func (btrfsStorage) name() string { return "btrfs" }

// btrfsImage is the file holding the filesystem, and btrfsMount is where it is
// mounted. Branches are subvolumes inside it, so a branch's data directory is
// mountBase/<name> exactly as with ZFS.
const (
	btrfsImage = "/var/lib/dbpool-btrfs.img"
	btrfsMount = mountBase
)

func btrfsSubvol(branch string) string { return filepath.Join(btrfsMount, branch) }

func (b btrfsStorage) ensureReady() error {
	if _, err := exec.LookPath("mkfs.btrfs"); err != nil {
		return fmt.Errorf("btrfs-progs is not installed — install it and retry")
	}
	// Already mounted: nothing to do.
	if exec.Command("sudo", "mountpoint", "-q", btrfsMount).Run() == nil {
		return nil
	}
	if _, err := os.Stat(btrfsImage); os.IsNotExist(err) {
		size := envOr(envZpoolSize, defaultZpoolSize)
		fmt.Printf("Creating a %s btrfs image at %s (first run only)…\n", size, btrfsImage)
		if err := run("truncate", "-s", size, btrfsImage); err != nil {
			return fmt.Errorf("creating the storage image: %w", err)
		}
		if err := run("mkfs.btrfs", "-q", "-L", "foxbyte", btrfsImage); err != nil {
			return fmt.Errorf("formatting the storage image: %w", err)
		}
	}
	if err := run("mkdir", "-p", btrfsMount); err != nil {
		return err
	}
	// No compression: branch subvolumes are nodatacow (see disableCoW), which
	// btrfs cannot compress anyway, and compressing a database write path costs
	// CPU for little gain.
	if err := run("mount", "-o", "loop", btrfsImage, btrfsMount); err != nil {
		return fmt.Errorf("mounting the storage image: %w", err)
	}
	return nil
}

func (btrfsStorage) exists(branch string) bool {
	return exec.Command("sudo", "btrfs", "subvolume", "show", btrfsSubvol(branch)).Run() == nil
}

func (b btrfsStorage) createEmpty(branch string) error {
	if err := run("btrfs", "subvolume", "create", btrfsSubvol(branch)); err != nil {
		return err
	}
	return b.disableCoW(branch)
}

// clone is a single snapshot: btrfs needs no separate snapshot object, so
// there is nothing left behind to clean up when the branch is deleted.
//
// The snapshot inherits nodatacow from its source, and files created in it
// afterwards inherit it from the directory, so a branch performs like its
// parent. The first write to an extent still shared with the parent is copied
// once — that is what makes a branch a branch — and reverts to in-place after.
func (b btrfsStorage) clone(src, dst string) error {
	return run("btrfs", "subvolume", "snapshot", btrfsSubvol(src), btrfsSubvol(dst))
}

// disableCoW turns off copy-on-write for a branch's contents.
//
// This matters more than it sounds. Under CoW every random write into a
// Postgres heap or index relocates an extent, so the data files fragment badly
// and write throughput degrades as they age — the standard reason databases are
// not run on plain btrfs. Setting the attribute on the empty subvolume makes
// every file created inside it inherit nodatabase-cow, which keeps Postgres
// writing in place, as it does on ext4 or ZFS.
//
// Snapshots keep working: btrfs still copies an extent the first time it is
// written after being shared, which is exactly the branch semantics we want.
//
// The trade-off is that btrfs cannot checksum nodatacow extents. Postgres has
// its own page checksums and its WAL, so the database remains able to detect
// and recover from corruption on its own.
func (btrfsStorage) disableCoW(branch string) error {
	// Best effort: a filesystem that refuses the attribute still works, just
	// with CoW's write amplification.
	if err := run("chattr", "+C", btrfsSubvol(branch)); err != nil {
		fmt.Printf("note: could not disable copy-on-write on %s; writes may be slower\n", branch)
	}
	return nil
}

func (btrfsStorage) destroy(branch string) error {
	return run("btrfs", "subvolume", "delete", btrfsSubvol(branch))
}

// btrfsLot is a lot's directory. Everything must stay inside the one btrfs
// filesystem mounted at btrfsMount, so the lot is a dot-directory there: the
// branch listing's "*/" glob does not match it.
func btrfsLot(lot string) string { return filepath.Join(btrfsMount, "."+lot) }

func (btrfsStorage) stash(branch, lot string) error {
	if err := run("mkdir", "-p", btrfsLot(lot)); err != nil {
		return err
	}
	return run("mv", btrfsSubvol(branch), filepath.Join(btrfsLot(lot), branch))
}

func (btrfsStorage) unstash(branch, lot string) error {
	return run("mv", filepath.Join(btrfsLot(lot), branch), btrfsSubvol(branch))
}

func (btrfsStorage) stashed(lot string) ([]string, error) {
	out, err := capture("sh", "-c", fmt.Sprintf("ls -1 %s 2>/dev/null || true", btrfsLot(lot)))
	if err != nil {
		return nil, err
	}
	f := strings.Fields(out)
	if len(f) == 0 {
		return nil, nil
	}
	return f, nil
}

func (b btrfsStorage) dropStash(lot string) error {
	names, err := b.stashed(lot)
	if err != nil {
		return err
	}
	for _, n := range names {
		if err := run("btrfs", "subvolume", "delete", filepath.Join(btrfsLot(lot), n)); err != nil {
			return err
		}
	}
	quiet("rmdir", btrfsLot(lot))
	return nil
}

func (b btrfsStorage) list() error {
	if err := run("btrfs", "subvolume", "list", btrfsMount); err != nil {
		return err
	}
	return run("btrfs", "filesystem", "df", btrfsMount)
}

// usage reports what each branch appears to contain.
//
// btrfs cannot report a branch's exclusive cost without quota groups, which are
// off by default because they slow the filesystem down. Reporting the apparent
// size for both figures is honest about that: it says what is there, and never
// claims a shared extent is exclusively owned.
func (b btrfsStorage) usage() ([]branchUsage, error) {
	out, err := capture("sh", "-c",
		fmt.Sprintf("du -sh --apparent-size %s/*/ 2>/dev/null || true", btrfsMount))
	if err != nil {
		return nil, err
	}
	var us []branchUsage
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) != 2 {
			continue
		}
		name := filepath.Base(strings.TrimSuffix(f[1], "/"))
		us = append(us, branchUsage{Name: name, Used: f[0], Refer: f[0]})
	}
	return us, nil
}

// The standby is a subvolume alongside the branches rather than a sibling
// directory: everything must live inside the one mounted btrfs filesystem.
func (btrfsStorage) standbyPath() string { return btrfsSubvol("standby") }

func (b btrfsStorage) resetStandby() error {
	b.destroyStandby()
	return b.createEmpty("standby")
}

func (b btrfsStorage) destroyStandby() {
	if b.exists("standby") {
		quiet("btrfs", "subvolume", "delete", btrfsSubvol("standby"))
	}
}

// protectPrimary is a no-op on btrfs: it has no reservation, and per-branch
// quota groups are off by default for performance (see usage()).
func (btrfsStorage) protectPrimary() {}

func (b btrfsStorage) capacity() (string, string, error) {
	// FSSize/FSUsed from `btrfs filesystem usage --raw`, rendered like ZFS.
	out, err := capture("btrfs", "filesystem", "usage", "--raw", btrfsMount)
	if err != nil {
		return "", "", err
	}
	var size, used uint64
	for _, ln := range strings.Split(out, "\n") {
		t := strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(t, "Device size:"):
			size = parseBytesField(t)
		case strings.HasPrefix(t, "Used:"):
			used = parseBytesField(t)
		}
	}
	if size == 0 {
		return "", "", fmt.Errorf("could not read btrfs usage")
	}
	return humanBytes(used), humanBytes(size - used), nil
}

func parseBytesField(line string) uint64 {
	f := strings.Fields(line)
	if len(f) == 0 {
		return 0
	}
	n, _ := strconv.ParseUint(f[len(f)-1], 10, 64)
	return n
}

// humanBytes formats a byte count the way zfs list does (1.5G, 200M), so the
// status view reads the same whichever driver is in use.
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit && exp < 4; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%c", float64(n)/float64(div), "KMGTP"[exp])
}
