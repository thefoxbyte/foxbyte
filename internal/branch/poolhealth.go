// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// The storage pool's health, and the disk under it.
//
// The pool usually lives in a sparse file on the machine's own disk
// (defaultZpoolFile, btrfsImage), and nothing said when that disk ran out. The
// pool still counted its whole size as free, so the storage line read "29.5G
// free" while the file under it had 1.4G left to grow into. Then a write failed,
// ZFS suspended the pool, and every postgres on it waited for ever in the
// kernel: each psql, backup and `docker rm` against main hung, and nothing said
// why. That is how the test VM spent eight hours on one assertion on
// 2026-10-26. These are the two facts that would have said so.

// PoolHealth is the state of the copy-on-write substrate.
type PoolHealth struct {
	Driver string // "zfs" or "btrfs"
	// State is zpool's health (ONLINE, DEGRADED, SUSPENDED, FAULTED, UNAVAIL,
	// …) under ZFS, and "mounted", "read-only" or "not mounted" under btrfs.
	// Empty when it could not be read.
	State   string
	Missing bool   // there is no pool at all (the storage line says so already)
	Free    uint64 // bytes the pool itself counts as free; 0 when unknown
	Backing string // the regular file the pool lives in; "" for a block device or when unknown
	Err     string
}

// DiskSpace is one filesystem holding something the engine writes to.
type DiskSpace struct {
	Mount       string
	Size, Avail uint64   // bytes
	Holds       []string // what of the engine's is on it
}

// The things whose disk is reported, as they are named in a check line.
const (
	HoldsPool   = "the storage pool's file"
	HoldsDocker = "Docker's images and volumes"
)

// captureWithin is capture, bounded by d rather than a tier.
func captureWithin(d time.Duration, name string, args ...string) (string, error) {
	cmd, ctx, cancel := sudoCmd(d, name, args...)
	defer cancel()
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), execErr(ctx, d, name, withStderr(err))
}

// PoolHealthProbe reads the pool's state, giving each question at most d (the
// probe tier when d is not positive). It never hangs on a suspended pool:
// zpool answers about one, it is the pool's own I/O that waits.
func PoolHealthProbe(d time.Duration) PoolHealth {
	if d <= 0 {
		d = execProbe
	}
	if _, ok := activeStorage().(btrfsStorage); ok {
		return btrfsHealth(d)
	}
	h := PoolHealth{Driver: "zfs"}
	out, err := captureWithin(d, "zpool", "list", "-Hp", "-o", "health,free", pool)
	if err != nil {
		if strings.Contains(err.Error(), "no such pool") {
			h.Missing = true
		}
		h.Err = firstLine(err.Error())
		return h
	}
	h.State, h.Free = parseZpoolHealth(out)
	if h.State == "" {
		h.Err = fmt.Sprintf("unexpected zpool output: %q", out)
		return h
	}
	if v, err := captureWithin(d, "zpool", "list", "-vHP", pool); err == nil {
		h.Backing = zpoolFileVdev(v, isRegularFile)
	}
	return h
}

func btrfsHealth(d time.Duration) PoolHealth {
	h := PoolHealth{Driver: "btrfs", Backing: btrfsImage}
	out, err := captureWithin(d, "findmnt", "-n", "-o", "OPTIONS", "-M", btrfsMount)
	if err != nil || out == "" {
		h.State = "not mounted"
		return h
	}
	h.State = btrfsMountState(out)
	return h
}

// parseZpoolHealth reads `zpool list -Hp -o health,free`.
func parseZpoolHealth(out string) (state string, free uint64) {
	f := strings.Fields(out)
	if len(f) == 0 {
		return "", 0
	}
	if len(f) > 1 {
		free, _ = strconv.ParseUint(f[1], 10, 64)
	}
	return strings.ToUpper(f[0]), free
}

// zpoolFileVdev is the pool's vdev when it is a plain file, from `zpool list
// -vHP`: the pool's own line first, then one per vdev, named by absolute path.
// A pool on a block device has no file to outgrow its disk, so that is "".
func zpoolFileVdev(out string, regular func(string) bool) string {
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) > 0 && strings.HasPrefix(f[0], "/") && regular(f[0]) {
			return f[0]
		}
	}
	return ""
}

func isRegularFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// btrfsMountState reads the mount options: btrfs remounts itself read-only
// after a failed write, which is its way of saying what ZFS says by suspending.
func btrfsMountState(options string) string {
	for _, o := range strings.Split(strings.TrimSpace(options), ",") {
		if o == "ro" {
			return "read-only"
		}
	}
	return "mounted"
}

// DiskSpaceProbe reports the filesystems under the pool's file and Docker's
// data root, once each, giving each question at most d.
func DiskSpaceProbe(d time.Duration, h PoolHealth) ([]DiskSpace, error) {
	if d <= 0 {
		d = execProbe
	}
	type place struct{ path, holds string }
	var places []place
	if h.Backing != "" {
		places = append(places, place{h.Backing, HoldsPool})
	}
	var errs []error
	if root, err := captureWithin(d, "docker", "info", "-f", "{{.DockerRootDir}}"); err == nil && root != "" {
		places = append(places, place{root, HoldsDocker})
	} else if err != nil {
		errs = append(errs, fmt.Errorf("asking Docker where it keeps its data: %s", firstLine(err.Error())))
	}
	var disks []DiskSpace
	for _, p := range places {
		out, err := captureWithin(d, "df", "-P", "-k", p.path)
		if err != nil {
			errs = append(errs, fmt.Errorf("df %s: %s", p.path, firstLine(err.Error())))
			continue
		}
		ds, err := parseDF(out)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		ds.Holds = []string{p.holds}
		disks = mergeDisks(disks, ds)
	}
	if len(disks) == 0 {
		return nil, errors.Join(errs...)
	}
	return disks, nil
}

// parseDF reads `df -P -k <path>`: a header, then one line whose last field is
// the mount point (which may itself contain spaces — so it is everything after
// the capacity column).
func parseDF(out string) (DiskSpace, error) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 2 {
		return DiskSpace{}, fmt.Errorf("unexpected df output: %q", out)
	}
	f := strings.Fields(lines[len(lines)-1])
	if len(f) < 6 {
		return DiskSpace{}, fmt.Errorf("unexpected df output: %q", out)
	}
	size, err1 := strconv.ParseUint(f[1], 10, 64)
	avail, err2 := strconv.ParseUint(f[3], 10, 64)
	if err1 != nil || err2 != nil {
		return DiskSpace{}, fmt.Errorf("unexpected df output: %q", out)
	}
	return DiskSpace{Mount: strings.Join(f[5:], " "), Size: size * 1024, Avail: avail * 1024}, nil
}

// mergeDisks adds d, folding it into an entry for the same filesystem.
func mergeDisks(disks []DiskSpace, d DiskSpace) []DiskSpace {
	for i := range disks {
		if disks[i].Mount == d.Mount {
			disks[i].Holds = append(disks[i].Holds, d.Holds...)
			return disks
		}
	}
	return append(disks, d)
}

// HumanBytes formats a byte count the way zfs list does (1.5G, 200M).
func HumanBytes(n uint64) string { return humanBytes(n) }
