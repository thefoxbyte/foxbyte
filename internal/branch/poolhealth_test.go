// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import "testing"

// What zpool, findmnt and df print, read the way `fox check` needs it. The
// outputs are the ones the test VM printed on 2026-10-26, when its disk was full
// and the pool suspended.
func TestPoolHealthParsing(t *testing.T) {
	t.Run("zpool's health and free space", func(t *testing.T) {
		for out, want := range map[string]string{
			"SUSPENDED\t31675383808": "SUSPENDED",
			"ONLINE\t31675383808":    "ONLINE",
			"degraded":               "DEGRADED",
			"":                       "",
		} {
			st, _ := parseZpoolHealth(out)
			if st != want {
				t.Errorf("%q: state %q, want %q", out, st, want)
			}
		}
		if _, free := parseZpoolHealth("ONLINE\t31675383808"); free != 31675383808 {
			t.Errorf("free %d", free)
		}
	})

	t.Run("the vdev file, and none for a block device", func(t *testing.T) {
		out := "dbpool\t31675383808\t33030144\t31642353664\t-\t-\t0\t0\t1.00\tSUSPENDED\t-\n" +
			"\t/var/lib/dbpool-zpool.img\t31675383808\t33030144\t31642353664\t-\t-\t0\t0\t-\tONLINE\n"
		file := func(p string) bool { return p == "/var/lib/dbpool-zpool.img" }
		if got := zpoolFileVdev(out, file); got != "/var/lib/dbpool-zpool.img" {
			t.Errorf("got %q", got)
		}
		dev := "dbpool\t1000\t1\t999\t-\t-\t0\t0\t1.00\tONLINE\t-\n\t/dev/nvme1n1\t1000\t1\t999\t-\t-\t0\t0\t-\tONLINE\n"
		if got := zpoolFileVdev(dev, func(string) bool { return false }); got != "" {
			t.Errorf("a block device is not a file that can outgrow its disk: got %q", got)
		}
	})

	t.Run("btrfs read-only after a failed write", func(t *testing.T) {
		if got := btrfsMountState("ro,relatime,space_cache=v2,subvolid=5"); got != "read-only" {
			t.Errorf("got %q", got)
		}
		if got := btrfsMountState("rw,relatime,errors=ro"); got != "mounted" {
			t.Errorf("an option that merely mentions ro is not ro: got %q", got)
		}
	})

	t.Run("df, including a mount point with a space in it", func(t *testing.T) {
		d, err := parseDF("Filesystem     1024-blocks     Used Available Capacity Mounted on\n" +
			"/dev/vda1         39700000 37000000   1468006      97% /\n")
		if err != nil || d.Mount != "/" || d.Size != 39700000*1024 || d.Avail != 1468006*1024 {
			t.Errorf("got %+v, %v", d, err)
		}
		d, err = parseDF("Filesystem 1024-blocks Used Available Capacity Mounted on\n" +
			"/dev/disk3s5 100 50 50 50% /Volumes/My Data\n")
		if err != nil || d.Mount != "/Volumes/My Data" {
			t.Errorf("got %+v, %v", d, err)
		}
		if _, err := parseDF("df: /nope: No such file or directory"); err == nil {
			t.Error("want an error for output with no data line")
		}
	})

	t.Run("one line per filesystem, naming everything on it", func(t *testing.T) {
		disks := mergeDisks(nil, DiskSpace{Mount: "/", Holds: []string{HoldsPool}})
		disks = mergeDisks(disks, DiskSpace{Mount: "/", Holds: []string{HoldsDocker}})
		disks = mergeDisks(disks, DiskSpace{Mount: "/data", Holds: []string{HoldsDocker}})
		if len(disks) != 2 || len(disks[0].Holds) != 2 {
			t.Errorf("got %+v", disks)
		}
	})
}
