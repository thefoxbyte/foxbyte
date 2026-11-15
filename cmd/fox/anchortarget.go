// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// anchorTargetCmd is `fox blackbox anchor-target`: show, set or remove the
// bucket anchors are kept in under Object Lock (branch/anchortarget.go). The
// secret key is read from FOX_ANCHOR_S3_SECRET_KEY or asked for, never taken as
// an argument: the process list and the shell history would keep it.
func anchorTargetCmd(args []string) {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "", "show":
		a, ok, err := branch.CurrentAnchorTarget()
		must(err)
		if !ok {
			fmt.Println("no anchor target: anchors are kept on this machine" + backupCopyNote())
			fmt.Printf("set one with: %s blackbox anchor-target set s3://bucket --endpoint <https-url> --access-key <key>\n", brand.CLI)
			return
		}
		fmt.Printf("anchors go to %s\n", a.Describe())
		fmt.Printf("  each locked in COMPLIANCE mode for %d days\n", a.RetentionDays)
		lock, err := branch.CheckAnchorBucket(a.Target)
		if err != nil {
			fmt.Println("  not reachable now:", err)
		} else {
			fmt.Println("  bucket:", lock.Describe())
		}
		c := branch.CountAnchorCopies(branch.LockedSuffix)
		fmt.Printf("  %d of %d anchor(s) copied there\n", c.Total-c.Waiting, c.Total)
	case "set":
		if len(args) < 2 || strings.HasPrefix(args[1], "-") {
			fmt.Printf("usage: %s blackbox anchor-target set s3://bucket[/prefix] --endpoint <https-url> --access-key <key> [--region <r>] [--retention-days N] [--path-style] [--allow-insecure-http]\n", brand.CLI)
			os.Exit(2)
		}
		bucket, prefix, err := branch.ParseTargetURL(args[1])
		must(err)
		t := branch.Target{Kind: "s3", Bucket: bucket, Prefix: prefix,
			Endpoint:  optValue(args, "--endpoint"),
			AccessKey: optValue(args, "--access-key"),
			Region:    optValue(args, "--region"),
			PathStyle: hasFlag(args, "--path-style")}
		if t.Region == "" {
			t.Region = "us-east-1"
		}
		days := branch.DefaultAnchorRetentionDays
		if v := optValue(args, "--retention-days"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				must(fmt.Errorf("--retention-days is a number of days, 1 or more; got %q", v))
			}
			days = n
		}
		t.SecretKey = strings.TrimSpace(brand.Getenv("ANCHOR_S3_SECRET_KEY"))
		if t.SecretKey == "" {
			fmt.Print("secret key: ")
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			t.SecretKey = strings.TrimSpace(line)
		}
		must(branch.SetAnchorTarget(t, days, allowInsecureHTTP(args)))
	case "none":
		must(branch.RemoveAnchorTarget())
		fmt.Println("no anchor target: new anchors stay on this machine" + backupCopyNote() + ".")
		fmt.Println("Anchors already copied stay in the bucket, locked until their retention ends.")
	default:
		fmt.Printf("usage: %[1]s blackbox anchor-target [show] | %[1]s blackbox anchor-target set s3://… | %[1]s blackbox anchor-target none\n", brand.CLI)
		os.Exit(2)
	}
}

// backupCopyNote says whether anchors are also copied to the backup bucket.
func backupCopyNote() string {
	if t, err := branch.CurrentTarget(); err == nil && t.Remote() {
		return ", with copies in the backup bucket (" + t.Root() + ")"
	}
	return ""
}
