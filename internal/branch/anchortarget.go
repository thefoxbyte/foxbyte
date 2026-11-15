// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// Anchors the administrator cannot rewrite (the expert review plan, G3).
//
// An anchor proves the Blackbox's history only if the person who could rewrite
// the database cannot also rewrite the anchor. By default both sit on this
// machine, and the copies MirrorAnchors makes go to the backup bucket, with
// the backup keys and whatever retention that bucket happens to have. Against
// the machine's administrator, that detects nothing.
//
// An anchor target is a bucket of its own, ideally in an account the database
// administrators do not control (for a bank, storage its security team owns).
// Every anchor is written there with Object Lock in COMPLIANCE mode for a set
// period: until it expires nobody can delete or overwrite it, the bucket's own
// root user included. GOVERNANCE mode is not enough, because anyone allowed to
// bypass governance retention can delete. The bucket must have Object Lock
// enabled, which is decided when it is created, and setting the target refuses
// one without it.
//
// Its keys only ever need to write; reading the anchors back for verification
// is for someone else, with keys of their own.

// DefaultAnchorRetentionDays is how long each anchor is locked unless the
// target says otherwise: a year, the plan's floor for keeping logs.
const DefaultAnchorRetentionDays = 365

// lockedSuffix marks an anchor copied to the anchor target, beside the
// .mirrored marker of the backup-bucket copy.
const lockedSuffix = ".locked"

// AnchorTarget is where anchors are kept under Object Lock.
type AnchorTarget struct {
	Target
	RetentionDays int      `json:"retention_days"`
	Lock          LockInfo `json:"lock"`   // the bucket's Object Lock, as found when the target was set
	SetAt         string   `json:"set_at"` // RFC 3339
}

// LockInfo is a bucket's Object Lock configuration.
type LockInfo struct {
	Enabled         bool   `json:"enabled"`
	DefaultMode     string `json:"default_mode,omitempty"`     // GOVERNANCE, COMPLIANCE or "" (no default rule)
	DefaultValidity string `json:"default_validity,omitempty"` // e.g. 1DAYS
}

// parseLockInfo reads `mc retention info --default --json`. A bucket without
// Object Lock answers with an error, which is an answer, not a failure.
func parseLockInfo(out string) (LockInfo, error) {
	var r struct {
		Status   string `json:"status"`
		Enabled  string `json:"enabled"`
		Mode     string `json:"mode"`
		Validity string `json:"validity"`
		Error    struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	line := strings.TrimSpace(out)
	if i := strings.LastIndex(line, "\n"); i >= 0 {
		line = line[i+1:]
	}
	if err := json.Unmarshal([]byte(line), &r); err != nil {
		return LockInfo{}, fmt.Errorf("unreadable answer about Object Lock: %q", strings.TrimSpace(out))
	}
	if r.Status != "success" {
		if strings.Contains(strings.ToLower(r.Error.Message), "lock") {
			return LockInfo{}, nil // the bucket does not support locking
		}
		return LockInfo{}, fmt.Errorf("asking about Object Lock: %s", r.Error.Message)
	}
	v := r.Validity
	if v == "0" {
		v = ""
	}
	return LockInfo{Enabled: strings.EqualFold(r.Enabled, "Enabled"), DefaultMode: strings.ToUpper(r.Mode), DefaultValidity: v}, nil
}

// Describe says what the lock gives, in a line.
func (l LockInfo) Describe() string {
	switch {
	case !l.Enabled:
		return "no Object Lock"
	case l.DefaultMode == "":
		return "Object Lock enabled, no default rule"
	default:
		return fmt.Sprintf("Object Lock enabled, default %s %s", l.DefaultMode, strings.ToLower(l.DefaultValidity))
	}
}

// CheckAnchorBucket reaches a bucket with the target's own keys and reads its
// Object Lock configuration.
func CheckAnchorBucket(t Target) (LockInfo, error) {
	env := envFile("mc-anchor-check.env", mcEnvContent(t))
	defer os.Remove(env)
	out, err := captureCombined("docker", "run", "--rm", "--network", network, "--env-file", env,
		"--entrypoint", "sh", mcImage(), "-c",
		fmt.Sprintf("mc ls t/%s >/dev/null || exit 3; mc retention info --default --json t/%s 2>&1; exit 0", t.Bucket, t.Bucket))
	if err != nil {
		return LockInfo{}, fmt.Errorf("cannot reach %s with those keys: %s", t.Root(), strings.TrimSpace(out))
	}
	return parseLockInfo(out)
}

func anchorTargetPath() string { return brand.StatePath("anchor-target.json") }

// CurrentAnchorTarget is the anchor target, and false when none is set.
func CurrentAnchorTarget() (AnchorTarget, bool, error) {
	b, err := os.ReadFile(anchorTargetPath())
	if errors.Is(err, os.ErrNotExist) {
		return AnchorTarget{}, false, nil
	}
	if err != nil {
		return AnchorTarget{}, false, err
	}
	var a AnchorTarget
	if err := json.Unmarshal(b, &a); err != nil {
		return AnchorTarget{}, false, fmt.Errorf("%s: %w", anchorTargetPath(), err)
	}
	if !a.Remote() {
		return AnchorTarget{}, false, nil
	}
	if a.RetentionDays <= 0 {
		a.RetentionDays = DefaultAnchorRetentionDays
	}
	return a, true, nil
}

// ErrNoObjectLock refuses a bucket created without Object Lock.
var ErrNoObjectLock = errors.New("the bucket does not have Object Lock enabled")

// sameControl reports why an anchor target is not independent of the backup
// target, or "" when nothing shows that it is the same. FoxByte cannot see who
// owns an account; the same bucket or the same key is the part it can see.
func sameControl(anchor, backup Target) string {
	if !backup.Remote() {
		return ""
	}
	switch {
	case anchor.AccessKey == backup.AccessKey:
		return "it uses the backup target's access key"
	case anchor.Endpoint == backup.Endpoint && anchor.Bucket == backup.Bucket:
		return "it is the backup target's bucket"
	}
	return ""
}

// SetAnchorTarget checks a bucket, saves it as the anchor target, and copies
// every anchor there under COMPLIANCE retention. A bucket without Object Lock
// is refused: per-object retention needs it, and a target that cannot lock is
// the backup bucket again under another name.
func SetAnchorTarget(t Target, retentionDays int, allowHTTP bool) error {
	t.Kind = "s3"
	if err := t.Validate(allowHTTP); err != nil {
		return err
	}
	if t.InsecureHTTP() {
		fmt.Fprintf(os.Stderr, "warning: %s is plain HTTP to another machine: the bucket's secret key crosses the network readable.\n", t.Endpoint)
	}
	if retentionDays <= 0 {
		retentionDays = DefaultAnchorRetentionDays
	}
	fmt.Printf("Checking %s …\n", t.Root())
	lock, err := CheckAnchorBucket(t)
	if err != nil {
		return err
	}
	if !lock.Enabled {
		return fmt.Errorf("%w: %s — create one with Object Lock (`mc mb --with-lock`, or Object Lock on in the console); it cannot be turned on later", ErrNoObjectLock, t.Root())
	}
	fmt.Printf("  reachable; %s.\n", lock.Describe())
	fmt.Printf("  Every anchor will be locked in COMPLIANCE mode for %d days: nobody can delete it before then, the bucket's owner included.\n", retentionDays)
	if why := sameControl(t, target()); why != "" {
		fmt.Printf("  warning: %s. Anchors protect history only from someone who cannot reach them: use a bucket and keys the database administrators do not hold.\n", why)
	}
	a := AnchorTarget{Target: t, RetentionDays: retentionDays, Lock: lock, SetAt: time.Now().UTC().Format(time.RFC3339)}
	if err := saveAnchorTarget(a); err != nil {
		return err
	}
	fmt.Printf("Anchors now go to %s as well.\n", t.Describe())
	n, err := mirrorAnchorsTo(t, envFile("mc-anchor.env", mcEnvContent(t)), lockedSuffix, retentionFlags(retentionDays))
	if err != nil {
		return fmt.Errorf("the target is set, but copying the anchors failed: %w", err)
	}
	fmt.Printf("Copied %d anchor(s) there.\n", n)
	return nil
}

// RemoveAnchorTarget stops copying anchors to the anchor target. What was
// copied stays, locked until its retention ends.
func RemoveAnchorTarget() error {
	err := os.Remove(anchorTargetPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func saveAnchorTarget(a AnchorTarget) error {
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(anchorTargetPath()), 0o700); err != nil {
		return err
	}
	return writeSecretFile(anchorTargetPath(), b)
}

// retentionFlags are the mc cp flags that lock one anchor.
func retentionFlags(days int) string {
	return fmt.Sprintf("--retention-mode compliance --retention-duration %dd", days)
}

// AnchorCopies is how far anchors have got off this machine: per destination,
// how many are waiting and the age of the oldest one waiting. Read from the
// marker files alone, so `fox check` can ask without the network.
type AnchorCopies struct {
	Total         int
	Waiting       int           // not yet at the destination
	OldestWaiting time.Duration // 0 when none is waiting
}

// CountAnchorCopies reports the copies for a marker suffix (.mirrored for the
// backup bucket, .locked for the anchor target).
func CountAnchorCopies(suffix string) AnchorCopies {
	var c AnchorCopies
	base := anchorBase()
	dirs, _ := os.ReadDir(base)
	now := time.Now()
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		dir := filepath.Join(base, d.Name())
		files, _ := os.ReadDir(dir)
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), ".json") {
				continue
			}
			c.Total++
			if _, err := os.Stat(filepath.Join(dir, f.Name()+suffix)); err == nil {
				continue
			}
			c.Waiting++
			if info, err := f.Info(); err == nil {
				if age := now.Sub(info.ModTime()); age > c.OldestWaiting {
					c.OldestWaiting = age
				}
			}
		}
	}
	return c
}

// LockedSuffix and MirroredSuffix name the markers, for CountAnchorCopies.
const (
	LockedSuffix   = lockedSuffix
	MirroredSuffix = mirroredSuffix
)
