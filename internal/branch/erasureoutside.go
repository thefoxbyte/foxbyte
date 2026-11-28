// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// The copies an erasure request lists that FoxByte made but does not erase
// (F4, Gate 1 step 5; design, sections 11 and 14): install tars, Blackbox
// exports, and the backup targets and archive prefixes left behind. None of
// them was recorded before this step, so each is recorded from now on, and
// the request says what it cannot know about the time before.

// ---- install tars -----------------------------------------------------------

// Where a tar was written: on the machine the engine runs on, or on the host
// a VM's install is driven from (macOS), whose files the engine cannot read.
const (
	TarOnServer = "server"
	TarOnHost   = "host"
)

// TarRecord is one install tar (`fox backup export`, or the one `fox pg
// upgrade` writes first), as the security log records it: where it went,
// which branches it holds and when it was made. Never what is in it.
type TarRecord struct {
	Path     string    `json:"path"`
	Place    string    `json:"place"`
	Branches []string  `json:"branches"`
	Created  time.Time `json:"created"`
	By       string    `json:"by,omitempty"`
}

// RecordTar writes a tar into the security log. The tar is written already:
// a store that cannot be opened is said, not a failed export.
func RecordTar(r TarRecord) error {
	if r.Place == "" {
		r.Place = TarOnServer
	}
	sort.Strings(r.Branches)
	s, err := restoreStore()
	if err != nil {
		return err
	}
	defer s.Close()
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	s.Audit(auth.EvBackupExport, r.By, r.Path, "", string(b))
	return nil
}

// RecordedTars reads every tar the security log holds, oldest first.
func RecordedTars(s *auth.Store) ([]TarRecord, error) {
	evs, err := s.SecurityEventsOfKind(auth.EvBackupExport)
	if err != nil {
		return nil, err
	}
	out := []TarRecord{}
	for _, e := range evs {
		var r TarRecord
		if json.Unmarshal([]byte(e.Detail), &r) != nil || r.Path == "" {
			continue
		}
		if r.By == "" {
			r.By = e.Actor
		}
		out = append(out, r)
	}
	return out, nil
}

// TarFile is a tar found in an exports folder: its path and when it was last
// written, which is when it was made.
type TarFile struct {
	Path     string    `json:"path"`
	Modified time.Time `json:"modified"`
}

// ListTars lists the tars in an exports folder. A folder that does not exist
// holds none.
func ListTars(dir string) []TarFile {
	es, err := os.ReadDir(dir)
	if err != nil {
		return []TarFile{}
	}
	out := []TarFile{}
	for _, e := range es {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tar") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, TarFile{Path: filepath.Join(dir, e.Name()), Modified: info.ModTime().UTC()})
	}
	return out
}

// ExportsDir is the exports folder `fox backup export` writes to when no
// --out is given, on the machine this runs on.
func ExportsDir() string { return brand.StatePath("exports") }

// HostExports is the host's exports folder as the host last listed it: a VM's
// engine cannot read the host's files, so the host lists them with every
// `dpdp erase` command it forwards (HostExportsEnv), and the last listing is
// kept here for the console.
type HostExports struct {
	Dir     string    `json:"dir"`
	Checked time.Time `json:"checked"`
	Tars    []TarFile `json:"tars"`
}

// HostExportsEnv carries the host's listing into the VM.
const HostExportsEnv = "HOST_EXPORTS"

var hostExportsPath = func() string { return brand.StatePath("host-exports.json") }

// SaveHostExports keeps the host's listing, as the host sent it.
func SaveHostExports(raw string) error {
	var h HostExports
	if err := json.Unmarshal([]byte(raw), &h); err != nil || h.Dir == "" {
		return fmt.Errorf("the host's listing of its exports cannot be read: %v", err)
	}
	if h.Tars == nil {
		h.Tars = []TarFile{}
	}
	b, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(hostExportsPath()), 0o700); err != nil {
		return err
	}
	return os.WriteFile(hostExportsPath(), b, 0o600)
}

// LoadHostExports reads the host's last listing, if a host ever sent one.
func LoadHostExports() (HostExports, bool) {
	var h HostExports
	b, err := os.ReadFile(hostExportsPath())
	if err != nil || json.Unmarshal(b, &h) != nil {
		return HostExports{}, false
	}
	return h, true
}

// ---- Blackbox exports ---------------------------------------------------------

// RecordLedgerExport writes a Blackbox export into the security log: whose
// Blackbox, by whom, from where. The export carries every statement's text,
// so it is a copy an erasure lists.
func RecordLedgerExport(s *auth.Store, branchName, by, ip string) {
	if s == nil {
		return
	}
	s.Audit(auth.EvLedgerExport, by, branchName, ip, fmt.Sprintf("the Blackbox of %s exported, every statement's text with it", branchName))
}

// ---- backup targets left behind ------------------------------------------------

// TargetLeft is a backup target the install moved away from: its backups
// stay there, and FoxByte prunes only the target in force.
type TargetLeft struct {
	Root   string     `json:"root"` // s3://bucket/prefix, or "local"
	Until  time.Time  `json:"until"`
	Gone   *time.Time `json:"gone,omitempty"` // an admin said its backups are deleted
	GoneBy string     `json:"goneBy,omitempty"`
	Reason string     `json:"reason,omitempty"`
}

var targetsLeftPath = func() string { return brand.StatePath("backup-targets-left.json") }

// targetRoot names a target as the list keeps it, without a secret.
func targetRoot(t Target) string {
	if !t.Remote() {
		return "local"
	}
	return t.Root()
}

// TargetsLeft reads the targets left behind, oldest first.
func TargetsLeft() []TargetLeft {
	var out []TargetLeft
	if b, err := os.ReadFile(targetsLeftPath()); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	if out == nil {
		out = []TargetLeft{}
	}
	return out
}

func saveTargetsLeft(ts []TargetLeft) error {
	b, err := json.MarshalIndent(ts, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(targetsLeftPath()), 0o700); err != nil {
		return err
	}
	return os.WriteFile(targetsLeftPath(), b, 0o600)
}

// recordTargetLeft keeps the target moved away from, and says so in the
// security log. Moving back to it takes it off the list: it is in force again.
func recordTargetLeft(from, to Target) {
	if targetRoot(from) == targetRoot(to) {
		return
	}
	ts := TargetsLeft()
	kept := ts[:0]
	for _, t := range ts {
		if t.Root != targetRoot(to) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, TargetLeft{Root: targetRoot(from), Until: time.Now().UTC()})
	_ = saveTargetsLeft(kept)
	if s, err := restoreStore(); err == nil {
		s.Audit(auth.EvBackupTarget, "", targetRoot(to), "",
			fmt.Sprintf("backups moved from %s to %s; %s's backups stay there", targetRoot(from), targetRoot(to), targetRoot(from)))
		s.Close()
	}
}

// ErrTargetNotLeft is a target the list does not hold.
var ErrTargetNotLeft = errors.New("not a backup target left behind")

// ForgetTargetLeft records an admin's word that a target left behind no
// longer holds the install's backups: FoxByte cannot reach it to check.
func ForgetTargetLeft(root, by, reason string) error {
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("%w: say why with --reason (for instance, how the backups were deleted)", ErrInvalidRequest)
	}
	ts := TargetsLeft()
	for i := range ts {
		if ts[i].Root == root && ts[i].Gone == nil {
			now := time.Now().UTC()
			ts[i].Gone, ts[i].GoneBy, ts[i].Reason = &now, by, strings.TrimSpace(reason)
			if err := saveTargetsLeft(ts); err != nil {
				return err
			}
			if s, err := restoreStore(); err == nil {
				s.Audit(auth.EvBackupTarget, by, root, "", fmt.Sprintf("%s's backups said deleted: %s", root, ts[i].Reason))
				s.Close()
			}
			return nil
		}
	}
	var have []string
	for _, t := range ts {
		if t.Gone == nil {
			have = append(have, t.Root)
		}
	}
	if len(have) == 0 {
		return fmt.Errorf("%w: %s (none is listed)", ErrTargetNotLeft, root)
	}
	return fmt.Errorf("%w: %s (listed: %s)", ErrTargetNotLeft, root, strings.Join(have, ", "))
}

// ---- archive prefixes on the target in force ------------------------------------

// archivePrefixes lists the wal-g archives on a target: "" for the root, or
// the prefix an upgraded cluster archives under (walArchiveFile). FoxByte
// prunes only the one in force.
var archivePrefixes = func(t Target) ([]string, error) {
	env := envFile("mc-check.env", mcEnvContent(t))
	defer os.Remove(env)
	root := "t/" + strings.TrimPrefix(t.Root(), "s3://")
	out, err := captureCombined("docker", "run", "--rm", "--network", network, "--env-file", env,
		"--entrypoint", "sh", mcImage(), "-c",
		fmt.Sprintf(`top=$(mc ls %[1]s/ 2>&1) || { case "$top" in *"not exist"*) exit 0;; esac; echo "$top"; exit 3; }; `+
			`echo "$top" | sed 's/^/@ /'; echo "$top" | awk '{print $NF}' | grep '/$' | while read -r d; do mc ls "%[1]s/$d" 2>/dev/null | sed "s|^|$d |"; done`, root))
	if err != nil {
		return nil, fmt.Errorf("cannot list %s: %s", t.Root(), strings.TrimSpace(out))
	}
	return prefixesInListing(out), nil
}

// prefixesInListing reads archivePrefixes' listing: a line "@ <entry>" is
// the root's, "<dir>/ <entry>" one level down.
func prefixesInListing(out string) []string {
	seen := map[string]bool{}
	var ps []string
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasSuffix(l, "basebackups_005/") && !strings.HasSuffix(l, "wal_005/") {
			continue
		}
		p := ""
		if !strings.HasPrefix(l, "@ ") {
			p = strings.TrimSuffix(strings.Fields(l)[0], "/")
		}
		if !seen[p] {
			seen[p] = true
			ps = append(ps, p)
		}
	}
	sort.Strings(ps)
	return ps
}

// currentPrefix is the archive prefix in force: "" for the root.
func currentPrefix() string {
	return strings.TrimPrefix(strings.TrimPrefix(walgPrefix(), target().Root()), "/")
}
