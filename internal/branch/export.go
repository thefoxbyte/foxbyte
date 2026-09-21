// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"archive/tar"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/version"
)

// An export is a portable copy of an install's databases: one tar holding, per
// branch, a pg_dump in custom format and that branch's roles, plus a manifest
// and a SHA256SUMS over everything. It is what survives a move between
// PostgreSQL majors — `fox backup create` takes a wal-g base backup, which
// belongs to one major and one cluster — and it is what `fox pg upgrade` asks
// for before it touches anything.
//
// Roles are per branch because every branch is its own cluster: a per-user
// login role is created on the branch the user connected to, and roles are not
// in any database's pg_dump. A dump restored without them is a database nobody
// can log into.
//
// The dump keeps owners and privileges and includes the Blackbox (schema bb),
// so a restore is the same database. pg_dump writes event triggers and row
// triggers after the data, so restoring it records nothing new in the Blackbox,
// and the restore checks that: the ledger's row count and newest hash must
// equal what the manifest says they were.

const exportFormat = "foxbyte-export/1"

// ExportManifest describes an export. It is the archive's first member.
type ExportManifest struct {
	Format     string           `json:"format"`
	Created    time.Time        `json:"created"`
	FoxVersion string           `json:"fox_version"`
	PGMajor    string           `json:"pg_major"`
	Branches   []ExportedBranch `json:"branches"`
}

// ExportedBranch is one branch in an export, with the Blackbox state the
// restore must reproduce.
type ExportedBranch struct {
	Name       string `json:"name"`
	Dump       string `json:"dump"`  // archive path of the pg_dump (custom format)
	Roles      string `json:"roles"` // archive path of pg_dumpall --roles-only
	LedgerRows int64  `json:"ledger_rows"`
	LedgerHead string `json:"ledger_head"` // row_hash of the newest Blackbox entry, "" for none
	Suspended  bool   `json:"suspended"`
}

// Branch returns the named branch in the export.
func (m ExportManifest) Branch(name string) (ExportedBranch, bool) {
	for _, b := range m.Branches {
		if b.Name == name {
			return b, true
		}
	}
	return ExportedBranch{}, false
}

// ExportOptions says what to export and where to.
type ExportOptions struct {
	Out      string   // the archive to write
	Branches []string // empty: main and every branch that is not an agent's
	// Image is the image whose pg_dump runs. Empty means this install's own;
	// `fox pg upgrade` passes the new major's, because a newer pg_dump can read
	// an older server and the reverse is not supported.
	Image string
}

// exportBranches picks the branches an export covers: the ones asked for, or
// by default main and every branch that is not disposable. Agent branches are
// made and thrown away by agents; the standby is a copy of main; restore and
// branch-before products are copies of a moment already in the backups.
func exportBranches(all []string, asked []string) ([]string, error) {
	if len(asked) > 0 {
		for _, a := range asked {
			if !slices.Contains(all, a) {
				return nil, fmt.Errorf("no branch %q", a)
			}
		}
		out := slices.Clone(asked)
		slices.Sort(out)
		return slices.Compact(out), nil
	}
	var out []string
	for _, b := range all {
		if b == "standby" || strings.HasPrefix(b, "agent-") {
			continue
		}
		out = append(out, b)
	}
	if !slices.Contains(out, "main") {
		return nil, fmt.Errorf("main was not found — is the stack set up?")
	}
	sort.Strings(out)
	return out, nil
}

// allBranches lists every branch dataset, whatever its container is doing.
func allBranches() ([]string, error) {
	us, err := activeStorage().usage()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, u := range us {
		if !strings.Contains(u.Name, "/") {
			names = append(names, u.Name)
		}
	}
	return names, nil
}

// Export writes an export archive and returns its manifest.
func Export(opts ExportOptions) (ExportManifest, error) {
	all, err := allBranches()
	if err != nil {
		return ExportManifest{}, err
	}
	names, err := exportBranches(all, opts.Branches)
	if err != nil {
		return ExportManifest{}, err
	}
	image := opts.Image
	if image == "" {
		image = pgImage()
	}
	dir, err := os.MkdirTemp("", "fox-export-")
	if err != nil {
		return ExportManifest{}, err
	}
	defer os.RemoveAll(dir)

	m := ExportManifest{
		Format: exportFormat, Created: time.Now().UTC(), FoxVersion: version.Version,
		PGMajor: dataMajor("main"),
	}
	for _, b := range names {
		fmt.Printf("  exporting %s…\n", b)
		eb, err := dumpBranch(b, image, dir)
		if err != nil {
			return ExportManifest{}, fmt.Errorf("exporting %s: %w", b, err)
		}
		m.Branches = append(m.Branches, eb)
	}
	if err := writeExport(opts.Out, dir, m); err != nil {
		return ExportManifest{}, err
	}
	return m, nil
}

// dumpBranch writes a branch's roles and database into dir and returns what the
// manifest records for it. A suspended branch is woken for the dump and put
// back to sleep afterwards; main must already be up.
//
// pg_dump runs in a throwaway container of image, connecting over the docker
// network: that is what lets `fox pg upgrade` use the new major's pg_dump on
// the old server.
func dumpBranch(name, image, dir string) (ExportedBranch, error) {
	state := ContainerState(name)
	if name == "main" || container(name) == PrimaryContainer() {
		if state != "running" {
			return ExportedBranch{}, fmt.Errorf("main is not running — start the stack first (`fox start`)")
		}
	} else if state != "running" {
		if _, err := EnsureRunning(name); err != nil {
			return ExportedBranch{}, err
		}
		defer quiet("docker", "stop", container(name))
	}

	eb := ExportedBranch{
		Name:      name,
		Dump:      path.Join("branches", name, "data.dump"),
		Roles:     path.Join("branches", name, "roles.sql"),
		Suspended: state != "running" && name != "main",
	}
	if err := os.MkdirAll(filepath.Join(dir, "branches", name), 0o700); err != nil {
		return eb, err
	}
	if err := dumpTo(filepath.Join(dir, filepath.FromSlash(eb.Roles)), image,
		"pg_dumpall", "-h", container(name), "-U", pgUser, "--roles-only"); err != nil {
		return eb, fmt.Errorf("dumping roles: %w", err)
	}
	rows, head, err := dumpAtStableHead(
		func() (int64, string, error) { return ledgerHead(name) },
		func() error {
			return dumpTo(filepath.Join(dir, filepath.FromSlash(eb.Dump)), image,
				"pg_dump", "-h", container(name), "-U", pgUser, "-d", pgDatabase, "-Fc")
		})
	if err != nil {
		return eb, err
	}
	eb.LedgerRows, eb.LedgerHead = rows, head
	return eb, nil
}

// dumpAttempts bounds how often a dump is retaken while the schema changes.
const dumpAttempts = 3

// dumpAtStableHead dumps, and returns the Blackbox head the dump holds.
//
// The manifest records that head and a restore insists on it. pg_dump reads
// its own snapshot, so the head is read on both sides of the dump: if a schema
// change landed in between, the two disagree, and the dump is taken again
// rather than recorded against a head it does not hold — which would make a
// good export fail its own restore check.
func dumpAtStableHead(read func() (int64, string, error), dump func() error) (int64, string, error) {
	for attempt := 1; attempt <= dumpAttempts; attempt++ {
		rows, head, err := read()
		if err != nil {
			return 0, "", fmt.Errorf("reading the Blackbox: %w", err)
		}
		if err := dump(); err != nil {
			return 0, "", fmt.Errorf("dumping the database: %w", err)
		}
		rows2, head2, err := read()
		if err != nil {
			return 0, "", fmt.Errorf("reading the Blackbox: %w", err)
		}
		if rows == rows2 && head == head2 {
			return rows, head, nil
		}
	}
	return 0, "", fmt.Errorf("the schema kept changing while it was being dumped (%d attempts); try again when it is quiet", dumpAttempts)
}

// dumpTo runs a dump tool from image against the docker network and writes
// its standard output to file.
func dumpTo(file, image string, tool ...string) error {
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	args := append([]string{"docker", "run", "--rm", "--network", network, "-e", "PGPASSWORD=" + pgPass(), image}, tool...)
	cmd := exec.Command("sudo", args...)
	cmd.Stdout = f
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	closeErr := f.Close()
	if runErr != nil {
		return fmt.Errorf("%w: %s", runErr, strings.TrimSpace(stderr.String()))
	}
	return closeErr
}

// ledgerHeadSQL counts the Blackbox and returns its newest hash.
const ledgerHeadSQL = `SELECT count(*) || '|' || coalesce((SELECT row_hash FROM bb.schema_ledger ORDER BY id DESC LIMIT 1), '') FROM bb.schema_ledger`

func ledgerHead(name string) (int64, string, error) {
	out, err := capture("docker", "exec", "-e", "PGPASSWORD="+pgPass(), container(name),
		"psql", "-U", pgUser, "-d", pgDatabase, "-tA", "-c", ledgerHeadSQL)
	if err != nil {
		return 0, "", err
	}
	return parseLedgerHead(out)
}

func parseLedgerHead(out string) (int64, string, error) {
	count, head, ok := strings.Cut(strings.TrimSpace(out), "|")
	if !ok {
		return 0, "", fmt.Errorf("unexpected Blackbox head %q", out)
	}
	n, err := strconv.ParseInt(count, 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("unexpected Blackbox count %q", count)
	}
	return n, head, nil
}

// writeExport tars the manifest, a SHA256SUMS and every file the manifest names
// into out, writing to a temporary name and renaming at the end so a failed
// export never leaves a partial archive that looks whole.
func writeExport(out, dir string, m ExportManifest) error {
	manifest, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	var members []string
	for _, b := range m.Branches {
		members = append(members, b.Roles, b.Dump)
	}
	var sums bytes.Buffer
	fmt.Fprintf(&sums, "%s  manifest.json\n", sha256Hex(manifest))
	for _, name := range members {
		h, err := sha256File(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			return err
		}
		fmt.Fprintf(&sums, "%s  %s\n", h, name)
	}

	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		return err
	}
	partial := out + ".partial"
	f, err := os.OpenFile(partial, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	w := tar.NewWriter(f)
	add := func(name string, r io.Reader, size int64) error {
		if err := w.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: size, ModTime: m.Created}); err != nil {
			return err
		}
		_, err := io.Copy(w, r)
		return err
	}
	err = add("manifest.json", bytes.NewReader(manifest), int64(len(manifest)))
	if err == nil {
		err = add("SHA256SUMS", bytes.NewReader(sums.Bytes()), int64(sums.Len()))
	}
	for _, name := range members {
		if err != nil {
			break
		}
		var src *os.File
		if src, err = os.Open(filepath.Join(dir, filepath.FromSlash(name))); err != nil {
			break
		}
		var fi os.FileInfo
		if fi, err = src.Stat(); err == nil {
			err = add(name, src, fi.Size())
		}
		src.Close()
	}
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(partial)
		return err
	}
	return os.Rename(partial, out)
}

// ReadExport verifies an export against its own SHA256SUMS and returns its
// manifest. When dir is not empty, every member is also written there, so the
// archive is read once whether it is only being checked or being restored.
func ReadExport(archive, dir string) (ExportManifest, error) {
	var m ExportManifest
	f, err := os.Open(archive)
	if err != nil {
		return m, err
	}
	defer f.Close()

	want := map[string]string{}
	got := map[string]string{}
	r := tar.NewReader(bufio.NewReader(f))
	for {
		hdr, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return m, fmt.Errorf("%s is not a readable export: %w", filepath.Base(archive), err)
		}
		name := path.Clean(hdr.Name)
		if strings.HasPrefix(name, "../") || path.IsAbs(name) {
			return m, fmt.Errorf("%s names a file outside the archive: %s", filepath.Base(archive), hdr.Name)
		}
		h := sha256.New()
		var sink io.Writer = h
		var buf bytes.Buffer
		if name == "manifest.json" || name == "SHA256SUMS" {
			sink = io.MultiWriter(h, &buf)
		}
		var out *os.File
		if dir != "" && name != "SHA256SUMS" {
			p := filepath.Join(dir, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				return m, err
			}
			if out, err = os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err != nil {
				return m, err
			}
			sink = io.MultiWriter(sink, out)
		}
		_, err = io.Copy(sink, r)
		if out != nil {
			if cerr := out.Close(); err == nil {
				err = cerr
			}
		}
		if err != nil {
			return m, fmt.Errorf("reading %s from the export: %w", name, err)
		}
		switch name {
		case "SHA256SUMS":
			for _, ln := range strings.Split(buf.String(), "\n") {
				if sum, file, ok := strings.Cut(strings.TrimSpace(ln), "  "); ok {
					want[file] = sum
				}
			}
		case "manifest.json":
			if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
				return m, fmt.Errorf("the export's manifest is unreadable: %w", err)
			}
			got[name] = hex.EncodeToString(h.Sum(nil))
		default:
			got[name] = hex.EncodeToString(h.Sum(nil))
		}
	}
	if m.Format != exportFormat {
		return m, fmt.Errorf("%s is not a %s export (format %q)", filepath.Base(archive), exportFormat, m.Format)
	}
	if len(want) == 0 {
		return m, fmt.Errorf("%s has no SHA256SUMS; it cannot be verified", filepath.Base(archive))
	}
	for file, sum := range want {
		if got[file] != sum {
			return m, fmt.Errorf("%s does not match its checksum in the export — the file is damaged or incomplete", file)
		}
	}
	for _, b := range m.Branches {
		for _, member := range []string{b.Dump, b.Roles} {
			if _, ok := want[member]; !ok {
				return m, fmt.Errorf("the export is missing %s", member)
			}
		}
	}
	return m, nil
}

// RestoreExport restores one branch of an export into a new branch. The export
// may come from an older PostgreSQL than this install runs — a newer server
// reads an older dump — but not from a newer one.
func RestoreExport(archive, from, into string) error {
	if !validName(into) {
		return fmt.Errorf("invalid branch name %q", into)
	}
	store := activeStorage()
	if store.exists(into) {
		return fmt.Errorf("branch %q already exists — restore into a new name", into)
	}
	dir, err := os.MkdirTemp("", "fox-restore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	m, err := ReadExport(archive, dir)
	if err != nil {
		return err
	}
	eb, ok := m.Branch(from)
	if !ok {
		return fmt.Errorf("the export has no branch %q (it has %s)", from, exportNames(m))
	}
	here := dataMajor("main")
	if here == "" {
		here = PGMajor
	}
	if majorNum(m.PGMajor) > majorNum(here) {
		return fmt.Errorf("the export is from PostgreSQL %s and this install runs %s: a dump restores into the same or a newer major, not an older one", m.PGMajor, here)
	}
	if err := store.createEmpty(into); err != nil {
		return err
	}
	if err := run("chown", "-R", pgUID+":"+pgUID, mountpoint(into)); err != nil {
		return err
	}
	if err := startContainer(into, false); err != nil {
		return err
	}
	if err := waitReady(into); err != nil {
		return err
	}
	if err := restoreInto(into, dir, eb); err != nil {
		return fmt.Errorf("restoring %s into %q: %w (the new branch is left for inspection; `%s branch delete %s` removes it)", from, into, err, cliName(), into)
	}
	return nil
}

// branchNameRe is the control plane's rule for a branch name (lower-case,
// digits and dashes), applied here too: a restore names a new branch.
var branchNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)

func validName(n string) bool { return branchNameRe.MatchString(n) }

// cliName is the command, for messages that tell the user what to run.
func cliName() string { return brand.CLI }

func exportNames(m ExportManifest) string {
	var n []string
	for _, b := range m.Branches {
		n = append(n, b.Name)
	}
	return strings.Join(n, ", ")
}

// restoreInto loads an exported branch into the (empty, running) cluster of
// branch, then checks the Blackbox came across exactly: every row, ending in
// the same hash. Only after that does it bring the Blackbox's definitions and
// the role passwords up to this install.
func restoreInto(branch, dir string, eb ExportedBranch) error {
	roles, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(eb.Roles)))
	if err != nil {
		return err
	}
	// Roles first: the dump names them as owners and grantees. The superuser
	// already exists in a fresh cluster, so its CREATE ROLE fails and the rest
	// of the script carries on; that is the only error it can meet.
	if err := psqlScript(branch, "postgres", string(roles), false); err != nil {
		return fmt.Errorf("restoring roles: %w", err)
	}
	dump, err := os.Open(filepath.Join(dir, filepath.FromSlash(eb.Dump)))
	if err != nil {
		return err
	}
	defer dump.Close()
	cmd := exec.Command("sudo", "docker", "exec", "-i", "-e", "PGPASSWORD="+pgPass(), container(branch),
		"pg_restore", "-U", pgUser, "-d", pgDatabase, "--exit-on-error", "--single-transaction")
	cmd.Stdin = dump
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pg_restore: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	rows, head, err := ledgerHead(branch)
	if err != nil {
		return fmt.Errorf("reading the restored Blackbox: %w", err)
	}
	if rows != eb.LedgerRows || head != eb.LedgerHead {
		return fmt.Errorf("the Blackbox did not come across exactly: %d entries ending in %q, expected %d ending in %q",
			rows, head, eb.LedgerRows, eb.LedgerHead)
	}
	if _, err := LedgerVerify(branch); err != nil {
		return fmt.Errorf("the restored Blackbox does not verify: %w", err)
	}

	if err := syncRolePassword(branch); err != nil {
		return err
	}
	if err := InstallLedger(branch); err != nil {
		return err
	}
	ensureLedgerV2BestEffort(branch)
	return syncAppRole(branch)
}

// psqlScript runs a SQL script on a branch's cluster over its local socket.
// With stopOnError false it carries on past failing statements, and succeeds
// unless psql itself could not run.
func psqlScript(branch, db, sql string, stopOnError bool) error {
	stop := "0"
	if stopOnError {
		stop = "1"
	}
	cmd := exec.Command("sudo", "docker", "exec", "-i", "-e", "PGPASSWORD="+pgPass(), container(branch),
		"psql", "-U", pgUser, "-d", db, "-v", "ON_ERROR_STOP="+stop, "-q")
	cmd.Stdin = strings.NewReader(sql)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func sha256File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
