// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExportBranchesSkipsTheDisposable(t *testing.T) {
	all := []string{"qa", "main", "standby", "agent-7c2a", "checkout"}
	got, err := exportBranches(all, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "checkout,main,qa" {
		t.Errorf("default export = %v; want main and the named branches, not the standby or agents", got)
	}
	got, err = exportBranches(all, []string{"qa", "agent-7c2a", "qa"})
	if err != nil || strings.Join(got, ",") != "agent-7c2a,qa" {
		t.Errorf("asking for branches exports exactly those, once each: %v, %v", got, err)
	}
	if _, err := exportBranches(all, []string{"nope"}); err == nil {
		t.Error("asking for a branch that does not exist should fail")
	}
	if _, err := exportBranches([]string{"qa"}, nil); err == nil {
		t.Error("an install with no main has nothing to export")
	}
}

func TestParseLedgerHead(t *testing.T) {
	n, h, err := parseLedgerHead("42|ab12\n")
	if err != nil || n != 42 || h != "ab12" {
		t.Errorf("got %d %q %v", n, h, err)
	}
	n, h, err = parseLedgerHead("0|")
	if err != nil || n != 0 || h != "" {
		t.Errorf("an empty Blackbox: got %d %q %v", n, h, err)
	}
	if _, _, err := parseLedgerHead("ERROR"); err == nil {
		t.Error("output that is not count|hash should fail")
	}
}

// writeFakeExport lays out what dumpBranch leaves in its directory and archives it.
func writeFakeExport(t *testing.T) (string, ExportManifest) {
	t.Helper()
	dir := t.TempDir()
	m := ExportManifest{Format: exportFormat, Created: time.Unix(1_758_412_800, 0).UTC(), PGMajor: "16"}
	for _, b := range []string{"main", "qa"} {
		eb := ExportedBranch{Name: b, Dump: "branches/" + b + "/data.dump", Roles: "branches/" + b + "/roles.sql", LedgerRows: 3, LedgerHead: "h-" + b}
		for member, content := range map[string]string{eb.Dump: "PGDMP " + b, eb.Roles: "CREATE ROLE db_client;"} {
			p := filepath.Join(dir, filepath.FromSlash(member))
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		m.Branches = append(m.Branches, eb)
	}
	out := filepath.Join(t.TempDir(), "exports", "e.tar")
	if err := writeExport(out, dir, m); err != nil {
		t.Fatal(err)
	}
	return out, m
}

func TestExportRoundTrip(t *testing.T) {
	archive, want := writeFakeExport(t)
	if _, err := os.Stat(archive + ".partial"); !os.IsNotExist(err) {
		t.Error("the .partial file should be renamed away once the archive is complete")
	}
	dir := t.TempDir()
	got, err := ReadExport(archive, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.PGMajor != "16" || len(got.Branches) != 2 || got.Branches[1].LedgerHead != "h-qa" {
		t.Errorf("manifest did not survive: %+v", got)
	}
	b, err := os.ReadFile(filepath.Join(dir, "branches", "qa", "data.dump"))
	if err != nil || string(b) != "PGDMP qa" {
		t.Errorf("extracted dump = %q, %v", b, err)
	}
	if eb, ok := want.Branch("qa"); !ok || eb.Roles != "branches/qa/roles.sql" {
		t.Errorf("Branch lookup: %+v %v", eb, ok)
	}
}

// Rewrites one member of an archive and returns the new path.
func rewriteMember(t *testing.T, archive, member string, content []byte) string {
	t.Helper()
	in, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	r := tar.NewReader(in)
	for {
		hdr, err := r.Next()
		if err != nil {
			break
		}
		var body bytes.Buffer
		_, _ = body.ReadFrom(r)
		if hdr.Name == member {
			body.Reset()
			body.Write(content)
		}
		hdr.Size = int64(body.Len())
		_ = w.WriteHeader(hdr)
		_, _ = w.Write(body.Bytes())
	}
	_ = w.Close()
	out := filepath.Join(t.TempDir(), "tampered.tar")
	if err := os.WriteFile(out, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return out
}

// A damaged export must be refused before anything is restored from it: the
// point of taking one before an upgrade is that it is known to be whole.
func TestReadExportRefusesDamage(t *testing.T) {
	archive, _ := writeFakeExport(t)

	tampered := rewriteMember(t, archive, "branches/qa/data.dump", []byte("PGDMP something else"))
	if _, err := ReadExport(tampered, ""); err == nil || !strings.Contains(err.Error(), "branches/qa/data.dump") {
		t.Errorf("a changed dump should fail naming the file, got %v", err)
	}

	b, _ := os.ReadFile(archive)
	short := filepath.Join(t.TempDir(), "short.tar")
	_ = os.WriteFile(short, b[:len(b)/2], 0o600)
	if _, err := ReadExport(short, ""); err == nil {
		t.Error("a truncated export should not verify")
	}

	if _, err := ReadExport(filepath.Join(t.TempDir(), "missing.tar"), ""); err == nil {
		t.Error("a missing file should fail")
	}
}

// An archive is data from wherever the user kept it; a member named to climb
// out of the extraction directory must not be written anywhere.
func TestReadExportRefusesPathsOutsideTheArchive(t *testing.T) {
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	_ = w.WriteHeader(&tar.Header{Name: "../../escape", Mode: 0o600, Size: 1})
	_, _ = w.Write([]byte("x"))
	_ = w.Close()
	p := filepath.Join(t.TempDir(), "evil.tar")
	_ = os.WriteFile(p, buf.Bytes(), 0o600)
	dir := t.TempDir()
	if _, err := ReadExport(p, dir); err == nil || !strings.Contains(err.Error(), "outside the archive") {
		t.Errorf("got %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(filepath.Dir(dir)), "escape")); !os.IsNotExist(err) {
		t.Error("the member was written outside the extraction directory")
	}
}

func TestValidName(t *testing.T) {
	for _, ok := range []string{"qa", "restored-main", "b2"} {
		if !validName(ok) {
			t.Errorf("%q should be a valid branch name", ok)
		}
	}
	for _, bad := range []string{"", "QA", "-x", "a/b", "../main", "has space"} {
		if validName(bad) {
			t.Errorf("%q should not be a valid branch name", bad)
		}
	}
}
