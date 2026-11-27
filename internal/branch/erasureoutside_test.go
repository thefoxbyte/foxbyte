// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

func TestTarsAreRecordedAndReadBack(t *testing.T) {
	// RecordTar closes the store it opens: give it one of its own each time.
	_, path := requestStore(t)
	opened := func() (*auth.Store, error) { return auth.Open(auth.Config{DBPath: path, WebOrigin: "http://x"}) }
	old := restoreStore
	restoreStore = opened
	t.Cleanup(func() { restoreStore = old })
	created := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	if err := RecordTar(TarRecord{Path: "/state/exports/a.tar", Branches: []string{"qa", "main"}, Created: created, By: "op"}); err != nil {
		t.Fatal(err)
	}
	if err := RecordTar(TarRecord{Path: "/Users/a/x.tar", Place: TarOnHost, Branches: []string{"main"}, Created: created, By: "op"}); err != nil {
		t.Fatal(err)
	}
	st, err := opened()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rs, err := RecordedTars(st)
	if err != nil || len(rs) != 2 {
		t.Fatalf("recorded: %v %+v", err, rs)
	}
	if rs[0].Place != TarOnServer || strings.Join(rs[0].Branches, ",") != "main,qa" || !rs[0].Created.Equal(created) || rs[1].Place != TarOnHost {
		t.Fatalf("read back: %+v", rs)
	}
}

func TestTargetsLeftAndForgotten(t *testing.T) {
	dir := t.TempDir()
	old := targetsLeftPath
	targetsLeftPath = func() string { return filepath.Join(dir, "left.json") }
	t.Cleanup(func() { targetsLeftPath = old })
	oldStore := restoreStore
	restoreStore = func() (*auth.Store, error) { return nil, errors.New("no store in this test") }
	t.Cleanup(func() { restoreStore = oldStore })

	a := Target{Kind: "s3", Bucket: "old", Prefix: "fox"}
	b := Target{Kind: "s3", Bucket: "new"}
	recordTargetLeft(Target{Kind: "local"}, a) // local, then a
	recordTargetLeft(a, b)                     // a left
	recordTargetLeft(b, b)                     // no move
	ts := TargetsLeft()
	if len(ts) != 2 || ts[0].Root != "local" || ts[1].Root != "s3://old/fox" {
		t.Fatalf("left: %+v", ts)
	}
	// Moving back to a target takes it off the list.
	recordTargetLeft(b, Target{Kind: "local"})
	if ts = TargetsLeft(); len(ts) != 2 || ts[0].Root != "s3://old/fox" || ts[1].Root != "s3://new" {
		t.Fatalf("back to local: %+v", ts)
	}
	if err := ForgetTargetLeft("s3://old/fox", "admin@x", ""); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("no reason: %v", err)
	}
	if err := ForgetTargetLeft("s3://nope", "admin@x", "r"); !errors.Is(err, ErrTargetNotLeft) || !strings.Contains(err.Error(), "s3://old/fox") {
		t.Fatalf("unknown: %v", err)
	}
	if err := ForgetTargetLeft("s3://old/fox", "admin@x", "bucket emptied"); err != nil {
		t.Fatal(err)
	}
	if ts = TargetsLeft(); ts[0].Gone == nil || ts[0].GoneBy != "admin@x" || ts[0].Reason != "bucket emptied" {
		t.Fatalf("forgotten: %+v", ts[0])
	}
}

func TestHostExportsAreKeptAsListed(t *testing.T) {
	dir := t.TempDir()
	old := hostExportsPath
	hostExportsPath = func() string { return filepath.Join(dir, "host-exports.json") }
	t.Cleanup(func() { hostExportsPath = old })
	if _, ok := LoadHostExports(); ok {
		t.Fatal("a listing before any")
	}
	if err := SaveHostExports(`{"dir":"/Users/a/.fox/exports","checked":"2026-11-27T10:00:00Z","tars":[{"path":"/Users/a/.fox/exports/x.tar","modified":"2026-11-20T09:00:00Z"}]}`); err != nil {
		t.Fatal(err)
	}
	h, ok := LoadHostExports()
	if !ok || h.Dir != "/Users/a/.fox/exports" || len(h.Tars) != 1 {
		t.Fatalf("listing: %+v", h)
	}
	if err := SaveHostExports("not json"); err == nil {
		t.Fatal("a broken listing was kept")
	}
	// ListTars reads a folder: tars only, with their times.
	ex := filepath.Join(dir, "exports")
	_ = os.MkdirAll(ex, 0o700)
	_ = os.WriteFile(filepath.Join(ex, "a.tar"), []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(ex, "notes.txt"), []byte("x"), 0o600)
	if ts := ListTars(ex); len(ts) != 1 || filepath.Base(ts[0].Path) != "a.tar" || ts[0].Modified.IsZero() {
		t.Fatalf("tars: %+v", ts)
	}
	if ts := ListTars(filepath.Join(dir, "none")); len(ts) != 0 {
		t.Fatalf("a folder that is not there: %+v", ts)
	}
}
