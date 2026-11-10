// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Masked branches (F5, Gate 1 step 5).

func tempMaskedBranches(t *testing.T) {
	t.Helper()
	tempMaskFiles(t)
	dir := t.TempDir()
	oldP, oldAlive := maskedBranchPath, processAlive
	t.Cleanup(func() {
		maskedBranchPath, processAlive = oldP, oldAlive
		maskedBranches.byName = nil
	})
	maskedBranchPath = func() string { return filepath.Join(dir, "masked-branches.json") }
}

// Closed from the first moment: being made, it is refused, saying how far it
// got; stopped part way (its process gone), it says so and how to start
// again; failed, it says what verifying found; open, it is anyone's.
func TestMaskedBranchClosedUntilOpen(t *testing.T) {
	tempMaskedBranches(t)
	if err := checkBranchOpen("dev"); err != nil || IsMaskedBranch("dev") {
		t.Fatalf("an ordinary branch: %v", err)
	}
	alive := true
	processAlive = func(int) bool { return alive }
	rec := MaskedBranch{Name: "safe", From: "main", State: MaskedMaking, Step: "masking 2 table(s) in place", PID: 4242, Fork: 17}
	if err := putMaskedBranch(rec); err != nil {
		t.Fatal(err)
	}
	err := checkBranchOpen("safe")
	if !errors.Is(err, ErrBranchClosed) || !strings.Contains(err.Error(), "is being masked (masking 2 table(s) in place)") {
		t.Fatalf("being made: %v", err)
	}
	if _, err := EnsureRunning("safe"); !errors.Is(err, ErrBranchClosed) {
		t.Fatalf("EnsureRunning, every client's way in, lets it through: %v", err)
	}
	alive = false
	if err := checkBranchOpen("safe"); !errors.Is(err, ErrBranchClosed) || !strings.Contains(err.Error(), "stopped part way") ||
		!strings.Contains(err.Error(), "branch create safe --masked --from main") {
		t.Fatalf("stopped part way: %v", err)
	}
	if MaskedBranches()[0].State != MaskedFailed || maskedStateOf("safe") != MaskedFailed {
		t.Error("a making whose process is gone is listed as running")
	}
	rec.State, rec.PID, rec.Problems = MaskedFailed, 0, []string{"public.logins.login holds email with no rule masking it"}
	_ = putMaskedBranch(rec)
	if err := checkBranchOpen("safe"); !strings.Contains(err.Error(), "public.logins.login holds email") {
		t.Fatalf("failed: %v", err)
	}
	if _, ok := MaskedBranchFork("safe"); ok {
		t.Error("a branch not open gives a fork to promote from")
	}
	rec.State, rec.Problems = MaskedOpen, nil
	_ = putMaskedBranch(rec)
	if err := checkBranchOpen("safe"); err != nil {
		t.Fatalf("open: %v", err)
	}
	if f, ok := MaskedBranchFork("safe"); !ok || f != 17 {
		t.Errorf("the fork: %d %v", f, ok)
	}
	forgetMaskedBranch("safe")
	if IsMaskedBranch("safe") {
		t.Error("forgotten, still listed")
	}
}

// On an open masked branch nobody is masked (its data is), and it never has
// the key; elsewhere a masked account still is.
func TestMaskedBranchNobodyMasked(t *testing.T) {
	tempMaskedBranches(t)
	old := MaskKeyDir
	t.Cleanup(func() { MaskKeyDir = old })
	dir := filepath.Join(t.TempDir(), "mask")
	MaskKeyDir = func() string { return dir }
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := SaveMaskedAccounts([]MaskedAccount{{Email: "m@x.io"}}); err != nil {
		t.Fatal(err)
	}
	_ = putMaskedBranch(MaskedBranch{Name: "safe", From: "main", State: MaskedMaking})
	if maskMount("safe") != nil || maskMount("dev") == nil {
		t.Error("the key: never on a masked branch, even while it is made; on others")
	}
	if !accountMasked("safe", "m@x.io") {
		t.Error("masked while the branch is not open yet")
	}
	_ = putMaskedBranch(MaskedBranch{Name: "safe", From: "main", State: MaskedOpen})
	if accountMasked("safe", "m@x.io") || !accountMasked("main", "m@x.io") {
		t.Error("on an open masked branch nobody is masked; on main the account still is")
	}
}

// A copy of an open masked branch is one too, recorded before its container
// starts; a copy of one not open is refused.
func TestInheritMasked(t *testing.T) {
	tempMaskedBranches(t)
	if err := inheritMasked("child", "dev"); err != nil || IsMaskedBranch("child") {
		t.Fatalf("a copy of an ordinary branch: %v", err)
	}
	_ = putMaskedBranch(MaskedBranch{Name: "safe", From: "main", State: MaskedOpen, Fork: 9, Rules: []MaskRule{{Table: "t", Column: "e"}}})
	if err := inheritMasked("child", "safe"); err != nil {
		t.Fatal(err)
	}
	c, ok := MaskedBranchOf("child")
	if !ok || !c.Inherited || c.State != MaskedOpen || c.Fork != 9 || len(c.Rules) != 1 || c.From != "safe" {
		t.Fatalf("the copy's record: %+v", c)
	}
	_ = putMaskedBranch(MaskedBranch{Name: "half", From: "main", State: MaskedFailed, Error: "x"})
	if err := inheritMasked("child2", "half"); !errors.Is(err, ErrBranchClosed) {
		t.Fatalf("a copy of a closed one: %v", err)
	}
}

// Without Enterprise's masker a masked branch is refused as not licensed, and
// nothing is recorded.
func TestCreateMaskedNotLicensed(t *testing.T) {
	tempMaskedBranches(t)
	old := masker
	t.Cleanup(func() { masker = old })
	masker = nil
	if _, err := CreateMasked("safe", "main", "cli:a", nil); !errors.Is(err, ErrNotLicensed) {
		t.Fatalf("not licensed: %v", err)
	}
	if IsMaskedBranch("safe") {
		t.Error("recorded without the licence")
	}
}
