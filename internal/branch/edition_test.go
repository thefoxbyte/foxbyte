// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// The whole table, in one place: which functions refuse without a licence.
//
// Each gate sits on the function that performs the action rather than only at
// the CLI and the REST route, so that a third caller — the scheduler is already
// one — cannot use a paid feature by not knowing about it. This is the test
// that would catch a new entry point added without a gate, by failing when
// someone removes one.
func TestTheGatedFunctionsRefuseWithoutALicence(t *testing.T) {
	edition.SetEntitlement(nil)
	t.Cleanup(func() { edition.SetEntitlement(nil) })

	for _, c := range []struct {
		what string
		call func() error
		want error
	}{
		{"Checkpoint", func() error { _, _, err := Checkpoint("main"); return err }, ErrAnchorsNotLicensed},
		{"AddPolicyRule", func() error { return AddPolicyRule("main", PolicyRule{RuleID: "r"}, "me") }, ErrPolicyNotLicensed},
		{"UpdatePolicyRule", func() error { return UpdatePolicyRule("main", "r", nil, nil, "me") }, ErrPolicyNotLicensed},
		{"RemovePolicyRule", func() error { return RemovePolicyRule("main", "r", "me") }, ErrPolicyNotLicensed},
		{"Impact", func() error { _, err := Impact("main", "select 1", "", ""); return err }, ErrImpactNotLicensed},
		{"ExportLedger", func() error { return ExportLedger("main", nil) }, ErrExportNotLicensed},
		{"ApplyRequest", func() error { _, err := ApplyRequest(1, "main", "me", nil); return err }, ErrPromotionNotLicensed},
		{"RunPipeline", func() error { _, err := RunPipeline(nil, PipelineSpec{}, "main"); return err }, ErrPipelinesNotLicensed},
	} {
		err := c.call()
		if !errors.Is(err, c.want) {
			t.Errorf("%s() = %v, want %v", c.what, err, c.want)
		}
		// And every one of them answers the generic question too, so a caller
		// can ask "was this the licence?" without naming the feature.
		if !errors.Is(err, ErrNotLicensed) {
			t.Errorf("%s() = %v, which does not match ErrNotLicensed", c.what, err)
		}
	}
}

// The other half of the line: reading is free. These are the functions a person
// still needs after an install changes edition — the rule that just blocked
// them, the record of what happened, the request left open. None of them may
// refuse on the licence.
//
// They are called without a database, so they fail; what is asserted is that
// they never fail for *this* reason.
func TestReadingIsNeverRefusedOnTheLicence(t *testing.T) {
	edition.SetEntitlement(nil)
	t.Cleanup(func() { edition.SetEntitlement(nil) })

	for _, c := range []struct {
		what string
		call func() error
	}{
		{"PolicyRules", func() error { _, err := PolicyRules("main"); return err }},
		{"PolicyCheck", func() error { _, _, err := PolicyCheck("main", "select 1"); return err }},
		{"PolicyEvaluations", func() error { _, err := PolicyEvaluations("main", 10); return err }},
		{"Integrity", func() error { _, err := Integrity("main"); return err }},
	} {
		if err := c.call(); errors.Is(err, ErrNotLicensed) {
			t.Errorf("%s() was refused on the licence: %v", c.what, err)
		}
	}
}

// A Standard build cannot be talked into any of them, whatever a licence
// claims. The code for these features is compiled into both binaries today —
// unlike the code under enterprise/ — so the entitlement is the whole of the
// gate, and this is the test that says so.
func TestAStandardBuildCannotBeEntitled(t *testing.T) {
	if edition.Enterprise {
		t.Skip("this build contains the paid code; the Standard build is the one under test")
	}
	edition.SetEntitlement(func(edition.Feature) bool { return true }) // a licence saying yes to everything
	t.Cleanup(func() { edition.SetEntitlement(nil) })

	for _, f := range edition.Features() {
		if edition.Has(f) {
			t.Errorf("a Standard build reports %q as available", f)
		}
	}
	if _, _, err := Checkpoint("main"); !errors.Is(err, ErrNotLicensed) {
		t.Errorf("a Standard build anchored on a licence's say-so: %v", err)
	}
}
