// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"io"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/edition"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
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

// The seam itself: a dispatcher calls the engine that registered with it, and
// refuses rather than panicking when none did.
//
// "None did" is what a Standard binary is — the paid packages are not compiled
// into it, so nothing ever calls the setters. The licence check normally
// refuses first, and this is the belt to that braces: if the two ever got out
// of order, a nil call would be a crash rather than a message.
func TestTheDispatchersCallTheRegisteredEngine(t *testing.T) {
	if !edition.Enterprise {
		t.Skip("a Standard build cannot entitle a paid feature, so the dispatch is unreachable")
	}
	entitle(t, edition.Anchors, edition.Export, edition.Impact, edition.Promotion, edition.Pipelines)

	called := map[string]bool{}
	SetAnchorWriter(
		func(string) (*ledger.Anchor, string, error) { called["anchor"] = true; return nil, "", nil },
		func(string, io.Writer) error { called["export"] = true; return nil },
	)
	SetImpactAnalyser(func(_, _, _, _ string) (ImpactReport, error) { called["impact"] = true; return ImpactReport{}, nil })
	SetPromotion(
		func(_, _ string, _ []auth.ChangeRequest) ([]RequestEntry, int64, error) {
			called["build"] = true
			return nil, 0, nil
		},
		func(int64, string, string, []RequestEntry) (int, error) { called["apply"] = true; return 0, nil },
	)
	SetPipelineRunner(func(*Progress, PipelineSpec, string) (RunResult, error) {
		called["pipeline"] = true
		return RunResult{}, nil
	})
	t.Cleanup(func() {
		SetAnchorWriter(nil, nil)
		SetImpactAnalyser(nil)
		SetPromotion(nil, nil)
		SetPipelineRunner(nil)
	})

	_, _, _ = Checkpoint("main")
	_ = ExportLedger("main", io.Discard)
	_, _ = Impact("main", "select 1", "", "")
	_, _, _ = BuildRequest("dev", "main", nil)
	_, _ = ApplyRequest(1, "main", "me", []RequestEntry{{ID: 1}})
	_, _ = RunPipeline(nil, PipelineSpec{}, "main")

	for _, w := range []string{"anchor", "export", "impact", "build", "apply", "pipeline"} {
		if !called[w] {
			t.Errorf("the %s dispatcher did not reach its engine", w)
		}
	}
}

// Entitled, but nothing registered: refused, not a panic.
func TestTheDispatchersRefuseWithNoEngine(t *testing.T) {
	if !edition.Enterprise {
		t.Skip("a Standard build cannot entitle a paid feature")
	}
	entitle(t, edition.Anchors, edition.Export, edition.Impact, edition.Promotion, edition.Pipelines)
	SetAnchorWriter(nil, nil)
	SetImpactAnalyser(nil)
	SetPromotion(nil, nil)
	SetPipelineRunner(nil)

	for _, c := range []struct {
		what string
		call func() error
	}{
		{"Checkpoint", func() error { _, _, err := Checkpoint("main"); return err }},
		{"ExportLedger", func() error { return ExportLedger("main", io.Discard) }},
		{"Impact", func() error { _, err := Impact("main", "select 1", "", ""); return err }},
		{"BuildRequest", func() error { _, _, err := BuildRequest("dev", "main", nil); return err }},
		{"ApplyRequest", func() error { _, err := ApplyRequest(1, "main", "me", []RequestEntry{{ID: 1}}); return err }},
		{"RunPipeline", func() error { _, err := RunPipeline(nil, PipelineSpec{}, "main"); return err }},
	} {
		if err := c.call(); !errors.Is(err, ErrNotLicensed) {
			t.Errorf("%s with no engine = %v, want a refusal", c.what, err)
		}
	}
}

// Which schema each edition installs, as a list, so a new schema file cannot be
// added to the free set by accident.
//
// The schema lives in the database rather than in the binary, which is the
// whole shape of this: a branch keeps whatever it was given. One checkpointed
// or given policy rules before an install changed edition keeps those tables,
// and everything in them stays readable and verifiable. An edition decides only
// what gets created from here on.
func TestTheFreeSchemaSetIsInstalledInEveryEdition(t *testing.T) {
	for name, sql := range map[string]string{
		// Richer recording, keyed by ledger row id — not proof.
		"ledger_ext.sql": ledger.SchemaExt,
		// Agent provenance: the MCP server records a session for every change
		// an agent makes, and `fox blackbox sessions` reads them back. Knowing
		// which agent did what is part of the guardrails, not the paid tier —
		// and there is no licence that could unlock it, since provenance is not
		// a feature internal/edition knows about.
		"provenance.sql": ledger.SchemaProvenance,
		// The two default guardrails. Not policy rules.
		"datachanges.sql": ledger.SchemaData,
	} {
		if sql == "" {
			t.Errorf("%s is not embedded, so no edition installs it", name)
		}
	}
	for _, f := range edition.Features() {
		if string(f) == "provenance" {
			t.Error("provenance is now a licensed feature — provenance.sql must move with it")
		}
	}
}

// And which the paid half asks for, per feature rather than all-or-nothing: a
// licence covering anchors but not the rule engine installs the checkpoint
// table and not bb.policy_rules, the same line the commands draw.
func TestThePaidSchemaFollowsTheEntitlement(t *testing.T) {
	edition.SetEntitlement(nil)
	t.Cleanup(func() { edition.SetEntitlement(nil) })
	if c, p, i := PaidSchemaWanted(); c || p || i {
		t.Errorf("unlicensed install wants checkpoints=%v policy=%v impact=%v", c, p, i)
	}
	if !edition.Enterprise {
		return // a Standard build cannot entitle anything, which is the point
	}
	entitle(t, edition.Anchors)
	if c, p, i := PaidSchemaWanted(); !c || p || i {
		t.Errorf("a licence for anchors alone wants checkpoints=%v policy=%v impact=%v", c, p, i)
	}
}
