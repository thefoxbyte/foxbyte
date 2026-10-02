// SPDX-License-Identifier: AGPL-3.0-or-later

package edition

import "testing"

// An Enterprise build with no licence must behave exactly like a Standard one.
// That is the property that stops a build unlocking itself, so it is a test
// rather than a hope: Has consults the licence layer, and there is no licence
// layer until one is installed.
func TestHasNeedsBothTheBuildAndALicence(t *testing.T) {
	t.Cleanup(func() { SetEntitlement(nil) })

	SetEntitlement(nil)
	for _, f := range Features() {
		if Has(f) {
			t.Errorf("%s is available with no licence installed", f)
		}
	}
	if len(Available()) != 0 {
		t.Errorf("Available() reported %v with no licence installed", Available())
	}

	// A licence that grants everything still grants nothing in a Standard build.
	SetEntitlement(func(Feature) bool { return true })
	for _, f := range Features() {
		if got := Has(f); got != Enterprise {
			t.Errorf("Has(%s) = %v in the %s edition, want %v", f, got, Name(), Enterprise)
		}
	}
}

// A licence names specific features, so one being granted must not carry the
// others with it.
func TestALicenceGrantsOnlyWhatItNames(t *testing.T) {
	if !Enterprise {
		t.Skip("Standard build: Has is false for everything, covered above")
	}
	t.Cleanup(func() { SetEntitlement(nil) })
	SetEntitlement(func(f Feature) bool { return f == Realtime })

	if !Has(Realtime) {
		t.Error("realtime was licensed but is not available")
	}
	for _, f := range Features() {
		if f != Realtime && Has(f) {
			t.Errorf("%s is available although only realtime was licensed", f)
		}
	}
}

func TestNameMatchesTheBuild(t *testing.T) {
	want := "standard"
	if Enterprise {
		want = "enterprise"
	}
	if Name() != want {
		t.Errorf("Name() = %q, want %q", Name(), want)
	}
}

// Every feature needs a sentence, because Describe's output goes straight into
// the message a user sees when something is refused.
func TestEveryFeatureDescribesItself(t *testing.T) {
	for _, f := range Features() {
		if d := Describe(f); d == "" || d == string(f) {
			t.Errorf("%s has no description, so a refusal would name the identifier", f)
		}
	}
	if got := Describe(Feature("nonesuch")); got != "nonesuch" {
		t.Errorf("an unknown feature should describe itself, got %q", got)
	}
}
