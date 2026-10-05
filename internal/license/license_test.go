// SPDX-License-Identifier: AGPL-3.0-or-later

package license

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/edition"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func valid(t *testing.T, priv ed25519.PrivateKey) License {
	t.Helper()
	l := License{
		ID: "FB-0001", Customer: "Acme Ltd", Edition: "enterprise",
		Features:    []string{"anchors", "export"},
		IssuedAt:    time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:    time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC),
		Fingerprint: "abc123", RebindsAllowed: 3,
	}
	Sign(&l, priv)
	return l
}

func TestASignedLicenceVerifies(t *testing.T) {
	pub, priv := testKey(t)
	if err := CheckSignature(valid(t, priv), pub); err != nil {
		t.Fatalf("a licence we just signed does not verify: %v", err)
	}
}

// Every signed field has to be covered, or a customer could edit the one that
// is not. The loop is the test: it mutates each in turn and expects a refusal.
func TestEditingAnyFieldBreaksTheSignature(t *testing.T) {
	pub, priv := testKey(t)
	for name, edit := range map[string]func(*License){
		"id":              func(l *License) { l.ID = "FB-0002" },
		"customer":        func(l *License) { l.Customer = "Someone Else" },
		"edition":         func(l *License) { l.Edition = "standard" },
		"features":        func(l *License) { l.Features = append(l.Features, "realtime") },
		"issued_at":       func(l *License) { l.IssuedAt = l.IssuedAt.Add(time.Hour) },
		"not_after":       func(l *License) { l.NotAfter = l.NotAfter.AddDate(10, 0, 0) },
		"fingerprint":     func(l *License) { l.Fingerprint = "someone-elses-machine" },
		"rebinds_allowed": func(l *License) { l.RebindsAllowed = 9999 },
	} {
		l := valid(t, priv)
		edit(&l)
		if err := CheckSignature(l, pub); err == nil {
			t.Errorf("editing %s left the signature valid — that field is not covered by the payload", name)
		}
	}
}

// Extending the expiry by ten years is the edit anyone would try first.
func TestTheObviousForgeryIsRefused(t *testing.T) {
	pub, priv := testKey(t)
	l := valid(t, priv)
	l.NotAfter = time.Now().AddDate(10, 0, 0)
	st := Evaluate(l, pub, "abc123", time.Now())
	if st.State != Invalid {
		t.Fatalf("a licence with its expiry moved is %v, want Invalid", st.State)
	}
	if st.Unlocks() {
		t.Error("it unlocked features anyway")
	}
}

func TestAnotherKeysLicenceIsRefused(t *testing.T) {
	pub, _ := testKey(t)
	_, otherPriv := testKey(t)
	l := valid(t, otherPriv)
	err := CheckSignature(l, pub)
	if err == nil {
		t.Fatal("a licence signed by another key was accepted")
	}
	if !strings.Contains(err.Error(), "different FoxByte") {
		t.Errorf("the refusal should say whose key it is, got %q", err)
	}
}

// The states, and what each one may do. This is the behaviour the product was
// designed around: a billing event must never become an outage.
func TestExpiryWarnsBeforeItRefuses(t *testing.T) {
	pub, priv := testKey(t)
	l := valid(t, priv)
	expiry := l.NotAfter

	for _, c := range []struct {
		when    time.Time
		want    State
		unlocks bool
		what    string
	}{
		{expiry.Add(-24 * time.Hour), Active, true, "the day before expiry"},
		{expiry.Add(time.Hour), Warning, true, "an hour after expiry"},
		{expiry.Add(Grace - time.Hour), Warning, true, "the last hour of grace"},
		{expiry.Add(Grace + time.Hour), Lapsed, false, "an hour past grace"},
	} {
		st := Evaluate(l, pub, "abc123", c.when)
		if st.State != c.want {
			t.Errorf("%s: state %v, want %v", c.what, st.State, c.want)
		}
		if st.Unlocks() != c.unlocks {
			t.Errorf("%s: unlocks=%v, want %v", c.what, st.Unlocks(), c.unlocks)
		}
	}
}

// A machine that does not match is a rebuilt VM far more often than it is
// piracy, and we cannot tell the difference offline. So it warns, and says what
// to do, and everything keeps working.
func TestADifferentMachineWarnsAndKeepsWorking(t *testing.T) {
	pub, priv := testKey(t)
	st := Evaluate(valid(t, priv), pub, "a-different-machine", time.Now())
	if st.State != Warning {
		t.Fatalf("state %v, want Warning", st.State)
	}
	if !st.Unlocks() {
		t.Error("a fingerprint mismatch stopped the paid features — it must not")
	}
	if !strings.Contains(st.Action, "rebind") {
		t.Errorf("the warning should name the way out, got %q", st.Action)
	}
}

// Failing to read the machine id is our problem. Treating it as a mismatch
// would lock out a user because we could not run ioreg.
func TestAnUnreadableMachineIDIsNotAMismatch(t *testing.T) {
	pub, priv := testKey(t)
	if st := Evaluate(valid(t, priv), pub, "", time.Now()); st.State != Active {
		t.Fatalf("an empty fingerprint gave %v (%s), want Active", st.State, st.Reason)
	}
}

// A licence with no machine in it is a site licence and runs anywhere.
func TestASiteLicenceRunsAnywhere(t *testing.T) {
	pub, priv := testKey(t)
	l := License{ID: "FB-SITE", Customer: "Acme", Edition: "enterprise",
		Features: []string{"anchors"}, IssuedAt: time.Now().Add(-time.Hour),
		NotAfter: time.Now().AddDate(1, 0, 0)}
	Sign(&l, priv)
	if st := Evaluate(l, pub, "whatever-machine", time.Now()); st.State != Active {
		t.Fatalf("a licence with no fingerprint gave %v (%s)", st.State, st.Reason)
	}
}

// The payload is a wire format: the signature is over these bytes, so a change
// to the order or the separators invalidates every licence ever issued. This
// pins it.
func TestSigningPayloadIsStable(t *testing.T) {
	l := License{
		ID: "FB-0001", Customer: "Acme Ltd", Edition: "enterprise",
		Features:    []string{"export", "anchors"}, // deliberately unsorted
		IssuedAt:    time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:    time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC),
		Fingerprint: "abc123", RebindsAllowed: 3, KeyID: "deadbeef",
	}
	want := "foxbyte-license/1\nFB-0001\nAcme Ltd\nenterprise\nanchors,export\n" +
		"2026-10-01T00:00:00Z\n2027-10-01T00:00:00Z\nabc123\n3\ndeadbeef\n"
	if got := string(SigningPayload(l)); got != want {
		t.Errorf("the signing payload changed.\n got: %q\nwant: %q\n"+
			"Every licence already issued is signed over the old bytes.", got, want)
	}
}

// Sorting is not cosmetic: two orderings of the same features must produce the
// same signature, or re-serialising a licence breaks it.
func TestFeatureOrderDoesNotChangeTheSignature(t *testing.T) {
	a := License{Features: []string{"anchors", "export"}}
	b := License{Features: []string{"export", "anchors"}}
	if string(SigningPayload(a)) != string(SigningPayload(b)) {
		t.Error("feature order changes the payload, so the same licence can fail to verify")
	}
}

// A newer licence on an older binary should unlock what that binary knows and
// ignore the rest, rather than refusing wholesale.
func TestAnUnknownFeatureIsIgnoredNotFatal(t *testing.T) {
	l := License{Features: []string{"anchors", "something-from-next-year"}}
	if !l.Has(edition.Anchors) {
		t.Error("a known feature stopped working because an unknown one sat beside it")
	}
	if l.Has(edition.Realtime) {
		t.Error("a feature that is not listed was reported as licensed")
	}
}

// A build with no key cannot tell a real licence from a forged one, so it must
// accept neither.
func TestABuildWithNoKeyRefusesEverything(t *testing.T) {
	saved := licensePublicKey
	licensePublicKey = ""
	defer func() { licensePublicKey = saved }()
	if _, err := PublicKey(); err == nil {
		t.Fatal("a build with no licence key returned one")
	}
}

// The whole journey a customer's licence makes: minted, written as JSON,
// e-mailed, read back, checked. A signature over a canonical payload survives
// that; a signature over the JSON itself would not, because two encoders do not
// have to agree on spacing.
func TestALicenceSurvivesJSON(t *testing.T) {
	pub, priv := testKey(t)
	l := valid(t, priv)

	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var back License
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if err := CheckSignature(back, pub); err != nil {
		t.Fatalf("a licence did not survive a round trip through JSON: %v", err)
	}
	if st := Evaluate(back, pub, "abc123", time.Now()); st.State != Active {
		t.Fatalf("round-tripped licence is %v: %s", st.State, st.Reason)
	}
}

// The private key must never be committable. The release key has this guard by
// having been forgotten once; this one gets it on the first day, because a
// leaked licence key mints Enterprise for anyone and nothing would ever say so.
func TestTheSigningKeyIsGitignored(t *testing.T) {
	b, err := os.ReadFile("../../.gitignore")
	if err != nil {
		t.Fatal(err)
	}
	const keyFile = "license-signing.key"
	found := false
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == keyFile {
			found = true
		}
	}
	if !found {
		t.Errorf(".gitignore does not list %q — `make license-key` writes the private "+
			"key there, and an accidental commit of it is unrecoverable: every licence "+
			"ever issued would have to be reissued under a new key", keyFile)
	}
}
