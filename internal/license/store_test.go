// SPDX-License-Identifier: AGPL-3.0-or-later

package license

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// StateDir caches ~/.fox once per process, so these drive the store's pieces
// directly rather than fighting that. What they are about is the binding rules,
// not the path.

func TestSaveAndLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	path := filepath.Join(dir, "license.json")

	_, priv := testKeyPair(t)
	l := License{ID: "FB-1", Customer: "Acme", Edition: "enterprise",
		Features: []string{"anchors"}, IssuedAt: time.Now().UTC().Truncate(time.Second),
		NotAfter:    time.Now().UTC().Truncate(time.Second).AddDate(1, 0, 0),
		Fingerprint: "issued-for", RebindsAllowed: 3}
	Sign(&l, priv)

	if err := saveTo(path, l, "issued-for", 0); err != nil {
		t.Fatal(err)
	}
	got, boundTo, rebinds, err := loadFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if boundTo != "issued-for" || rebinds != 0 {
		t.Errorf("boundTo=%q rebinds=%d, want %q and 0", boundTo, rebinds, "issued-for")
	}
	// The licence half must come back byte-identical, or its signature stops
	// verifying the moment it is written and read.
	pub := priv.Public().(ed25519.PublicKey)
	if err := CheckSignature(got, pub); err != nil {
		t.Errorf("a licence did not survive being stored: %v", err)
	}
}

// The file holds a customer's name, which is theirs rather than ours to leave
// readable by every account on the machine.
func TestTheStoredLicenceIsNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "license.json")
	_, priv := testKeyPair(t)
	l := License{ID: "FB-1", Customer: "Acme"}
	Sign(&l, priv)
	if err := saveTo(path, l, "", 0); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode != 0o600 {
		t.Errorf("license.json is mode %o, want 600", mode)
	}
}

func TestRemovingWhatIsNotThereIsNotAnError(t *testing.T) {
	if err := removeAt(filepath.Join(t.TempDir(), "license.json")); err != nil {
		t.Errorf("removing a licence that is not installed returned %v; the end state was what was asked for", err)
	}
}

// The regression that running it found. A licence's own fingerprint is signed,
// so `fox license rebind` cannot change it — the first version of rebind wrote
// a new value beside the licence and then compared against the signed one, so
// it reported success and changed nothing. The binding that is compared has to
// be the stored one.
func TestRebindActuallyMovesTheBinding(t *testing.T) {
	pub, priv := testKeyPair(t)
	l := License{ID: "FB-1", Customer: "Acme", Edition: "enterprise",
		Features: []string{"anchors"}, IssuedAt: time.Now().Add(-time.Hour),
		NotAfter: time.Now().AddDate(1, 0, 0), Fingerprint: "machine-a"}
	Sign(&l, priv)

	// On machine B, bound as issued: a warning.
	if st := EvaluateBound(l, pub, l.Fingerprint, "machine-b", time.Now()); st.State != Warning {
		t.Fatalf("a licence issued for another machine is %v, want Warning", st.State)
	}
	// After a rebind, the binding is machine B and the warning is gone.
	st := EvaluateBound(l, pub, "machine-b", "machine-b", time.Now())
	if st.State != Active {
		t.Errorf("after rebinding, the licence is %v (%s) — rebind did nothing", st.State, st.Reason)
	}
	// And the licence still records where it was issued, which is what the
	// portal reconciles against.
	if l.Fingerprint != "machine-a" {
		t.Error("rebinding changed the signed fingerprint, which would break the signature")
	}
}

// Rebinding must not quietly extend a dead licence: expiry outranks the machine.
func TestRebindingDoesNotReviveALapsedLicence(t *testing.T) {
	pub, priv := testKeyPair(t)
	l := License{ID: "FB-1", Customer: "Acme", Features: []string{"anchors"},
		IssuedAt: time.Now().AddDate(-1, 0, 0),
		NotAfter: time.Now().Add(-Grace - 24*time.Hour), Fingerprint: "machine-a"}
	Sign(&l, priv)
	if st := EvaluateBound(l, pub, "machine-b", "machine-b", time.Now()); st.State != Lapsed {
		t.Errorf("a lapsed licence bound to this machine is %v, want Lapsed", st.State)
	}
}

func testKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}
