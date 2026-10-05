// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"strings"
	"testing"
)

// The fingerprint has to be the same every time or a licence stops matching the
// machine it was activated on after a restart.
func TestMachineIDIsStable(t *testing.T) {
	a := MachineID()
	if a == "" {
		t.Skip("no machine id readable here; MachineID is allowed to fail and callers treat that as unknown")
	}
	if b := MachineID(); a != b {
		t.Errorf("MachineID changed between two calls: %q then %q", a, b)
	}
}

// Hashed, and hex, so it can be pasted into a portal or an e-mail without
// carrying the operating system's own identifier out of the machine.
func TestMachineIDIsAHash(t *testing.T) {
	id := MachineID()
	if id == "" {
		t.Skip("no machine id readable here")
	}
	if len(id) != 32 {
		t.Errorf("fingerprint is %d characters, want 32 (16 bytes of SHA-256 in hex): %q", len(id), id)
	}
	if strings.ContainsAny(id, "-") || strings.ToLower(id) != id {
		t.Errorf("fingerprint %q is not lowercase hex — a raw UUID may be leaking through unhashed", id)
	}
	for _, c := range id {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("fingerprint %q contains %q, which is not hex", id, c)
		}
	}
}

// The raw identifier must never be the thing we hand out. If the hash ever
// contained it, a fingerprint would be reversible to an OS-level id by anyone
// who saw one.
func TestTheRawIdentifierIsNotInTheFingerprint(t *testing.T) {
	raw := strings.TrimSpace(rawMachineID())
	if raw == "" {
		t.Skip("no machine id readable here")
	}
	id := MachineID()
	if strings.Contains(strings.ToLower(id), strings.ToLower(raw)) {
		t.Error("the fingerprint contains the raw machine identifier")
	}
	// The domain separator is what stops this value matching a hash of the same
	// identifier made by something else for its own purposes.
	if !strings.HasPrefix(fingerprintDomain, "foxbyte-machine-id/") {
		t.Errorf("the hash is not domain-separated: %q", fingerprintDomain)
	}
}
