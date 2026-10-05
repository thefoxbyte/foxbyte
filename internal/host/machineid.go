// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// MachineID identifies the computer a licence was activated on.
//
// Four things about it, each of which is a decision rather than an accident.
//
// It is READ ON THE HOST, never in the VM. On macOS and Windows the engine
// lives in Lima or WSL, and recreating that VM is an ordinary repair step —
// `fox setup` does it. Fingerprinting the guest would mean a routine fix looked
// exactly like licence evasion, so `license` belongs in localCommands beside
// `version` and `setup`.
//
// It is HASHED with a domain separator, and the hash is the only form that ever
// leaves this machine. The raw value is an identifier the operating system uses
// elsewhere; hashing it with a string nobody else uses means the fingerprint
// cannot be lined up against anything that hashes the same identifier for its
// own purposes.
//
// It is ALLOWED TO FAIL. An empty return is not a mismatch and must never be
// read as one — see license.Evaluate. If `ioreg` is missing or a registry read
// is refused, that is our problem, and locking a paying customer out of the
// features they bought because of it would be the worst available reading.
//
// It is STABLE, not unique-to-a-person. It identifies a machine so a licence
// can say which one it was activated for. It is not an advertising identifier
// and nothing else should use it.
const fingerprintDomain = "foxbyte-machine-id/1\n"

// MachineID returns the hashed identifier of this computer, or "" if it cannot
// be read. Callers must treat "" as "unknown", never as "wrong".
func MachineID() string {
	raw := strings.TrimSpace(rawMachineID())
	if raw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(fingerprintDomain + strings.ToLower(raw)))
	// Half of SHA-256 is the same length the anchor format uses for a key id,
	// and is far beyond what distinguishing a few thousand machines needs.
	return hex.EncodeToString(sum[:16])
}
