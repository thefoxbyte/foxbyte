// SPDX-License-Identifier: AGPL-3.0-or-later

package license

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// Where an activated licence lives, beside the install's other state.
//
// Mode 0600 in a 0700 directory: it is not a secret — it unlocks nothing
// without the signature, and the signature is checked against a key only we
// hold — but it names a customer, and that is theirs rather than ours to
// publish.
func Path() string { return brand.StatePath(FileName) }

// FileName is the licence's name inside the state directory. It is named
// because the engine is given a copy of this file by name on macOS and
// Windows, where it runs in the VM with a state directory of its own.
const FileName = "license.json"

// stored is the licence plus what we learned locally about it. The licence half
// is signed and must be written back byte-identical; the rest is ours.
type stored struct {
	License     License   `json:"license"`
	ActivatedAt time.Time `json:"activated_at"`
	// BoundTo is the machine this licence is *currently* for, which is not
	// always the one it was issued for.
	//
	// The licence's own fingerprint is signed and therefore fixed: no local
	// command can change it, and an early version of rebind quietly did nothing
	// because of that. So the binding that is compared lives here, starting as
	// the issued one and moved by `fox license rebind`.
	//
	// That a user could edit this file is not an objection. The lock is soft by
	// decision — a mismatch warns and keeps working — so this was never the
	// thing stopping anybody. What it is, is the record: the licence says which
	// machine it was issued for, this says where it ended up, and the count
	// below says how often that changed. The portal reconciles the three, and
	// it is the only place that can.
	BoundTo string `json:"bound_to"`
	// Rebinds counts how many times the machine changed. It is kept for the
	// record and deliberately not enforced here: this file is removed by
	// `fox uninstall`, so a local count was never a limit anyone could rely on.
	// The portal counts machines per account, which is the only place that can.
	Rebinds int `json:"rebinds"`
}

// ErrNone means no licence is installed. It is not a failure: a Standard
// install has none, and an Enterprise build without one behaves like Standard
// on purpose.
var ErrNone = errors.New("no licence is installed")

// Load reads the installed licence. It does not check it — Evaluate does that,
// and the caller needs the licence either way to say what is wrong with it.
func Load() (License, string, int, error) { return loadFrom(Path()) }

func loadFrom(path string) (License, string, int, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return License{}, "", 0, ErrNone
	}
	if err != nil {
		return License{}, "", 0, err
	}
	var s stored
	if err := json.Unmarshal(b, &s); err != nil {
		return License{}, "", 0, fmt.Errorf("%s is not readable as a licence: %w", path, err)
	}
	return s.License, s.BoundTo, s.Rebinds, nil
}

// Save writes a licence as the installed one, bound to boundTo.
func Save(l License, boundTo string, rebinds int) error { return saveTo(Path(), l, boundTo, rebinds) }

func saveTo(path string, l License, boundTo string, rebinds int) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(stored{
		License: l, ActivatedAt: time.Now().UTC().Truncate(time.Second),
		BoundTo: boundTo, Rebinds: rebinds,
	}, "", "  ")
	if err != nil {
		return err
	}
	// Temp file plus rename, so a reader never sees half a licence — the same
	// way the install's secrets are written.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Remove deletes the installed licence. Removing one that is not there is not
// an error: the end state is what was asked for.
func Remove() error { return removeAt(Path()) }

func removeAt(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Current is the whole picture: the installed licence, checked, against this
// machine, now. Everything that asks "may this run" goes through here.
func Current(machine string) (Status, error) {
	l, boundTo, rebinds, err := Load()
	if err != nil {
		return Status{}, err
	}
	pub, err := PublicKey()
	if err != nil {
		return Status{}, err
	}
	st := EvaluateBound(l, pub, boundTo, machine, time.Now())
	st.Rebinds = rebinds
	return st, nil
}
