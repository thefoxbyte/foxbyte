// SPDX-License-Identifier: AGPL-3.0-or-later

package license

import (
	"fmt"
	"time"
)

// State is what a licence is doing right now, as distinct from whether it is
// genuine. CheckSignature answers "is this real"; this answers "what should the
// product do about it", and they are different questions with different
// consequences.
type State int

const (
	// Active: signed, in date, and for this machine.
	Active State = iota
	// Warning: something is wrong but within Grace, or the fingerprint does not
	// match. Everything still works and the user is told.
	Warning
	// Lapsed: past its expiry and past Grace. New paid work refuses; nothing
	// already running stops, and nothing already recorded becomes unreadable.
	Lapsed
	// Invalid: not signed by our key, or edited. Never unlocks anything, and
	// gets no grace — grace is for a customer who paid, not for a forgery.
	Invalid
)

func (s State) String() string {
	switch s {
	case Active:
		return "active"
	case Warning:
		return "active, with a warning"
	case Lapsed:
		return "lapsed"
	default:
		return "invalid"
	}
}

// Status is the whole answer: what state, why, and what a person should do.
type Status struct {
	State   State
	Reason  string // empty when Active
	Action  string // what would fix it, empty when there is nothing to fix
	License License
	// BoundTo is the machine the licence was compared against, which is not
	// always the one it was issued for. It is here because the answer is
	// meaningless without it: "this licence was activated on a different
	// machine" cannot be reported, recorded or renewed without saying which.
	BoundTo string
	// Rebinds is how many times that binding has moved. Only Current knows it —
	// it is kept beside the licence, not in it — so it is zero from a bare
	// EvaluateBound.
	Rebinds int
}

// Unlocks reports whether a feature may run. Warning unlocks: that is the whole
// point of a warning. Lapsed and Invalid do not.
func (s Status) Unlocks() bool { return s.State == Active || s.State == Warning }

// Evaluate decides a licence's state at a moment, for a machine.
//
// fingerprint is this machine's; an empty one means we could not read it, which
// must never be treated as a mismatch — failing to identify the machine is our
// problem, not the customer's, and locking them out for it would be the worst
// possible reading.
func Evaluate(l License, pub []byte, machine string, now time.Time) Status {
	return EvaluateBound(l, pub, l.Fingerprint, machine, now)
}

// EvaluateBound is Evaluate against a binding that may have moved.
//
// A licence's own fingerprint is signed, so `fox license rebind` cannot change
// it — an early version tried, and silently did nothing. The binding that is
// compared therefore lives beside the licence: it starts as the issued one and
// a rebind moves it. The licence still says which machine it was issued for,
// which is what the portal reconciles against.
func EvaluateBound(l License, pub []byte, boundTo, machine string, now time.Time) Status {
	st := evaluateBound(l, pub, boundTo, machine, now)
	// Set once here rather than in each of the returns below, so a new state
	// cannot be added that forgets it.
	st.BoundTo = boundTo
	return st
}

func evaluateBound(l License, pub []byte, boundTo, machine string, now time.Time) Status {
	if err := CheckSignature(l, pub); err != nil {
		return Status{State: Invalid, Reason: err.Error(),
			Action: "ask for a replacement licence", License: l}
	}
	if !l.NotAfter.IsZero() && now.After(l.NotAfter) {
		if now.Before(l.NotAfter.Add(Grace)) {
			left := l.NotAfter.Add(Grace).Sub(now).Round(time.Hour)
			return Status{State: Warning, License: l,
				Reason: fmt.Sprintf("the licence expired on %s", l.NotAfter.UTC().Format("2 January 2006")),
				Action: fmt.Sprintf("renew it within %s, after which the paid features stop", humanDuration(left))}
		}
		return Status{State: Lapsed, License: l,
			Reason: fmt.Sprintf("the licence expired on %s", l.NotAfter.UTC().Format("2 January 2006")),
			Action: "renew it — nothing already recorded is affected, and the databases keep running"}
	}
	// A fingerprint that does not match warns and no more. A rebuilt VM, a
	// replaced disk and a new laptop all land here, and none of them is a
	// licence problem.
	if boundTo != "" && machine != "" && boundTo != machine {
		return Status{State: Warning, License: l,
			Reason: "this licence was activated on a different machine",
			Action: "run `fox license rebind` to move it here"}
	}
	return Status{State: Active, License: l}
}

func humanDuration(d time.Duration) string {
	if days := int(d.Hours() / 24); days >= 1 {
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	}
	h := int(d.Hours())
	if h <= 1 {
		return "an hour"
	}
	return fmt.Sprintf("%d hours", h)
}
