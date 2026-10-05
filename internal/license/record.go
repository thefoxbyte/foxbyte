// SPDX-License-Identifier: AGPL-3.0-or-later

package license

import (
	"fmt"
	"log"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

// The security log's account of this install's entitlement: when the paid
// features became available, when they moved machine, and when they stopped.
//
// Two decisions shape all of it.
//
// **The engine records, not the command.** `fox license activate` runs on the
// host, and on macOS and Windows the host has no store to chain an event onto.
// But the better reason is that an auditor is asking which features this engine
// honoured, and only the engine can answer that. So the licence commands change
// the file and the engine records what it then honoured.
//
// **It records only at start-up, and that is deliberate.** An entitlement is
// established once, when the process starts: edition.Has answers from what
// Install decided, and nothing re-reads the licence while the server runs. A
// watcher that noticed a licence expiring at 3am and wrote "lapsed" would be
// putting an untrue event into a tamper-evident log — the running engine is
// still unlocking those features, and will until it restarts. A late true
// record beats a prompt false one. Making the entitlement itself live is the
// other half of the portal lease work, and the record follows it there.

// Recorder is the security log as this package needs it: append an event, and
// read back the last licence one. An interface, so the decision below is tested
// without a database.
type Recorder interface {
	Audit(kind, actor, subject, ip, detail string)
	LastLicenseEvent() (kind, subject string, ok bool, err error)
}

// Record appends a licence event if what this engine honours has changed since
// the last one, and nothing if it has not.
//
// Idempotent on purpose: every engine start calls it, and a steady install
// writes one event ever. It never returns an error and never fails its caller —
// the same posture Store.Audit takes, and for the same reason: a log that
// cannot be written must not become an outage.
func Record(rec Recorder, st Status) {
	if rec == nil {
		return
	}
	prevKind, prevSubject, had, err := rec.LastLicenseEvent()
	if err != nil {
		// Unreadable is not the same as absent, and guessing "absent" here
		// would write a duplicate activation every start. Say so and stop.
		log.Printf("security log: could not read the last licence event: %v", err)
		return
	}
	kind, subject, detail := recordFor(st, prevKind, prevSubject, had)
	if kind == "" {
		return
	}
	// No actor: nobody did this, the engine observed it. The person who typed
	// the command is on the other side of a VM boundary and cannot be
	// identified from here, and inventing one would be worse than leaving it
	// empty in a log an auditor reads.
	rec.Audit(kind, "", subject, "", detail)
}

// recordFor decides which event a licence state calls for. An empty kind means
// nothing changed and nothing should be written.
//
// The comparison is against the previous event's kind and subject, both stored
// fields, so nothing has to parse a sentence meant for a person. Between them
// they say which licence, which machine, and whether it was unlocking.
func recordFor(st Status, prevKind, prevSubject string, had bool) (kind, subject, detail string) {
	// "None installed" is not a state of its own: Install reports it as Invalid,
	// the same as a forgery, so Present is what tells them apart.
	if !st.Present() {
		if !had || prevKind == auth.EvLicenseRemoved {
			return "", "", ""
		}
		return auth.EvLicenseRemoved, noLicenceSubject,
			"no licence is installed — the paid features are not unlocked"
	}
	l := st.License
	subject = l.ID + "@" + st.BoundTo

	if !st.Unlocks() {
		if had && prevKind == auth.EvLicenseLapsed && prevSubject == subject {
			return "", "", ""
		}
		return auth.EvLicenseLapsed, subject, fmt.Sprintf("%s — %s", l.Customer, st.Reason)
	}

	// Warning unlocks, so a licence in grace or bound elsewhere is recorded as
	// what it is: still unlocking. The reason it is warning goes in the detail,
	// where it is read rather than enforced.
	wasUnlocking := had && (prevKind == auth.EvLicenseActivated || prevKind == auth.EvLicenseRebound)
	if wasUnlocking && prevSubject == subject {
		return "", "", ""
	}
	if wasUnlocking && subjectLicenseID(prevSubject) == l.ID {
		// Same licence, different machine: that is a rebind, and saying so is
		// the whole value of the record — it is what a portal reconciles
		// against when counting machines on an account.
		d := fmt.Sprintf("%s — moved from %s to %s", l.Customer,
			describeMachine(subjectMachine(prevSubject)), describeMachine(st.BoundTo))
		if st.Rebinds > 0 {
			d += fmt.Sprintf(" (move %d)", st.Rebinds)
		}
		return auth.EvLicenseRebound, subject, d
	}
	return auth.EvLicenseActivated, subject, activatedDetail(st)
}

// noLicenceSubject is the subject of a removal. The column is NOT NULL with an
// empty default, so an empty string would read as "no subject recorded" rather
// than "the subject is that there is none".
const noLicenceSubject = "-"

func activatedDetail(st Status) string {
	l := st.License
	parts := []string{l.Customer}
	if len(l.Features) > 0 {
		parts = append(parts, "unlocks "+strings.Join(l.Features, ", "))
	} else {
		parts = append(parts, "unlocks nothing it names")
	}
	if l.NotAfter.IsZero() {
		parts = append(parts, "no expiry")
	} else {
		parts = append(parts, "to "+l.NotAfter.UTC().Format("2 January 2006"))
	}
	// A licence that unlocks while something is wrong with it is the case worth
	// having in the log: it is how a lapse two weeks later stops being a
	// surprise.
	if st.State != Active && st.Reason != "" {
		parts = append(parts, st.Reason)
	}
	return strings.Join(parts, " — ")
}

// subjectLicenseID and subjectMachine split a subject written as <id>@<machine>.
// Split at the last @, so a licence id containing one still reads; a machine
// fingerprint is hex and never does.
func subjectLicenseID(subject string) string {
	if i := strings.LastIndex(subject, "@"); i >= 0 {
		return subject[:i]
	}
	return subject
}

func subjectMachine(subject string) string {
	if i := strings.LastIndex(subject, "@"); i >= 0 {
		return subject[i+1:]
	}
	return ""
}

// describeMachine keeps an unreadable machine id out of the log as a blank.
func describeMachine(fp string) string {
	if fp == "" {
		return "an unidentified machine"
	}
	return fp
}
