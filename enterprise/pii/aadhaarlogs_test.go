//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package pii

import (
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

// A number in a table and in a log is one person; a number only in the logs
// is a person of its own; an entry is kept once per number and part.
func TestLogExposureGroupsWithTables(t *testing.T) {
	e := newExposure()
	var none pgtype.Timestamptz
	e.add(colKey{"public", "customers", "uid", ""}, "id=1", none, []string{aadA})
	tablePeople := int32(len(e.people))
	l := &logExposure{kept: map[logPlaceKey]bool{}, persons: map[int32]bool{}}
	at := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	l.add(e, auth.AadhaarLogHistory, 7, "sql", "ada", at, []string{aadA, aadB})
	l.add(e, auth.AadhaarLogHistory, 7, "sql", "ada", at, []string{aadA})
	l.add(e, auth.AadhaarLogHistory, 7, "error", "ada", at, []string{aadA})
	if len(l.places) != 3 || l.numbers != 4 || len(l.persons) != 2 {
		t.Fatalf("places %d numbers %d persons %d", len(l.places), l.numbers, len(l.persons))
	}
	if l.places[0].Person != 1 || l.places[1].Person != 2 || int32(l.places[1].Person) <= tablePeople {
		t.Fatalf("%+v", l.places)
	}
	for _, p := range l.places {
		all := p.Source + p.Field + p.Last4 + p.Actor + p.Masked
		for _, n := range []string{aadA, aadB} {
			if strings.Contains(all, n) || strings.Contains(all, n[:8]) {
				t.Errorf("a log place keeps a number: %+v", p)
			}
		}
	}
	for i := 0; i < maxLogListed+2; i++ {
		l.add(e, auth.AadhaarLogAudit, int64(i), "", "", at, []string{aadB})
	}
	if !l.capped || len(l.places) != maxLogListed {
		t.Fatalf("capped %v, %d places", l.capped, len(l.places))
	}
}

// A run that reads the logs says so where a run of the tables alone says it
// did not.
func TestExposureLimitsWithLogs(t *testing.T) {
	e := newExposure()
	without := strings.Join(exposureLimits(e, exposureStats{}, false), " ")
	with := strings.Join(exposureLimits(e, exposureStats{}, true), " ")
	if !strings.Contains(without, onlyTables) || strings.Contains(without, withLogs) {
		t.Errorf("tables only: %s", without)
	}
	if !strings.Contains(with, withLogs) || strings.Contains(with, onlyTables) {
		t.Errorf("with logs: %s", with)
	}
}
