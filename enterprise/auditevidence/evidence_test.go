//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package auditevidence

import (
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// The document from what was read: the period's counts and changes, the
// records only when asked, no client address.
func TestAssemble(t *testing.T) {
	since := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	in := inputs{now: until, on: true, retention: 365, textDays: 30,
		chain: branch.ChainReport{Intact: true, Records: 4, Anchors: 1, Anchored: 3},
		records: []branch.AuditRecord{
			{Seq: 1, Kind: "statement", Branch: "main"}, {Seq: 2, Kind: "outcome", Branch: "main"},
			{Seq: 3, Kind: "heartbeat", Branch: "dev"}, {Seq: 4, Kind: "gap", Branch: "dev", Missing: 2},
		}}
	o := branch.EvidenceOptions{Since: since, Until: until, By: "ada@example.com", Events: []auth.SecurityEvent{
		{Kind: auth.EvAuditLogOn, At: "2026-11-02T10:00:00Z", Actor: "ada@example.com", IP: "10.0.0.9"},
		{Kind: auth.EvAuditMarked, At: "2026-10-30T10:00:00Z", Subject: "main", Detail: "auditing writes of public.t"}, // before the period
		{Kind: "user.login", At: "2026-11-02T11:00:00Z"},                                                               // not the audit log's
	}}
	ev := assemble(o, in)
	if ev.Format != "audit-evidence/1" || ev.Period.Since != "2026-11-01T00:00:00Z" || ev.By != "ada@example.com" {
		t.Fatalf("header: %+v", ev)
	}
	a := ev.Activity
	if a.Records != 4 || a.Errors != 1 || a.Heartbeats != 1 || len(a.Gaps) != 1 || a.ByBranch["dev"] != 2 || a.ByKind["statement"] != 1 {
		t.Fatalf("activity: %+v", a)
	}
	if len(ev.Changes) != 1 || ev.Changes[0].Kind != auth.EvAuditLogOn || ev.Changes[0].IP != "" {
		t.Fatalf("changes: %+v", ev.Changes)
	}
	if ev.Records != nil || ev.Anchors != nil {
		t.Fatal("the records went without being asked for")
	}
	if len(ev.Coverage.NotLogged) == 0 || len(ev.Limits) == 0 || !ev.Integrity.Intact || ev.Integrity.Anchored != 3 {
		t.Fatalf("coverage and integrity: %+v %+v", ev.Coverage, ev.Integrity)
	}
	o.Records = true
	if ev := assemble(o, in); len(ev.Records) != 4 {
		t.Fatalf("with --records: %d", len(ev.Records))
	}
}
