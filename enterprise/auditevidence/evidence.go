//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package auditevidence

import (
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
	"github.com/thefoxbyte/foxbyte/internal/version"
)

func init() { branch.SetAuditEvidence(build) }

// inputs is everything the document is made from, gathered first so that
// making it is a pure function the tests drive.
type inputs struct {
	now       time.Time
	on        bool
	forensic  map[string]branch.ForensicGrant
	retention int
	textDays  int
	branches  []branch.EvidenceBranch
	chain     branch.ChainReport
	anchors   branch.AuditAnchorStatus
	keyID     string
	forward   *branch.ForwardStatus
	findings  []branch.AuditFinding
	activity  branch.EvidenceActivity
	records   []branch.AuditRecord // only when they were asked for
	anchorSet []ledger.Anchor
	publicKey string
}

func build(o branch.EvidenceOptions) (branch.AuditEvidence, error) {
	in, err := gather(o)
	if err != nil {
		return branch.AuditEvidence{}, err
	}
	return assemble(o, in), nil
}

// gather reads the engine. A branch not running is listed as not read: it is
// not woken to be read, as the findings never wake one.
func gather(o branch.EvidenceOptions) (inputs, error) {
	in := inputs{now: time.Now().UTC(), on: branch.AuditOn()}
	s := branch.LoadAuditSettings()
	in.forensic = s.Forensic
	in.retention, in.textDays = branch.AuditRetentionDays(), branch.ForensicRetentionDays()
	bs, err := branch.Branches()
	if err != nil {
		return in, err
	}
	for _, b := range bs {
		if b.State != "running" {
			in.branches = append(in.branches, branch.EvidenceBranch{Name: b.Name, Marks: []branch.AuditMark{},
				Definers: []branch.DefinerFunc{}, PersonalUnmarked: []string{}, Note: "not running: not woken to be read"})
			continue
		}
		in.branches = append(in.branches, branch.AuditBranchCoverage(b.Name))
	}
	if in.chain, err = branch.VerifyAudit(); err != nil {
		return in, err
	}
	in.anchors = branch.AuditAnchors()
	if in.anchors.Anchors > 0 {
		if pub, _, err := branch.AnchorPublicKey(); err == nil {
			in.keyID, in.publicKey = ledger.KeyID(pub), hex.EncodeToString(pub)
		}
	}
	in.forward = branch.AuditForwardStatus()
	var marks []branch.MarkEvent
	for _, e := range o.Events {
		if e.Kind == auth.EvAuditMarked {
			if m, ok := branch.ParseMarkEvent(e.Subject, e.Detail, e.Actor, e.At); ok {
				marks = append(marks, m)
			}
		}
	}
	in.findings = branch.AuditFindings(marks)
	if in.activity, in.records, err = branch.AuditActivityBetween(o.Since, o.Until, o.Records); err != nil {
		return in, err
	}
	if o.Records {
		in.anchorSet, _ = ledger.LoadAnchors(branch.AuditAnchorDir())
		sort.Slice(in.anchorSet, func(i, j int) bool { return in.anchorSet[i].ToID < in.anchorSet[j].ToID })
	}
	return in, nil
}

// assemble makes the document from what gather read.
func assemble(o branch.EvidenceOptions, in inputs) branch.AuditEvidence {
	ev := branch.AuditEvidence{
		Format: branch.AuditEvidenceFormat, Generated: in.now.Format(time.RFC3339), By: o.By,
		Product: brand.Product, Version: version.Version, Edition: edition.Name(),
		Period: branch.EvidencePeriod{Since: o.Since.UTC().Format(time.RFC3339), Until: o.Until.UTC().Format(time.RFC3339)},
		Coverage: branch.EvidenceCoverage{
			On: in.on, Forensic: in.forensic, RetentionDays: in.retention, ForensicDays: in.textDays,
			Logged: branch.EvidenceLogged, NotLogged: branch.EvidenceNotLogged, Checked: branch.EvidenceChecked,
			Branches: in.branches,
		},
		Integrity: branch.EvidenceIntegrity{ChainReport: in.chain, AnchorsKept: in.anchors, KeyID: in.keyID},
		Delivery:  branch.EvidenceDelivery{Forward: in.forward, Findings: in.findings},
		Activity:  in.activity,
		Changes:   []auth.SecurityEvent{},
		Limits:    branch.EvidenceLimits,
	}
	if ev.Coverage.Forensic == nil {
		ev.Coverage.Forensic = map[string]branch.ForensicGrant{}
	}
	if ev.Coverage.Branches == nil {
		ev.Coverage.Branches = []branch.EvidenceBranch{}
	}
	if ev.Delivery.Findings == nil {
		ev.Delivery.Findings = []branch.AuditFinding{}
	}
	for _, e := range o.Events {
		if !strings.HasPrefix(e.Kind, "audit-log.") {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, e.At)
		if err != nil || at.Before(o.Since) || !at.Before(o.Until) {
			continue
		}
		e.IP = "" // the audit log keeps no client address, and its evidence adds none
		ev.Changes = append(ev.Changes, e)
	}
	if o.Records {
		ev.Records = in.records
		if ev.Records == nil {
			ev.Records = []branch.AuditRecord{}
		}
		ev.Anchors, ev.PublicKey = in.anchorSet, in.publicKey
	}
	return ev
}
