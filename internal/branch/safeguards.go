// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
	"github.com/thefoxbyte/foxbyte/internal/version"
)

// The safeguards evidence (point 11.4): Rule 6 of the DPDP Rules, 2025
// (G.S.R. 846(E), 13 Nov 2025), clause by clause, against what FoxByte checks
// on this machine now, what it does by how it is built, and what the
// customer declares, which FoxByte cannot see. Each clause says what it
// guards against and what it does not (its threat model). Built like the
// vault's evidence (vaultevidence.go): a verdict is never more than its
// checks: "met" when every check passed and every declaration it needs is
// made, "not met" when a check failed, "open" when only a declaration is
// missing. The declarations are kept with the vault's, under their own kind.
//
// Rule 6 comes into force on 13 May 2027 (Rule 1(4)). Enterprise, the dpdp
// feature; reading the declarations is free.

// SafeguardsFormat names the document.
const SafeguardsFormat = "safeguards-evidence/1"

// safeguardsKind is the declarations' kind in the vault's declaration store.
const safeguardsKind = "dpdp-safeguards"

// SafeguardItem is something the customer declares for Rule 6.
type SafeguardItem struct {
	Item   string `json:"item"`
	Clause string `json:"clause"`
	Asks   string `json:"asks"`
}

var safeguardItems = []SafeguardItem{
	{"disk-encryption", "6(1)(a)", "The disks of the machines that hold the data and its backups are encrypted at rest (name how: LUKS, the cloud's volume encryption, …)."},
	{"host-access", "6(1)(b)", "Access to the machines themselves (their operating system, the cloud console, the hypervisor) is limited to named people, with a second factor."},
	{"monitoring", "6(1)(c)", "Someone reviews the security log and the audit log, and how often; where they are forwarded, if anywhere."},
	{"dr", "6(1)(d)", "A disaster-recovery plan exists and was last tested (when)."},
	{"processors", "6(1)(f)", "Each Data Processor's contract provides for reasonable security safeguards; or there is no Data Processor."},
	{"policy", "6(1)(g)", "An information security policy covers this database, and who owns it."},
	{"training", "6(1)(g)", "The people with access are trained in it, and when they were last."},
}

// SafeguardItems lists what the customer declares.
func SafeguardItems() []SafeguardItem { return append([]SafeguardItem(nil), safeguardItems...) }

// ErrSafeguardItem is a declaration of an item that is not one.
var ErrSafeguardItem = errors.New("not a safeguards declaration item")

// DeclareSafeguard records the customer's declaration, or withdraws it (an
// empty value), with who and when. Enterprise.
func DeclareSafeguard(st *auth.Store, item, value, by string) (auth.VaultDeclaration, error) {
	if err := requireFeature(edition.DPDP); err != nil {
		return auth.VaultDeclaration{}, err
	}
	known := false
	for _, it := range safeguardItems {
		known = known || it.Item == item
	}
	if !known {
		var names []string
		for _, it := range safeguardItems {
			names = append(names, it.Item)
		}
		return auth.VaultDeclaration{}, fmt.Errorf("%w: %q (one of %s)", ErrSafeguardItem, item, strings.Join(names, ", "))
	}
	d, err := st.DeclareVault(safeguardsKind, item, strings.TrimSpace(value), by)
	if err != nil {
		return d, err
	}
	if strings.TrimSpace(value) == "" {
		st.Audit(auth.EvSafeguardDeclare, by, item, "", "withdrew "+item)
	} else {
		st.Audit(auth.EvSafeguardDeclare, by, item, "", "declared "+item)
	}
	return d, nil
}

// SafeguardDeclarations are the declarations in force.
func SafeguardDeclarations(st *auth.Store) ([]auth.VaultDeclaration, error) {
	return st.VaultDeclarations(safeguardsKind, false)
}

// SafeguardCheck is one thing checked, or true by how FoxByte is built.
type SafeguardCheck struct {
	What   string `json:"what"`
	OK     bool   `json:"ok"`
	Basis  string `json:"basis"` // checked, built in
	Detail string `json:"detail"`
}

// SafeguardRule is one clause of Rule 6(1).
type SafeguardRule struct {
	Clause      string                  `json:"clause"`
	Requirement string                  `json:"requirement"` // the Rule's words
	Verdict     string                  `json:"verdict"`
	Checks      []SafeguardCheck        `json:"checks"`
	Items       []string                `json:"items"` // the declarations it needs
	Declared    []auth.VaultDeclaration `json:"declared"`
	Guards      string                  `json:"guards"`     // what it guards against
	NotAgainst  string                  `json:"notAgainst"` // and what it does not
	Notes       []string                `json:"notes,omitempty"`
}

// SafeguardAccess is the access review's counts, which the caller reads
// (internal/access cannot be imported from here).
type SafeguardAccess struct {
	Accounts, Admins, Dormant, Keys, StaleKeys int
	DormantDays                                int
	Err                                        string
}

// SafeguardsOptions are what the evidence is made with.
type SafeguardsOptions struct {
	By     string
	Access *SafeguardAccess
}

// SafeguardsEvidence is the document.
type SafeguardsEvidence struct {
	Format    string          `json:"format"`
	Generated string          `json:"generated"`
	By        string          `json:"by"`
	Product   string          `json:"product"`
	Version   string          `json:"version"`
	Edition   string          `json:"edition"`
	Rule      string          `json:"rule"`
	InForce   string          `json:"inForce"`
	Rules     []SafeguardRule `json:"rules"`
	Summary   map[string]int  `json:"summary"`
	Items     []SafeguardItem `json:"items"`
	Limits    []string        `json:"limits"`
}

// safeguardFacts are what the checks read, gathered once.
type safeguardFacts struct {
	now          time.Time
	target       Target
	targetErr    error
	backups      BackupHealth
	restore      RestoreCheck
	restored     bool
	restoreEvery time.Duration
	exposure     []VaultBranchExposure
	vault        bool
	masked       int
	unmasked     int // confirmed personal columns with no masking rule, on main
	unmaskedErr  error
	auditOn      bool
	auditDays    int
	unaudited    []string
	unauditedErr error
	auditChain   *ChainReport
	auditErr     error
	blackbox     string
	blackboxErr  error
	seclog       ledger.Report
	seclogDays   time.Duration
	seclogErr    error
	hardening    *HardeningReport
	hardenErr    error
	access       *SafeguardAccess
	reviewed     *time.Time
	forward      string
	ha           HAState
	historyDays  int
	decl         map[string]*auth.VaultDeclaration
}

var gatherSafeguards = realSafeguardFacts

func realSafeguardFacts(st *auth.Store, o SafeguardsOptions) safeguardFacts {
	f := safeguardFacts{now: time.Now().UTC(), access: o.Access, decl: map[string]*auth.VaultDeclaration{}}
	f.target, f.targetErr = CurrentTarget()
	f.backups = CurrentBackupHealth()
	f.restore, f.restored = LastRestoreCheck()
	f.restoreEvery = restoreCheckInterval()
	f.vault = VaultSetUp()
	f.exposure = vaultBranchExposure(st, f.now)
	f.masked = len(MaskedAccounts())
	if cols, err := ConfirmedPersonalColumns("main", "", ""); err != nil {
		f.unmaskedErr = err
	} else {
		for _, c := range cols {
			if c.Mask == "" {
				f.unmasked++
			}
		}
	}
	f.auditOn, f.auditDays = AuditOn(), AuditRetentionDays()
	f.unaudited, f.unauditedErr = PersonalTablesUnmarked("main")
	if f.auditOn {
		if r, err := VerifyAudit(); err != nil {
			f.auditErr = err
		} else {
			f.auditChain = &r
		}
	}
	f.blackbox, f.blackboxErr = LedgerVerify("main")
	if evs, err := st.SecurityEvents(0, 0); err != nil {
		f.seclogErr = err
	} else {
		anchors, _ := ledger.LoadAnchors(SecurityLogAnchorDir())
		pub, _ := ledger.ReadPublicKey(AnchorKeyPath() + ".pub")
		f.seclog = VerifySecurityLog(evs, anchors, pub)
	}
	f.seclogDays, _ = SecurityLogRetention()
	if h, err := ProduceHardening("main"); err != nil {
		f.hardenErr = err
	} else {
		f.hardening = &h
	}
	if e, err := st.LastSecurityEventOfKind(auth.EvAccessReviewed); err == nil && e != nil {
		if t, err := time.Parse(time.RFC3339Nano, e.At); err == nil {
			f.reviewed = &t
		}
	}
	if fw := AuditForwardStatus(); fw != nil && fw.AuditForward != nil {
		f.forward = fw.URL
	}
	f.ha = HAInfo()
	if h, err := st.HistorySettings(); err == nil {
		f.historyDays = h.RetentionDays
	}
	for _, it := range safeguardItems {
		if d, err := st.VaultDeclarationOf(safeguardsKind, it.Item); err == nil && d != nil {
			f.decl[it.Item] = d
		}
	}
	return f
}

// SafeguardsEvidenceFor produces the document. Enterprise.
func SafeguardsEvidenceFor(st *auth.Store, o SafeguardsOptions) (*SafeguardsEvidence, error) {
	if err := requireFeature(edition.DPDP); err != nil {
		return nil, err
	}
	if st == nil {
		return nil, errors.New("the install's store is not open, and the evidence reads it")
	}
	ev := reckonSafeguards(gatherSafeguards(st, o))
	ev.By = o.By
	st.Audit(auth.EvSafeguardEvidence, o.By, "main", "", fmt.Sprintf("safeguards evidence produced: %d met, %d not met, %d open",
		ev.Summary[VaultMet], ev.Summary[VaultNotMet], ev.Summary[VaultOpen]))
	return ev, nil
}

func sgCheck(what string, ok bool, basis, detail string) SafeguardCheck {
	return SafeguardCheck{What: what, OK: ok, Basis: basis, Detail: detail}
}

func (f safeguardFacts) rule(clause, req, guards, notAgainst string, checks []SafeguardCheck, items ...string) SafeguardRule {
	if checks == nil {
		checks = []SafeguardCheck{} // a list, never null: a clause only declared has none
	}
	r := SafeguardRule{Clause: clause, Requirement: req, Guards: guards, NotAgainst: notAgainst, Checks: checks,
		Items: append([]string{}, items...), Declared: []auth.VaultDeclaration{}, Verdict: VaultMet}
	for _, c := range checks {
		if !c.OK {
			r.Verdict = VaultNotMet
		}
	}
	for _, it := range items {
		if d := f.decl[it]; d != nil {
			r.Declared = append(r.Declared, *d)
		} else if r.Verdict == VaultMet {
			r.Verdict = VaultOpen
		}
	}
	return r
}

func reckonSafeguards(f safeguardFacts) *SafeguardsEvidence {
	ev := &SafeguardsEvidence{Format: SafeguardsFormat, Generated: f.now.Format(time.RFC3339), Product: brand.Product, Version: version.Version,
		Edition: edition.Name(), Rule: "Digital Personal Data Protection Rules, 2025 (G.S.R. 846(E), 13 Nov 2025), Rule 6",
		InForce: "13 May 2027, eighteen months after publication (Rule 1(4))", Items: SafeguardItems(), Summary: map[string]int{}}
	ev.Rules = []SafeguardRule{
		f.ruleA(), f.ruleB(), f.ruleC(), f.ruleD(), f.ruleE(),
		f.rule("6(1)(f)", "appropriate provision in the contract entered into between such Data Fiduciary and such a Data Processor, wherever applicable, for taking reasonable security safeguards",
			"A processor that handles the data under weaker safeguards than the fiduciary's.",
			"Anything the contract does not reach, or a processor that breaks it; FoxByte cannot see contracts.",
			nil, "processors"),
		f.ruleG(),
	}
	for _, r := range ev.Rules {
		ev.Summary[r.Verdict]++
	}
	ev.Limits = []string{
		"Each check is read on this machine when the document is made; a check true then may not be later.",
		"What FoxByte cannot see (the machines, the contracts, the people) is the customer's declaration, recorded with who made it and when, and never checked.",
		"Rule 6 asks for reasonable safeguards \"at the minimum\" of these; meeting each clause here is not a finding that the safeguards are reasonable.",
		"The branches other than main are not read, apart from the vault's exposure reports, which cover every branch.",
		ErasureReview,
	}
	return ev
}

func (f safeguardFacts) ruleA() SafeguardRule {
	var cs []SafeguardCheck
	switch {
	case f.targetErr != nil:
		cs = append(cs, sgCheck("The backups' encryption", false, BasisChecked, "the backup target cannot be read: "+f.targetErr.Error()))
	case f.target.Remote():
		cs = append(cs, sgCheck("Backups on another machine are encrypted by FoxByte", f.target.Encrypted, BasisChecked,
			fmt.Sprintf("%s; encrypted: %v", f.target.Describe(), f.target.Encrypted)))
	default:
		cs = append(cs, sgCheck("Backups stay on this machine", true, BasisChecked, f.target.Describe()+": their encryption at rest is the disk's (declared below)"))
	}
	cs = append(cs, sgCheck("Connections from other machines are encrypted (TLS)", true, BasisBuiltIn,
		"the console, the API and the Gateway serve TLS, and refuse a client on another machine that does not use it"))
	aadhaar := true
	var flagged []string
	for _, x := range f.exposure {
		if x.Numbers > 0 || x.LogNumbers > 0 {
			aadhaar = false
			flagged = append(flagged, fmt.Sprintf("%s: %d number(s) outside the vault", x.Branch, x.Numbers+x.LogNumbers))
		}
	}
	detail := "no Aadhaar number found outside the vault in the latest exposure reports"
	if !f.vault {
		detail = "the vault is not set up; " + detail
	}
	if len(flagged) > 0 {
		detail = strings.Join(flagged, "; ")
	}
	cs = append(cs, sgCheck("Aadhaar numbers are held as the vault's tokens, not in the clear", aadhaar, BasisChecked, detail))
	if f.masked > 0 {
		d := fmt.Sprintf("%d masked account(s); %d confirmed personal-data column(s) on main have no masking rule", f.masked, f.unmasked)
		if f.unmaskedErr != nil {
			d = "the columns could not be read: " + f.unmaskedErr.Error()
		}
		cs = append(cs, sgCheck("Every personal-data column a masked account can read is masked", f.unmaskedErr == nil && f.unmasked == 0, BasisChecked, d))
	}
	return f.rule("6(1)(a)", "appropriate data security measures, such as securing of personal data through encryption, obfuscation, masking or the use of virtual tokens mapped to that personal data",
		"Personal data read from a stolen backup, a copied disk, the wire, or by an account that should see masks.",
		"Someone with the database's own admin keys, or a disk encrypted with a key kept beside it.",
		cs, "disk-encryption")
}

func (f safeguardFacts) ruleB() SafeguardRule {
	cs := []SafeguardCheck{
		sgCheck("Every way into the database needs an account or a key; there is no anonymous access", true, BasisBuiltIn,
			"the console, the API, the Gateway and MCP authenticate every request; agents use their own keys"),
	}
	switch a := f.access; {
	case a == nil || a.Err != "":
		why := "the access review is not available in this edition"
		if a != nil {
			why = a.Err
		}
		cs = append(cs, sgCheck("Accounts and keys are reviewed", false, BasisChecked, why))
	default:
		cs = append(cs,
			sgCheck(fmt.Sprintf("No account unused for %d days", a.DormantDays), a.Dormant == 0, BasisChecked,
				fmt.Sprintf("%d account(s), %d admin(s), %d dormant", a.Accounts, a.Admins, a.Dormant)),
			sgCheck(fmt.Sprintf("No key unused for %d days", a.DormantDays), a.StaleKeys == 0, BasisChecked,
				fmt.Sprintf("%d key(s), %d stale", a.Keys, a.StaleKeys)))
	}
	reviewed := f.reviewed != nil && f.now.Sub(*f.reviewed) <= 90*24*time.Hour
	d := "no access review is recorded"
	if f.reviewed != nil {
		d = "last reviewed " + f.reviewed.Local().Format("2006-01-02")
	}
	cs = append(cs, sgCheck("The access review was read in the last 90 days", reviewed, BasisChecked, d))
	r := f.rule("6(1)(b)", "appropriate measures to control access to the computer resources used by such Data Fiduciary or such a Data Processor, wherever applicable",
		"An account or key left behind by someone who left, or never used, being used by someone else.",
		"Access to the machines themselves, around FoxByte; a stolen password, FoxByte having no second factor yet (point 15).",
		cs, "host-access")
	r.Notes = append(r.Notes, "FoxByte has no second factor of its own yet (point 15): sign-in through a provider that enforces one, or keep the console on this machine.")
	return r
}

func (f safeguardFacts) ruleC() SafeguardRule {
	var cs []SafeguardCheck
	cs = append(cs, sgCheck("The audit log (pgAudit) is on", f.auditOn, BasisChecked, map[bool]string{true: "on", false: "off: " + brand.CLI + " audit-log on"}[f.auditOn]))
	switch {
	case f.unauditedErr != nil:
		cs = append(cs, sgCheck("Every table holding confirmed personal data is audited", false, BasisChecked, f.unauditedErr.Error()))
	default:
		d := "all are"
		if len(f.unaudited) > 0 {
			d = "not audited: " + strings.Join(f.unaudited, ", ")
		}
		cs = append(cs, sgCheck("Every table holding confirmed personal data is audited", len(f.unaudited) == 0, BasisChecked, d))
	}
	if f.auditOn {
		ok, d := f.auditChain != nil && f.auditChain.Intact, ""
		switch {
		case f.auditErr != nil:
			d = f.auditErr.Error()
		case f.auditChain != nil:
			d = fmt.Sprintf("%d record(s), %d anchored", f.auditChain.Records, f.auditChain.Anchored)
			if !f.auditChain.Intact {
				d += "; " + strings.Join(f.auditChain.Problems, "; ")
			}
		}
		cs = append(cs, sgCheck("The audit log's chain verifies", ok, BasisChecked, d))
	}
	bd := f.blackbox
	if f.blackboxErr != nil {
		bd = f.blackboxErr.Error()
	}
	cs = append(cs, sgCheck("main's Blackbox (every schema and data change) verifies", f.blackboxErr == nil, BasisChecked, firstLine(bd)))
	sd := fmt.Sprintf("%d event(s), %d anchored", f.seclog.Rows, f.seclog.AnchoredRows)
	if f.seclogErr != nil {
		sd = f.seclogErr.Error()
	} else if !f.seclog.Intact {
		sd += "; " + strings.Join(f.seclog.Problems, "; ")
	}
	cs = append(cs, sgCheck("The security log (sign-ins, refusals, keys, exports) verifies", f.seclogErr == nil && f.seclog.Intact, BasisChecked, sd))
	r := f.rule("6(1)(c)", "visibility on the accessing of such personal data, through appropriate logs, monitoring and review, for enabling detection of unauthorised access, its investigation and remediation to prevent recurrence",
		"Access to personal data no one can later see, and logs changed to hide it.",
		"Logs no one reads; FoxByte records and chains them, the review is people's (declared below).",
		cs, "monitoring")
	if f.forward != "" {
		r.Notes = append(r.Notes, "The audit log is forwarded to "+f.forward+".")
	}
	return r
}

func (f safeguardFacts) ruleD() SafeguardRule {
	var cs []SafeguardCheck
	switch {
	case f.backups.Unknown:
		cs = append(cs, sgCheck("A recent base backup exists", false, BasisChecked, "the backups could not be read: "+f.backups.Err))
	case f.backups.Newest == "":
		cs = append(cs, sgCheck("A recent base backup exists", false, BasisChecked, "there is no base backup"))
	default:
		cs = append(cs, sgCheck("A recent base backup exists", !f.backups.Stale, BasisChecked,
			fmt.Sprintf("the newest is %d hour(s) old, taken %s; schedule %s", f.backups.AgeHours, f.backups.Newest, f.backups.Schedule)))
	}
	rok := f.restored && f.restore.OK
	rd := "no restore check has run"
	if f.restored {
		at, err := time.Parse(time.RFC3339, f.restore.At)
		rok = rok && err == nil && f.now.Sub(at) <= 2*f.restoreEvery
		rd = fmt.Sprintf("the last ran %s: ok %v", f.restore.At, f.restore.OK)
		if f.restore.Err != "" {
			rd += ", " + f.restore.Err
		}
	}
	cs = append(cs, sgCheck("A backup was restored and checked recently", rok, BasisChecked, rd))
	r := f.rule("6(1)(d)", "reasonable measures for continued processing in the event of confidentiality, integrity or availability of such personal data being compromised as a result of destruction or loss of access to personal data or otherwise, such as by way of data-backups",
		"Losing the data to a failed disk, a deletion, or ransomware on the database.",
		"Losing the machine and its backups together, when the backups are on it; a recovery plan no one has tried.",
		cs, "dr")
	if f.ha.Enabled {
		r.Notes = append(r.Notes, "A standby follows main (high availability).")
	}
	if !f.target.Remote() {
		r.Notes = append(r.Notes, "The backups are on this machine: losing it loses them too. A target on another machine is "+brand.CLI+" backup target set.")
	}
	return r
}

func (f safeguardFacts) ruleE() SafeguardRule {
	sec := f.seclogDays == 0 || f.seclogDays >= 365*24*time.Hour
	secd := "kept for ever"
	if f.seclogDays > 0 {
		secd = fmt.Sprintf("kept %d day(s)", int(f.seclogDays.Hours()/24))
	}
	cs := []SafeguardCheck{
		sgCheck("The audit log's records are kept a year or more", !f.auditOn || f.auditDays >= 365, BasisChecked, fmt.Sprintf("kept %d day(s)", f.auditDays)),
		sgCheck("The security log is kept a year or more", sec, BasisChecked, secd),
		sgCheck("The Blackbox is never pruned", true, BasisBuiltIn, "its entries are append-only and hash-chained; an erasure redacts a value with a seal, the entry stays"),
		sgCheck("Retention erases no personal data sooner than a year from its date", true, BasisBuiltIn,
			"retention acts no sooner than "+RetentionFloor+" from a row's date, whatever its entry says (point 11.3)"),
	}
	r := f.rule("6(1)(e)", "for enabling the detection of unauthorised access, its investigation, remediation to prevent recurrence and continued processing in the event of such a compromise, retain such logs and personal data for a period of one year, unless compliance with any law for the time being in force requires otherwise",
		"Evidence of a breach gone before anyone looks for it.",
		"Logs kept outside FoxByte, and a law that asks for longer.",
		cs)
	if f.historyDays > 0 && f.historyDays < 365 {
		r.Notes = append(r.Notes, fmt.Sprintf("Query history is kept %d day(s): it is the console's convenience, not the log of processing, which is the audit log's.", f.historyDays))
	}
	return r
}

func (f safeguardFacts) ruleG() SafeguardRule {
	var cs []SafeguardCheck
	switch {
	case f.hardenErr != nil:
		cs = append(cs, sgCheck("main passes the hardening report's checks", false, BasisChecked, "the report could not run: "+f.hardenErr.Error()))
	default:
		fail := f.hardening.Summary[HardenFail]
		cs = append(cs, sgCheck("main passes the hardening report's checks", fail == 0, BasisChecked,
			fmt.Sprintf("%d pass, %d fail, %d manual (%s hardening)", f.hardening.Summary[HardenPass], fail, f.hardening.Summary[HardenManual], brand.CLI)))
	}
	return f.rule("6(1)(g)", "appropriate technical and organisational measures to ensure effective observance of security safeguards",
		"Safeguards set once and left to drift: a setting changed, a person who never learned them.",
		"Measures outside the database; the hardening report reads PostgreSQL's settings, not the machine's.",
		cs, "policy", "training")
}
