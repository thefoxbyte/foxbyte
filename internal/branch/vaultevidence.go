// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
	"github.com/thefoxbyte/foxbyte/internal/version"
)

// The vault's evidence (point 13, step 13.4b; docs/FOX_P13_Vault_Design.md,
// sections 3 and 14): one document an auditor is handed for a kind, saying,
// rule by rule, what FoxByte checked on this machine just now, what it does
// by how it is built, and what the customer declared, which FoxByte cannot
// check. For Aadhaar the rules are UIDAI Circular No. 14 of 2025, read with
// UIDAI's FAQ of 3 November 2025. Decided on 22 November 2026: what FoxByte
// cannot check is recorded as a declaration, by whom and when, and listed as
// open until someone declares it; the branches are read from their latest
// exposure reports, and the evidence runs no scan.
//
// A verdict is never more than its checks: "met" when every check passed and
// any declaration it needs is made, "not met" when a check failed, "open"
// when only a declaration is missing, and "not applicable" when a declaration
// says the rule does not apply.

// VaultEvidenceFormat names the document.
const VaultEvidenceFormat = "vault-evidence/1"

// VaultExposureMaxAge is how old a branch's latest exposure report may be
// before the evidence flags it.
const VaultExposureMaxAge = 30 * 24 * time.Hour

// Verdicts.
const (
	VaultMet           = "met"
	VaultNotMet        = "not met"
	VaultOpen          = "open"
	VaultNotApplicable = "not applicable"
)

// How a check knows: run against the machine now, or true by how FoxByte is
// built (each says where).
const (
	BasisChecked = "checked"
	BasisBuiltIn = "built in"
)

// VaultDeclItem is something the customer declares about a kind's vault.
type VaultDeclItem struct {
	Item string `json:"item"`
	Para string `json:"para"`
	// Asks is what to state, as the person declaring reads it.
	Asks string `json:"asks"`
}

// vaultDeclItems are the items each kind with mapped rules asks for.
var vaultDeclItems = map[string][]VaultDeclItem{
	"aadhaar": {
		{"hosting", "5", `Where the vault is hosted: "on premises", "GCC" (a MeitY-empanelled Government Community Cloud) or "vault as a service", then where`},
		{"soc2", "6", "On GCC or as a service: the latest SOC 2 Type II report, its CERT-In empanelled auditor and date"},
		{"no-input-storage", "4", "That no Aadhaar number or related data from what holders type into authentication or eKYC requests is stored"},
		{"network-zone", "7(g)", "The highly restricted network zone the machine sits in: segment, firewall rules, who may reach it"},
		{"dr", "7(f)", "The DR site and its security, the HSM keys held there, and the dual redundant links to the ASAs"},
		{"monitoring", "7(i)", "Who watches the vault's refusals and the security log, and how they are alerted"},
		{"retention", "7(j)", "The retention policy for vault values and the vault's logs, and how often the data key is rotated to shred what was deleted"},
		{"hsm-certificate", "9", "The HSM: maker, model, and its FIPS 140-2 Level 3 (or higher) certificate's CMVP number"},
		{"hsm-access", "9", "The HSM's own multi-factor, multi-role access control and audit logging, and its partition for this entity"},
		{"auth-apps", "10", "That the authentication applications are hosted on premises or on GCC"},
	},
}

// VaultDeclItems lists what a kind asks to be declared; none for a kind
// without mapped rules.
func VaultDeclItems(kind string) []VaultDeclItem { return vaultDeclItems[kind] }

// hostingChoices are how a hosting declaration begins (para 5).
var hostingChoices = []string{"on premises", "gcc", "vault as a service"}

// ErrVaultNoItem is a declaration of an item the kind does not ask for.
var ErrVaultNoItem = errors.New("no such item")

// DeclareVault records a statement about a kind's vault; value "" withdraws
// it. In the security log as vault.declare, with the statement.
func DeclareVault(st *auth.Store, kind, item, value, by, ip string) (auth.VaultDeclaration, error) {
	if err := requireFeature(edition.Vault); err != nil {
		return auth.VaultDeclaration{}, err
	}
	if st == nil {
		return auth.VaultDeclaration{}, errors.New("the install's store is not open, and declarations are kept there")
	}
	found := false
	for _, it := range VaultDeclItems(kind) {
		found = found || it.Item == item
	}
	if !found {
		names := []string{}
		for _, it := range VaultDeclItems(kind) {
			names = append(names, it.Item)
		}
		if len(names) == 0 {
			return auth.VaultDeclaration{}, fmt.Errorf("%w: the %q kind has no rules mapped, so nothing to declare", ErrVaultNoItem, kind)
		}
		return auth.VaultDeclaration{}, fmt.Errorf("%w: %q is not one of %s's: %s", ErrVaultNoItem, item, kind, strings.Join(names, ", "))
	}
	value = strings.TrimSpace(value)
	if len(value) > auth.MaxVaultDeclaration {
		return auth.VaultDeclaration{}, fmt.Errorf("%w: at most %d characters", ErrInvalidRequest, auth.MaxVaultDeclaration)
	}
	if item == "hosting" && value != "" {
		ok := false
		for _, c := range hostingChoices {
			ok = ok || strings.HasPrefix(strings.ToLower(value), c)
		}
		if !ok {
			return auth.VaultDeclaration{}, fmt.Errorf(`%w: hosting begins "on premises", "GCC" or "vault as a service" (para 5), then where`, ErrInvalidRequest)
		}
	}
	d, err := st.DeclareVault(kind, item, value, by)
	if err != nil {
		return d, err
	}
	if value == "" {
		st.Audit(auth.EvVaultDeclare, by, kind, ip, fmt.Sprintf("withdrew %s", item))
	} else {
		st.Audit(auth.EvVaultDeclare, by, kind, ip, fmt.Sprintf("declared %s: %s", item, value))
	}
	return d, nil
}

// VaultCheck is one thing checked, or true by construction.
type VaultCheck struct {
	What   string `json:"what"`
	OK     bool   `json:"ok"`
	Basis  string `json:"basis"`
	Detail string `json:"detail"`
}

// VaultRule is one rule and what stands behind it.
type VaultRule struct {
	Para        string       `json:"para"`
	Requirement string       `json:"requirement"`
	Whose       string       `json:"whose"`
	Verdict     string       `json:"verdict"`
	Checks      []VaultCheck `json:"checks"`
	// Items are what the customer declares for it; Declared their current
	// statements (an item with none is open).
	Items    []string                `json:"items,omitempty"`
	Declared []auth.VaultDeclaration `json:"declared,omitempty"`
	Note     string                  `json:"note,omitempty"`
}

// VaultEvidenceKey is a key as the token reports it back.
type VaultEvidenceKey struct {
	Label            string `json:"label"`
	Role             string `json:"role"`
	Gen              int    `json:"gen"`
	Current          bool   `json:"current"`
	Destroyed        bool   `json:"destroyed"`
	Created          string `json:"created"`
	DestroyedAt      string `json:"destroyed_at,omitempty"`
	Records          int64  `json:"records"`
	Uses             int64  `json:"uses"`
	Sensitive        bool   `json:"sensitive"`
	Extractable      bool   `json:"extractable"`
	AlwaysSensitive  bool   `json:"always_sensitive"`
	NeverExtractable bool   `json:"never_extractable"`
	Local            bool   `json:"local"`
}

// VaultBranchExposure is a branch's latest Aadhaar exposure report, as the
// evidence reads it.
type VaultBranchExposure struct {
	Branch  string     `json:"branch"`
	State   string     `json:"state"`
	Run     int64      `json:"run,omitempty"`
	Ran     *time.Time `json:"ran,omitempty"`
	Numbers int64      `json:"numbers"`
	People  int        `json:"people"`
	// LogsRan and LogNumbers are the branch's latest logs part (4.5b).
	LogsRan    *time.Time `json:"logs_ran,omitempty"`
	LogNumbers int64      `json:"log_numbers"`
	// Flag says why the branch does not show a clean report: never scanned,
	// too old, numbers found, or not read; "" when it does.
	Flag string `json:"flag,omitempty"`
}

// VaultActivity counts the access log's calls in the period, by action.
type VaultActivity struct {
	Calls   map[string]int `json:"calls"`   // entries by action
	Values  map[string]int `json:"values"`  // values or keys they named, by action
	Refused int            `json:"refused"` // engine refusals in the security log
	// Changed counts values deleted or replaced since the current data key
	// was made: their old ciphertexts stay in the vault database's history
	// and backups, readable with that key, until the next data-key rotation
	// destroys it.
	Changed     int    `json:"changed_since_data_key"`
	DataKeyMade string `json:"data_key_made,omitempty"`
}

// VaultKindEvidence is one kind's part of the document.
type VaultKindEvidence struct {
	Kind        string                `json:"kind"`
	Rules       string                `json:"rules"`
	HSMRequired bool                  `json:"hsm_required"`
	Records     int64                 `json:"records"`
	Keys        []VaultEvidenceKey    `json:"keys"`
	Activity    VaultActivity         `json:"activity"`
	Grants      []auth.VaultGrant     `json:"grants"`
	Rows        []VaultRule           `json:"rows"`
	Summary     map[string]int        `json:"summary"`
	Branches    []VaultBranchExposure `json:"branches,omitempty"`
	// Entries are the access log's entries in the period, newest first, when
	// asked for: who, what, which keys and why, never a value.
	Entries []json.RawMessage `json:"entries,omitempty"`
}

// VaultEvidence is the document.
type VaultEvidence struct {
	Format    string `json:"format"`
	Generated string `json:"generated"`
	By        string `json:"by"`
	Product   string `json:"product"`
	Version   string `json:"version"`
	Edition   string `json:"edition"`
	Since     string `json:"since"`
	Token     struct {
		Label    string `json:"label"`
		Maker    string `json:"maker"`
		Model    string `json:"model"`
		Serial   string `json:"serial"`
		Software bool   `json:"software"`
	} `json:"token"`
	Log struct {
		Entries  int64       `json:"entries"`
		BrokenAt int64       `json:"broken_at"`
		Head     string      `json:"head"`
		Anchor   VaultAnchor `json:"anchor"`
	} `json:"log"`
	Kinds  []VaultKindEvidence `json:"kinds"`
	Limits []string            `json:"limits"`
}

// VaultEvidenceOptions is what the document is asked for.
type VaultEvidenceOptions struct {
	Kind    string // "" for every kind
	Since   time.Time
	Entries bool
	By      string
	IP      string
}

// vaultServiceStatus is the service's status, as the evidence reads it.
type vaultServiceStatus struct {
	Token struct {
		Label    string `json:"label"`
		Maker    string `json:"maker"`
		Model    string `json:"model"`
		Serial   string `json:"serial"`
		Software bool   `json:"software"`
	} `json:"token"`
	Kinds []struct {
		Name        string             `json:"name"`
		Rules       string             `json:"rules"`
		HSMRequired bool               `json:"hsm_required"`
		Records     int64              `json:"records"`
		Keys        []VaultEvidenceKey `json:"keys"`
	} `json:"kinds"`
	Log struct {
		Entries  int64  `json:"entries"`
		BrokenAt int64  `json:"broken_at"`
		Head     string `json:"head"`
	} `json:"log"`
}

// vaultMachine is what the evidence checks on the machine itself.
type vaultMachine struct {
	set, db, svc     bool
	internal         bool // the vault's network is internal
	onNetwork        []string
	published        string // the vault's containers' published ports, "" for none
	socketMode       os.FileMode
	socketErr        error
	databaseBackedUp bool
}

func readVaultMachine() vaultMachine {
	m := vaultMachine{set: VaultSetUp(), db: vaultRunning(vaultDBContainer), svc: vaultRunning(vaultSvcContainer)}
	if out, err := capture("docker", "network", "inspect", "-f", "{{.Internal}}|{{range .Containers}}{{.Name}} {{end}}", VaultNetwork); err == nil {
		a, b, _ := strings.Cut(strings.TrimSpace(out), "|")
		m.internal = a == "true"
		m.onNetwork = strings.Fields(b)
		sort.Strings(m.onNetwork)
	}
	for _, c := range []string{vaultDBContainer, vaultSvcContainer} {
		out, _ := capture("docker", "inspect", "-f", "{{range $p, $b := .NetworkSettings.Ports}}{{if $b}}{{$p}} {{end}}{{end}}", c)
		if p := strings.TrimSpace(out); p != "" {
			m.published += c + ": " + p + " "
		}
	}
	m.published = strings.TrimSpace(m.published)
	if fi, err := os.Stat(VaultSocket()); err == nil {
		m.socketMode = fi.Mode().Perm()
	} else {
		m.socketErr = err
	}
	return m
}

// VaultEvidenceFor assembles the document. Admins and the operator; the
// export is in the security log as vault.evidence.
func VaultEvidenceFor(st *auth.Store, o VaultEvidenceOptions) (*VaultEvidence, error) {
	if err := requireVault(); err != nil {
		return nil, err
	}
	if st == nil {
		return nil, errors.New("the install's store is not open, and the evidence reads it")
	}
	now := time.Now().UTC()
	if o.Since.IsZero() {
		o.Since = now.Add(-90 * 24 * time.Hour)
	}
	raw, err := vaultStatusRaw()
	if err != nil {
		return nil, fmt.Errorf("the vault service: %w", err)
	}
	var svc vaultServiceStatus
	if err := json.Unmarshal(raw, &svc); err != nil {
		return nil, fmt.Errorf("the vault service's status: %w", err)
	}
	ev := &VaultEvidence{Format: VaultEvidenceFormat, Generated: now.Format(time.RFC3339), By: o.By,
		Product: brand.Product, Version: version.Version, Edition: edition.Name(), Since: o.Since.Format(time.RFC3339)}
	ev.Token = svc.Token
	ev.Log.Entries, ev.Log.BrokenAt, ev.Log.Head = svc.Log.Entries, svc.Log.BrokenAt, svc.Log.Head
	ev.Log.Anchor = vaultCheckAnchor(st)
	machine := readVaultMachine()

	entries, err := vaultEntriesSince(o.Since)
	if err != nil {
		return nil, fmt.Errorf("the vault's access log: %w", err)
	}
	refusals := vaultRefusalsSince(st, o.Since)
	grants, err := st.VaultGrants(false)
	if err != nil {
		return nil, err
	}
	var branches []VaultBranchExposure
	for _, k := range svc.Kinds {
		if o.Kind != "" && k.Name != o.Kind {
			continue
		}
		ke := VaultKindEvidence{Kind: k.Name, Rules: k.Rules, HSMRequired: k.HSMRequired, Records: k.Records, Keys: k.Keys,
			Grants: []auth.VaultGrant{}, Rows: []VaultRule{}, Summary: map[string]int{}}
		if ke.Keys == nil {
			ke.Keys = []VaultEvidenceKey{}
		}
		for _, g := range grants {
			if g.Kind == k.Name {
				ke.Grants = append(ke.Grants, g)
			}
		}
		ke.Activity = vaultActivity(entries, k.Name, k.Keys)
		ke.Activity.Refused = refusals[k.Name]
		if o.Entries {
			ke.Entries = []json.RawMessage{}
			for _, e := range entries {
				if e.Kind == k.Name {
					ke.Entries = append(ke.Entries, e.raw)
				}
			}
		}
		if k.Name == "aadhaar" {
			if branches == nil {
				branches = vaultBranchExposure(st, now)
			}
			ke.Branches = branches
			decl := map[string]*auth.VaultDeclaration{}
			for _, it := range VaultDeclItems(k.Name) {
				if d, err := st.VaultDeclarationOf(k.Name, it.Item); err == nil && d != nil {
					decl[it.Item] = d
				}
			}
			ke.Rows = aadhaarRules(vaultFacts{svc: svc, kind: ke, machine: machine, anchor: ev.Log.Anchor, decl: decl, now: now, since: o.Since})
		}
		for _, r := range ke.Rows {
			ke.Summary[r.Verdict]++
		}
		ev.Kinds = append(ev.Kinds, ke)
	}
	if o.Kind != "" && len(ev.Kinds) == 0 {
		return nil, fmt.Errorf("%w: no kind %q in the vault", ErrInvalidRequest, o.Kind)
	}
	ev.Limits = vaultEvidenceLimits(o.Entries)
	what := o.Kind
	if what == "" {
		what = "every kind"
	}
	st.Audit(auth.EvVaultEvidence, o.By, o.Kind, o.IP, fmt.Sprintf("evidence for %s since %s%s", what, o.Since.Format("2006-01-02"), map[bool]string{true: ", with the access log's entries"}[o.Entries]))
	return ev, nil
}

func vaultEvidenceLimits(entries bool) []string {
	l := []string{
		"Checked means checked on this machine when the document was made; built in means true by how FoxByte is built, as its design document says. A declaration is the customer's statement, kept with who made it and when; FoxByte does not check it.",
		"What surrounds the machine (the network zone, the DR site, the links to the ASAs, the HSM's own access control and certificate) is not visible from it.",
		"A real HSM is driven through PKCS#11 as the software token is; FoxByte reads back that its keys were made in it and cannot leave it, and does not verify its certificate.",
		"The branches are read from their latest Aadhaar exposure reports; the document runs no scan, and a branch that is not running is not read.",
		"The access log's chain is checked by the vault service, and its head against the security log, when the document is made.",
	}
	if entries {
		l = append(l, "The entries listed carry no hashes, so their chain cannot be checked again from this document alone.")
	}
	return l
}

// vaultEntry is an access-log entry as the evidence reads it, kept as it came.
type vaultEntry struct {
	Seq    int64     `json:"seq"`
	At     time.Time `json:"at"`
	Action string    `json:"action"`
	Kind   string    `json:"kind"`
	N      int       `json:"n"`
	Result string    `json:"result"`
	raw    json.RawMessage
}

// vaultEntriesSince reads the access log back to since, newest first.
func vaultEntriesSince(since time.Time) ([]vaultEntry, error) {
	if vaulter == nil || vaulter.Entries == nil {
		return nil, notLicensed{edition.Vault}
	}
	secret, err := vaultSecret()
	if err != nil {
		return nil, err
	}
	var out []vaultEntry
	var before int64
	for page := 0; page < 1000; page++ {
		b, err := vaulter.Entries(VaultSocket(), secret, 1000, before)
		if err != nil {
			return nil, err
		}
		var r struct {
			Entries []json.RawMessage `json:"entries"`
		}
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, err
		}
		if len(r.Entries) == 0 {
			return out, nil
		}
		for _, raw := range r.Entries {
			var e vaultEntry
			if err := json.Unmarshal(raw, &e); err != nil {
				return nil, err
			}
			if e.At.Before(since) {
				return out, nil
			}
			e.raw = raw
			out = append(out, e)
			before = e.Seq
		}
	}
	return out, nil
}

// vaultRefusalsSince counts the engine's refusals by kind since a time.
func vaultRefusalsSince(st *auth.Store, since time.Time) map[string]int {
	out := map[string]int{}
	evs, err := st.SecurityEventsOfKind(auth.EvVaultRefused)
	if err != nil {
		return out
	}
	for _, e := range evs {
		if at, err := time.Parse(time.RFC3339Nano, e.At); err == nil && !at.Before(since) {
			out[e.Subject]++
		}
	}
	return out
}

func vaultActivity(entries []vaultEntry, kind string, keys []VaultEvidenceKey) VaultActivity {
	a := VaultActivity{Calls: map[string]int{}, Values: map[string]int{}}
	var made time.Time
	for _, k := range keys {
		if k.Role == "data" && k.Current {
			a.DataKeyMade = k.Created
			made, _ = time.Parse(time.RFC3339, k.Created)
		}
	}
	for _, e := range entries {
		if e.Kind != kind {
			continue
		}
		a.Calls[e.Action]++
		a.Values[e.Action] += e.N
		if (e.Action == "delete" || e.Action == "update") && !made.IsZero() && !e.At.Before(made) {
			a.Changed += doneCount(e.Result)
		}
	}
	return a
}

// doneCount reads how many were done from a result such as "done 3, not
// found 1".
func doneCount(result string) int {
	for _, part := range strings.Split(result, ",") {
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(part), "done %d", &n); err == nil {
			return n
		}
	}
	return 0
}

// vaultBranchExposure reads each branch's latest Aadhaar exposure report.
func vaultBranchExposure(st *auth.Store, now time.Time) []VaultBranchExposure {
	infos, err := Branches()
	if err != nil {
		return []VaultBranchExposure{{Branch: "(every branch)", Flag: "the branches could not be listed: " + err.Error()}}
	}
	out := []VaultBranchExposure{}
	for _, b := range infos {
		x := VaultBranchExposure{Branch: b.Name, State: b.State}
		if lr, err := st.LatestAadhaarLogRun(b.Name); err == nil && lr != nil {
			f := lr.Finished
			x.LogsRan, x.LogNumbers = &f, lr.Numbers
		}
		if b.State != "running" {
			x.Flag = "not read: the branch is not running"
			out = append(out, x)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		conn, run, err := latestAadhaarRun(ctx, b.Name)
		if conn != nil {
			conn.Close(context.Background())
		}
		cancel()
		switch {
		case err != nil:
			x.Flag = "not read: " + err.Error()
		case run == nil:
			x.Flag = "never scanned"
		default:
			f := run.Finished
			x.Run, x.Ran, x.Numbers, x.People = run.ID, &f, run.Numbers, run.People
			x.Flag = exposureFlag(x, now)
		}
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i].Branch == "main") != (out[j].Branch == "main") {
			return out[i].Branch == "main"
		}
		return out[i].Branch < out[j].Branch
	})
	return out
}

// exposureFlag says what keeps a read branch's report from showing it clean.
func exposureFlag(x VaultBranchExposure, now time.Time) string {
	var why []string
	if x.Numbers > 0 {
		why = append(why, fmt.Sprintf("%d Aadhaar number(s) found in its tables", x.Numbers))
	}
	if x.LogNumbers > 0 {
		why = append(why, fmt.Sprintf("%d in its logs", x.LogNumbers))
	}
	if x.Ran != nil && now.Sub(*x.Ran) > VaultExposureMaxAge {
		why = append(why, fmt.Sprintf("its latest report is %d days old", int(now.Sub(*x.Ran).Hours()/24)))
	}
	return strings.Join(why, "; ")
}

// vaultFacts is what the rules are judged on.
type vaultFacts struct {
	svc     vaultServiceStatus
	kind    VaultKindEvidence
	machine vaultMachine
	anchor  VaultAnchor
	decl    map[string]*auth.VaultDeclaration
	now     time.Time
	since   time.Time
}

func check(what string, ok bool, basis, detail string) VaultCheck {
	return VaultCheck{What: what, OK: ok, Basis: basis, Detail: detail}
}

// rule judges one rule from its checks and the declarations it needs.
func (f vaultFacts) rule(para, req, whose string, checks []VaultCheck, items ...string) VaultRule {
	r := VaultRule{Para: para, Requirement: req, Whose: whose, Checks: checks, Items: items, Verdict: VaultMet}
	if r.Checks == nil {
		r.Checks = []VaultCheck{}
	}
	for _, c := range checks {
		if !c.OK {
			r.Verdict = VaultNotMet
		}
	}
	missing := false
	for _, it := range items {
		if d := f.decl[it]; d != nil {
			r.Declared = append(r.Declared, *d)
		} else {
			missing = true
		}
	}
	if r.Verdict == VaultMet && missing {
		r.Verdict = VaultOpen
	}
	return r
}

func (f vaultFacts) onPremises() bool {
	d := f.decl["hosting"]
	return d != nil && strings.HasPrefix(strings.ToLower(d.Value), "on premises")
}

// branchesClean is the check that no branch shows an Aadhaar number.
func (f vaultFacts) branchesClean() VaultCheck {
	var flagged []string
	for _, b := range f.kind.Branches {
		if b.Flag != "" {
			flagged = append(flagged, b.Branch+": "+b.Flag)
		}
	}
	if len(f.kind.Branches) == 0 {
		return check("every branch's latest exposure report finds no number", false, BasisChecked, "no branch was listed")
	}
	if len(flagged) > 0 {
		return check("every branch's latest exposure report finds no number", false, BasisChecked, strings.Join(flagged, "; "))
	}
	return check("every branch's latest exposure report finds no number", true, BasisChecked,
		fmt.Sprintf("%d branch(es), each scanned in the last %d days with no number found", len(f.kind.Branches), int(VaultExposureMaxAge.Hours()/24)))
}

func (f vaultFacts) keysProtected() VaultCheck {
	var bad []string
	n := 0
	for _, k := range f.kind.Keys {
		if k.Destroyed {
			continue
		}
		n++
		if !k.Sensitive || k.Extractable || !k.NeverExtractable || !k.Local {
			bad = append(bad, k.Label)
		}
	}
	if len(bad) > 0 {
		return check("every key was made in the token and can never leave it", false, BasisChecked, "not protected: "+strings.Join(bad, ", "))
	}
	return check("every key was made in the token and can never leave it", n > 0, BasisChecked, fmt.Sprintf("%d key(s) read back from the token: sensitive, never extractable, made there", n))
}

func (f vaultFacts) logHolds() VaultCheck {
	ok := f.svc.Log.BrokenAt == 0 && f.anchor.Holds
	d := fmt.Sprintf("%d entries; ", f.svc.Log.Entries)
	if f.svc.Log.BrokenAt == 0 {
		d += "the chain holds; "
	} else {
		d += fmt.Sprintf("the chain breaks at entry %d; ", f.svc.Log.BrokenAt)
	}
	d += "against the security log: " + f.anchor.Note
	return check("every call is in the access log, whose chain holds and agrees with the head the security log saw", ok, BasisChecked, d)
}

// aadhaarRules is UIDAI Circular No. 14 of 2025, rule by rule (design,
// section 3), read with the FAQ of 3 November 2025.
func aadhaarRules(f vaultFacts) []VaultRule {
	m := f.machine
	running := check("the vault database and the vault service are running", m.db && m.svc, BasisChecked,
		fmt.Sprintf("database %s, service %s", runningOr(m.db), runningOr(m.svc)))
	others := []string{}
	for _, c := range m.onNetwork {
		if c != vaultDBContainer && c != vaultSvcContainer {
			others = append(others, c)
		}
	}
	network := check("the vault's network is internal, with only the vault's two containers on it", m.internal && len(others) == 0, BasisChecked,
		fmt.Sprintf("internal: %v; on it: %s", m.internal, strings.Join(m.onNetwork, ", ")))
	soft := f.svc.Token.Software
	var activity []string
	for _, a := range []string{"tokenise", "find", "detokenise", "update", "delete", "rotate"} {
		if n := f.kind.Activity.Calls[a]; n > 0 {
			activity = append(activity, fmt.Sprintf("%s %d", a, n))
		}
	}
	act := "none"
	if len(activity) > 0 {
		act = strings.Join(activity, ", ")
	}
	var detok, use int
	for _, g := range f.kind.Grants {
		if g.Permission == auth.VaultDetokenise {
			detok++
		} else {
			use++
		}
	}
	var dataRotated string
	for _, k := range f.kind.Keys {
		if k.Role == "data" && k.Current {
			dataRotated = fmt.Sprintf("the current data key, %s, was made %s", k.Label, k.Created)
		}
	}

	rows := []VaultRule{
		f.rule("2", "Aadhaar numbers and connected data are kept only in a separate secure database (the vault)", "FoxByte",
			[]VaultCheck{
				check("the vault is set up, its own database in its own container", m.set, BasisChecked, "fox vault setup"),
				running, network,
			}),
		f.rule("3", "Reference keys and demographic data may stay in local databases as long as the number is not there", "FoxByte, then the customer",
			[]VaultCheck{f.branchesClean()}),
		f.rule("4", "No Aadhaar number or related data from what a holder types into an authentication or eKYC request is stored", "The customer; FoxByte reports what it finds",
			[]VaultCheck{f.branchesClean()}, "no-input-storage"),
		f.rule("5", "The vault is on premises, on a MeitY-empanelled GCC, or a vault-as-a-service", "The customer",
			nil, "hosting"),
	}
	soc2 := f.rule("6", "On GCC or as a service: an annual SOC 2 Type II audit by a CERT-In empanelled auditor", "The customer", nil, "soc2")
	if f.onPremises() && f.decl["soc2"] == nil {
		soc2.Verdict, soc2.Note = VaultNotApplicable, "the vault is declared hosted on premises"
	}
	rows = append(rows, soc2,
		f.rule("7(a)", "A provider for several entities keeps each entity's vault logically separate", "FoxByte, per install",
			[]VaultCheck{check("one vault per install, with its own database, network, token and keys", m.set, BasisBuiltIn, "design, section 5")}),
		f.rule("7(b)", "Each number has a reference key, and the mapping is kept in the vault", "FoxByte",
			[]VaultCheck{check("each record is a reference key and its value encrypted in the token", true, BasisBuiltIn, fmt.Sprintf("%d %s record(s)", f.kind.Records, f.kind.Kind))}),
		f.rule("7(c)", "Business systems store only the reference key", "FoxByte and the customer",
			[]VaultCheck{f.branchesClean()}),
		f.rule("7(d)", "A single logical instance per entity, reached through internal systems only", "FoxByte",
			[]VaultCheck{
				check("the vault's containers publish no port", m.published == "", BasisChecked, orNone(m.published)),
				check("the service answers only the engine, on a socket of mode 600 in the state directory", m.socketErr == nil && m.socketMode == 0o600, BasisChecked, socketDetail(m)),
			}),
	)
	aes := f.rule("7(e)", "Encrypted with AES-256 or stronger", "FoxByte",
		[]VaultCheck{check("each value is encrypted with AES-256-GCM inside the token, its kind and reference key bound in", true, BasisBuiltIn, "design, section 6")})
	aes.Note = "UIDAI's FAQ 20 refers the algorithm and key strength to its API 2.5 specification, which this document does not map."
	rows = append(rows, aes,
		f.rule("7(f)", "High availability and disaster recovery at the same level of security; dual redundant links to the ASAs", "Both",
			[]VaultCheck{check("the vault database is backed up", m.databaseBackedUp, BasisChecked, "not yet: FoxByte does not back up the vault database yet, and has no standby of it (design, section 13)")}, "dr"),
		f.rule("7(g)", "The vault and the referencing system are in a highly restricted network zone", "Both",
			[]VaultCheck{network}, "network-zone"),
		f.rule("7(h)", "Only trusted channels and secure APIs; all access through authenticated applications, with authentication, authorisation and logging", "FoxByte",
			[]VaultCheck{
				check("only the engine reaches the service, proving itself with the install's secret; people and applications reach it through FoxByte's sign-in and API keys", true, BasisBuiltIn, "design, sections 9 and 11"),
				f.logHolds(),
			}),
		f.rule("7(i)", "Access control, monitoring and alerting against unauthorised access; every access logged and monitored", "FoxByte; the alerting is the customer's",
			[]VaultCheck{
				check("reading values back needs a grant, given by an admin, with a limit an hour; refusals are in the security log", true, BasisBuiltIn,
					fmt.Sprintf("%d detokenise and %d use grant(s) now; since %s, %d refusal(s) and these calls: %s", detok, use, f.since.Format("2006-01-02"), f.kind.Activity.Refused, act)),
			}, "monitoring"),
		f.rule("7(j)", "Secure deletion and update, as the entity's retention policy requires", "FoxByte; the policy is the customer's",
			[]VaultCheck{check("values are deleted and updated by reference key, and a data-key rotation destroys the key their old ciphertexts were made under", true, BasisBuiltIn,
				fmt.Sprintf("%s; %d value(s) deleted or replaced since, still readable from the vault database's history until the next rotation", dataRotated, f.kind.Activity.Changed))}, "retention"),
		f.rule("7(k)", "Recovering the number from reference keys is not computationally feasible; a hash of the number is not a reference key", "FoxByte",
			[]VaultCheck{check("reference keys are drawn from the token's random generator, with no relation to the number", true, BasisBuiltIn, "design, section 7")}),
		f.rule("8", "An HSM is mandatory for encrypting and decrypting vault data", "FoxByte talks to it; the customer supplies it",
			[]VaultCheck{check("the token is an HSM, not FoxByte's software token", !soft, BasisChecked,
				fmt.Sprintf("%s %s, serial %s%s", f.svc.Token.Maker, f.svc.Token.Model, f.svc.Token.Serial, map[bool]string{true: ": the software token, for trials and testing only"}[soft]))}),
		f.rule("9", "The HSM is FIPS 140-2 Level 3 or higher, logically separate per entity, with key generation, secure key storage, multi-factor multi-role access control and audit logging", "The customer; FoxByte checks its keys",
			[]VaultCheck{f.keysProtected()}, "hsm-certificate", "hsm-access"),
		f.rule("10", "Authentication applications are hosted on premises or on GCC only", "The customer", nil, "auth-apps"),
	)
	return rows
}

func runningOr(b bool) string {
	if b {
		return "running"
	}
	return "stopped"
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func socketDetail(m vaultMachine) string {
	if m.socketErr != nil {
		return "the socket: " + m.socketErr.Error()
	}
	return fmt.Sprintf("mode %o", m.socketMode)
}
