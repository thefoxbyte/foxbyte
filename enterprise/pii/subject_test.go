//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package pii

import (
	"errors"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// fakeSubjects is two branches' findings, and the rows each column holds,
// already in the normalised form the SQL compares.
type fakeSubjects struct {
	findings map[string][]branch.PIIFinding
	rows     map[string][]string // branch/table.column -> values
	counted  []string
}

func (f *fakeSubjects) Branches() ([]string, error) { return []string{"main", "dev", "broken"}, nil }

func (f *fakeSubjects) Findings(name string) ([]branch.PIIFinding, error) {
	if name == "broken" {
		return nil, errors.New("down")
	}
	return f.findings[name], nil
}

func (f *fakeSubjects) Count(name string, fd branch.PIIFinding, m SubjectMatch) (int64, error) {
	key := name + "/" + fd.Table + "." + fd.Column
	f.counted = append(f.counted, key)
	n := int64(0)
	for _, v := range f.rows[key] {
		if normaliseSubject(m.Category, v) == m.Value {
			n++
		}
	}
	return n, nil
}

func finding(table, column string, c Category, state string) branch.PIIFinding {
	return branch.PIIFinding{Schema: "public", Table: table, Column: column, Category: string(c), State: state}
}

func TestFindSubjectCounts(t *testing.T) {
	src := &fakeSubjects{
		findings: map[string][]branch.PIIFinding{
			"main": {
				finding("users", "email", Email, branch.PIIConfirmed),
				finding("users", "phone", Mobile, branch.PIIConfirmed),
				finding("orders", "contact", Email, branch.PIIConfirmed),
				finding("leads", "email", Email, branch.PIISuggested), // not confirmed: not searched
			},
			"dev": {finding("users", "email", Email, branch.PIIConfirmed)},
		},
		rows: map[string][]string{
			"main/users.email":    {"asha@example.com", "ravi@example.com"},
			"main/orders.contact": {"Asha@Example.com ", "asha@example.com", "x@y.com"},
			"main/leads.email":    {"asha@example.com"},
			"dev/users.email":     {"ASHA@example.com"},
		},
	}
	rep, err := FindSubject("asha@example.com", "", src)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"dev/users.email": 1, "main/orders.contact": 2, "main/users.email": 1}
	if len(rep.Places) != len(want) {
		t.Fatalf("places %+v, want %v", rep.Places, want)
	}
	for _, p := range rep.Places {
		if n := want[p.Branch+"/"+p.Table+"."+p.Column]; n != p.Rows {
			t.Errorf("%s/%s.%s: %d rows, want %d", p.Branch, p.Table, p.Column, p.Rows, n)
		}
	}
	for _, c := range src.counted {
		if c == "main/leads.email" || c == "main/users.phone" {
			t.Errorf("searched %s: an unconfirmed finding, or another category", c)
		}
	}
	if rep.Columns != 3 || rep.Branches != 3 {
		t.Errorf("columns %d, branches %d", rep.Columns, rep.Branches)
	}
	saidWaiting, saidBroken := false, false
	for _, l := range rep.Limits {
		saidWaiting = saidWaiting || (len(l) > 5 && l[:5] == "main:")
		saidBroken = saidBroken || (len(l) > 7 && l[:7] == "broken:")
	}
	if !saidWaiting || !saidBroken {
		t.Errorf("limits do not mention the unconfirmed finding or the unreadable branch: %v", rep.Limits)
	}
}

func TestFindSubjectPhoneNormalises(t *testing.T) {
	src := &fakeSubjects{
		findings: map[string][]branch.PIIFinding{"main": {finding("users", "phone", Mobile, branch.PIIConfirmed)}},
		rows:     map[string][]string{"main/users.phone": {"+91 98765 43210", "9876543210", "09876543210", "9876500000"}},
	}
	rep, err := FindSubject("98765-43210", "", src)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Places) != 1 || rep.Places[0].Rows != 3 {
		t.Fatalf("places %+v, want one with 3 rows", rep.Places)
	}
	if _, err := FindSubject("not personal data", "", src); err == nil {
		t.Error("an unrecognised value was searched")
	}
}
