//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package accessreview

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

var now = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

func daysAgo(n int) time.Time { return now.Add(-time.Duration(n) * 24 * time.Hour) }

func fixture() inputs {
	return inputs{
		accounts: []auth.Account{
			{ID: 1, Email: "admin@example.com", Created: daysAgo(400).Unix()},
			{ID: 2, Email: "dev@example.com", Created: daysAgo(200).Unix()},
			{ID: 3, Email: "gone@example.com", Created: daysAgo(300).Unix()},
			{ID: 4, Email: "new@example.com", Created: daysAgo(10).Unix()},
		},
		keys: []auth.KeyRecord{
			{ID: "k1", Name: "ci", Prefix: "key_ab", UserID: 1, Email: "admin@example.com", Created: daysAgo(300), LastUsed: daysAgo(1)},
			{ID: "k2", Name: "bot", Prefix: "agk_cd", Kind: auth.KindAgent, UserID: 2, Email: "dev@example.com", Created: daysAgo(150)},
			{ID: "k3", Name: "feed", Prefix: "rtk_ef", Kind: auth.KindRealtime, Scope: "qa", UserID: 2, Email: "dev@example.com", Created: daysAgo(100), LastUsed: daysAgo(95)},
			{ID: "k4", Name: "old", Prefix: "key_gh", UserID: 3, Email: "gone@example.com", Created: daysAgo(290), LastUsed: daysAgo(200)},
		},
		owners:  map[string]int64{"qa": 2, "feature": 2},
		signIns: map[string]time.Time{"dev@example.com": daysAgo(3), "gone@example.com": daysAgo(250)},
		queries: map[string]time.Time{"dev@example.com": daysAgo(2)},
		branches: []branch.BranchInfo{
			{Name: "qa", State: "running"}, {Name: "main", State: "running"}, {Name: "feature", State: "exited"},
			{Name: "scratch", State: "running"}, {Name: "standby", State: "running"},
		},
		admins: map[string][]string{
			"main":    {"admin@example.com"},
			"qa":      {"admin@example.com", "dev@example.com"},
			"scratch": {"admin@example.com"},
		},
	}
}

func account(r access.Review, email string) access.ReviewAccount {
	for _, a := range r.Accounts {
		if a.Email == email {
			return a
		}
	}
	return access.ReviewAccount{}
}

func key(r access.Review, id string) access.ReviewKey {
	for _, k := range r.Keys {
		if k.ID == id {
			return k
		}
	}
	return access.ReviewKey{}
}

func TestBuild(t *testing.T) {
	r := build(fixture(), 90, now)

	t.Run("an install admin reaches every branch, and main's override is not listed twice", func(t *testing.T) {
		a := account(r, "admin@example.com")
		if !a.Admin || a.Reaches != "every branch (an install admin)" {
			t.Fatalf("%+v", a)
		}
		if !reflect.DeepEqual(a.OverrideOn, []string{"qa", "scratch"}) {
			t.Fatalf("override on %v", a.OverrideOn)
		}
	})
	t.Run("an account reaches main and what it owns, and may override where it was granted", func(t *testing.T) {
		a := account(r, "dev@example.com")
		if a.Admin || a.Reaches != "main, and the 2 branch(es) it owns" || !reflect.DeepEqual(a.Owns, []string{"feature", "qa"}) {
			t.Fatalf("%+v", a)
		}
		if !reflect.DeepEqual(a.OverrideOn, []string{"qa"}) || a.Keys != 2 {
			t.Fatalf("%+v", a)
		}
	})
	t.Run("last active is the newest of a sign-in, a key's use and a query", func(t *testing.T) {
		if a := account(r, "dev@example.com"); !a.LastActive.Equal(daysAgo(2)) || a.Dormant {
			t.Fatalf("%+v", a)
		}
		if a := account(r, "admin@example.com"); !a.LastActive.Equal(daysAgo(1)) || a.LastSignIn != nil {
			t.Fatalf("a key's use counts: %+v", a)
		}
	})
	t.Run("dormant is no activity in the window, and a new account is not dormant", func(t *testing.T) {
		if a := account(r, "gone@example.com"); !a.Dormant {
			t.Fatalf("200 days since its key was used: %+v", a)
		}
		if a := account(r, "new@example.com"); a.Dormant || a.LastActive != nil {
			t.Fatalf("10 days old and never used: %+v", a)
		}
		if r.Summary.Dormant != 1 {
			t.Fatalf("dormant %d", r.Summary.Dormant)
		}
	})
	t.Run("keys say what they are, what they reach, and whether they are stale", func(t *testing.T) {
		if k := key(r, "k1"); k.Kind != "account" || k.Stale || k.Reach != "what admin@example.com reaches" || k.AgeDays != 300 {
			t.Fatalf("%+v", k)
		}
		if k := key(r, "k2"); k.Kind != "agent" || !k.Stale || k.Why != "never used, made 150 days ago" {
			t.Fatalf("%+v", k)
		}
		if k := key(r, "k3"); k.Kind != "realtime" || k.Reach != "the branch qa only" || !k.Stale || k.Why != "last used 95 days ago" {
			t.Fatalf("%+v", k)
		}
		if r.Summary.AgentKeys != 1 || r.Summary.StaleKeys != 3 {
			t.Fatalf("summary %+v", r.Summary)
		}
	})
	t.Run("branches: main first, the standby left out, owners, and admins only where they could be read", func(t *testing.T) {
		var names []string
		for _, b := range r.Branches {
			names = append(names, b.Name)
		}
		if !reflect.DeepEqual(names, []string{"main", "feature", "qa", "scratch"}) {
			t.Fatalf("branches %v", names)
		}
		if b := r.Branches[1]; b.Owner != "dev@example.com" || b.Asked || len(b.Admins) != 0 {
			t.Fatalf("a suspended branch: %+v", b)
		}
		if r.Summary.Unowned != 1 { // scratch; main is nobody's
			t.Fatalf("unowned %d", r.Summary.Unowned)
		}
		if !strings.Contains(strings.Join(r.Limits, " "), "1 branch(es) were not running") {
			t.Fatalf("limits %v", r.Limits)
		}
	})
	t.Run("every account is told it sees data unmasked, since nothing is masked yet", func(t *testing.T) {
		for _, a := range r.Accounts {
			if !strings.Contains(a.Unmasked, "no masking is in place") {
				t.Fatalf("%+v", a)
			}
		}
	})
}

func TestCSV(t *testing.T) {
	in := fixture()
	in.keys[0].Name = "=HYPERLINK(\"http://x\")"
	r := build(in, 90, now)
	var b bytes.Buffer
	if err := r.CSV("keys", &b); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != 5 || !strings.HasPrefix(lines[0], "id,name,prefix,owner,kind") {
		t.Fatalf("keys csv:\n%s", b.String())
	}
	if !strings.Contains(lines[1], `"'=HYPERLINK(""http://x"")"`) {
		t.Fatalf("a key's name became a formula: %s", lines[1])
	}
	for _, s := range access.ReviewSections {
		b.Reset()
		if err := r.CSV(s, &b); err != nil || b.Len() == 0 {
			t.Fatalf("%s: %v", s, err)
		}
	}
	if err := r.CSV("passwords", &b); err == nil {
		t.Fatal("an unknown section is refused")
	}
}

// The Applications table (F1): each registration with its keys and what each
// asserted, and the findings a reviewer should question.
func TestApplications(t *testing.T) {
	in := fixture()
	rev, comp := daysAgo(5).Unix(), daysAgo(20).Unix()
	in.accounts = append(in.accounts, auth.Account{ID: 5, Email: "shop-svc@example.com", Created: daysAgo(200).Unix()})
	in.apps = []auth.App{
		{Name: "shop", Account: "shop-svc@example.com", Created: daysAgo(200).Unix(), MaxLife: 300, OnInvalid: "none", Keys: []auth.AppKey{
			{Kid: "k-old", Created: daysAgo(150).Unix(), Revoked: &rev, CompromisedSince: &comp},
			{Kid: "k-now", Created: daysAgo(120).Unix()},
		}},
		{Name: "idle", Account: "shop-svc@example.com", Created: daysAgo(10).Unix(), MaxLife: 60, OnInvalid: "refuse", Keys: []auth.AppKey{
			{Kid: "k1", Created: daysAgo(100).Unix()},
		}},
		{Name: "personal", Account: "dev@example.com", Created: daysAgo(5).Unix(), MaxLife: 300, OnInvalid: "none"},
		{Name: "admins", Account: "admin@example.com", Created: daysAgo(5).Unix(), MaxLife: 300, OnInvalid: "none", Keys: []auth.AppKey{
			{Kid: "k1", Created: daysAgo(5).Unix()},
		}},
		{Name: "orphan", Account: "", Created: daysAgo(5).Unix(), MaxLife: 300, OnInvalid: "none"},
	}
	in.asserted = map[string]map[[2]string]branch.Asserted{
		"main": {{"shop", "k-now"}: {Records: 12, Sessions: 1, Last: daysAgo(1)}, {"shop", "k-old"}: {Records: 3, Last: daysAgo(30)}},
		"qa":   {{"shop", "k-now"}: {Records: 15, Last: daysAgo(2)}},
	}
	r := build(in, 90, now)
	app := func(name string) access.ReviewApp {
		for _, a := range r.Applications {
			if a.Name == name {
				return a
			}
		}
		t.Fatalf("no application %q in %+v", name, r.Applications)
		return access.ReviewApp{}
	}
	has := func(a access.ReviewApp, want string) bool {
		for _, f := range a.Findings {
			if strings.Contains(f, want) {
				return true
			}
		}
		return false
	}

	shop := app("shop")
	if len(shop.Keys) != 2 || shop.Account != "shop-svc@example.com" {
		t.Fatalf("shop: %+v", shop)
	}
	now1 := shop.Keys[1]
	if now1.Kid != "k-now" || !now1.Active || now1.AgeDays != 120 ||
		!reflect.DeepEqual(now1.Records, map[string]int{"main": 12, "qa": 15}) || !reflect.DeepEqual(now1.Sessions, map[string]int{"main": 1}) ||
		now1.LastAsserted == nil || !now1.LastAsserted.Equal(daysAgo(1)) {
		t.Errorf("an active key and what it asserted, by branch: %+v", now1)
	}
	old := shop.Keys[0]
	if old.Active || old.Revoked == nil || old.CompromisedSince == nil || old.Records["main"] != 3 {
		t.Errorf("a revoked, compromised key: %+v", old)
	}
	if !has(shop, "Key k-now is 120 days old: rotate it") || !has(shop, "Key k-old was reported compromised") {
		t.Errorf("shop's findings: %v", shop.Findings)
	}
	if has(shop, "signs in") || has(shop, "install admin") || has(shop, "no active key") {
		t.Errorf("shop's account is its own, not an admin, and has a key: %v", shop.Findings)
	}
	if !has(app("idle"), "Key k1 has asserted nothing on a running branch in its 100 days") {
		t.Errorf("an old key that asserted nothing: %v", app("idle").Findings)
	}
	if p := app("personal"); !has(p, "signs in to the console") || !has(p, "no active key") {
		t.Errorf("a person's account, no key: %v", p.Findings)
	}
	if !has(app("admins"), "install admin") {
		t.Errorf("an admin's account: %v", app("admins").Findings)
	}
	if o := app("orphan"); !has(o, "no longer exists") || has(o, "no active key") {
		t.Errorf("an account gone is said once, as that: %v", o.Findings)
	}
	if r.Summary.Applications != 5 || r.Summary.AppsWithFinding != 5 {
		t.Errorf("summary: %+v", r.Summary)
	}

	var b bytes.Buffer
	if err := r.CSV("applications", &b); err != nil {
		t.Fatal(err)
	}
	csv := b.String()
	for _, want := range []string{"application,account,on_invalid,token_life_seconds,kid",
		"shop,shop-svc@example.com,none,300,k-now,", ",main:12 qa:15,main:1,", "personal,dev@example.com,none,300,,,,,,,,,,"} {
		if !strings.Contains(csv, want) {
			t.Errorf("the CSV should contain %q:\n%s", want, csv)
		}
	}
}

// No application registered: an empty table, never null.
func TestApplicationsEmpty(t *testing.T) {
	r := build(fixture(), 90, now)
	if r.Applications == nil || len(r.Applications) != 0 || r.Summary.Applications != 0 {
		t.Errorf("no applications: %+v", r.Applications)
	}
}
