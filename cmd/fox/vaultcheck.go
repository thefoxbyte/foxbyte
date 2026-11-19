// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// checkVaultLines is `fox check`'s vault group (point 13, step 13.2; design,
// section 9: monitoring): that the vault runs, that its log holds and agrees
// with the security log, what its token means for compliance, and what the
// last day's refusals, limits and unverified records say, and grants nobody
// uses. Nothing at all when the install has no vault.
func checkVaultLines() []checkLine {
	if !edition.Has(edition.Vault) || !branch.VaultSetUp() {
		return []checkLine{ok("vault", "not set up")}
	}
	st := openStore()
	if st != nil {
		defer st.Close()
	}
	s, err := branch.VaultStatus(st)
	if err != nil {
		return []checkLine{fail("vault", firstLine(err.Error()), brand.CLI+" vault status")}
	}
	return vaultLines(s, st, time.Now())
}

// vaultServiceView is the part of the service's status the check reads.
type vaultServiceView struct {
	Token struct {
		Software bool `json:"software"`
	} `json:"token"`
	Kinds []struct {
		Name        string `json:"name"`
		HSMRequired bool   `json:"hsm_required"`
		Rules       string `json:"rules"`
	} `json:"kinds"`
	Log struct {
		Entries  int64 `json:"entries"`
		BrokenAt int64 `json:"broken_at"`
	} `json:"log"`
}

func vaultLines(s *branch.VaultState, st *auth.Store, now time.Time) []checkLine {
	var out []checkLine
	if !s.Database || !s.Service {
		what := []string{}
		if !s.Database {
			what = append(what, "its database")
		}
		if !s.Service {
			what = append(what, "its service")
		}
		return []checkLine{fail("vault", strings.Join(what, " and ")+" stopped", brand.CLI+" start")}
	}
	if s.StatusErr != "" {
		return []checkLine{fail("vault", "the service did not answer: "+firstLine(s.StatusErr), "docker logs fox-vault")}
	}
	var v vaultServiceView
	_ = json.Unmarshal(s.Status, &v)
	switch {
	case v.Log.BrokenAt != 0:
		out = append(out, fail("vault log", fmt.Sprintf("the access log's chain breaks at entry %d", v.Log.BrokenAt), brand.CLI+" vault status"))
	case !s.Anchor.Holds:
		out = append(out, fail("vault log", s.Anchor.Note, brand.CLI+" vault status"))
	default:
		out = append(out, ok("vault log", fmt.Sprintf("running; %d entries, the chain holds and agrees with the security log", v.Log.Entries)))
	}
	if v.Token.Software {
		for _, k := range v.Kinds {
			if k.HSMRequired {
				out = append(out, warn("vault token", fmt.Sprintf("FoxByte's own software token holds %s, whose rules (%s) require an HSM: trials and testing only", k.Name, k.Rules),
					brand.CLI+" vault setup --hsm-dir … (a vault set up with your HSM)"))
				break
			}
		}
	}
	if st == nil {
		return out
	}
	evs, _ := st.RecentSecurityEvents(5000)
	since := now.Add(-24 * time.Hour)
	refused, limits, unverified := 0, 0, 0
	for _, e := range evs {
		at, err := time.Parse(time.RFC3339Nano, e.At)
		if err != nil || at.Before(since) {
			continue
		}
		switch e.Kind {
		case auth.EvVaultRefused:
			refused++
			if strings.Contains(e.Detail, branch.ErrVaultLimit.Error()) {
				limits++
			}
		case auth.EvVaultCall:
			if strings.Contains(e.Detail, "did not verify") {
				unverified++
			}
		}
	}
	if unverified > 0 {
		out = append(out, fail("vault records", fmt.Sprintf("%d call(s) in the last day read a record that did not verify: a ciphertext changed, or moved to another record", unverified),
			brand.CLI+" audit --limit 500 | grep vault.call"))
	}
	if refused > 0 {
		d := fmt.Sprintf("%d call(s) refused in the last day", refused)
		if limits > 0 {
			d += fmt.Sprintf(", %d at a grant's limit an hour", limits)
		}
		out = append(out, warn("vault refusals", d, brand.CLI+" audit --limit 500 | grep vault.refused"))
	}
	gs, err := st.VaultGrants(false)
	if err == nil {
		var idle []string
		for _, g := range gs {
			last := g.GrantedAt
			if g.LastUsed != nil {
				last = *g.LastUsed
			}
			if now.Sub(last) >= branch.VaultGrantUnused {
				idle = append(idle, fmt.Sprintf("%d (%s, %s on %s)", g.ID, g.Email, g.Permission, g.Kind))
			}
		}
		if len(idle) > 0 {
			out = append(out, warn("vault grants", fmt.Sprintf("unused for 90 days: %s", strings.Join(idle, "; ")), brand.CLI+" vault revoke <id>"))
		} else {
			out = append(out, ok("vault grants", fmt.Sprintf("%d grant(s), each used in the last 90 days", len(gs))))
		}
	}
	return out
}
