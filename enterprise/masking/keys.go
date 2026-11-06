//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package masking

import (
	"fmt"
	"slices"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// Key domains and rotation (Gate 1, step 2; design, section 8). The key files
// are the core's (internal/branch/maskkey.go); moving masks between keys is
// here.

// rekey moves one table's keyed masks from one key to another, masked readers
// reading the old ones until the swap, then records the domain and key.
func rekey(b, schema, table, from, to, domain string, gen int, actor string) error {
	cols, err := branch.MaskColumns(b, schema, table)
	if err != nil {
		return err
	}
	rules, err := branch.MaskRulesOn(b)
	if err != nil {
		return err
	}
	rk, keyed, err := rekeyTable(schema, table, cols, rulesFor(rules, schema, table), from, to)
	if err != nil {
		return err
	}
	if !keyed {
		return branch.RunMaskSQL(b, actor, []string{tableKeySQL(schema, table, domain, gen)}, false)
	}
	if err := branch.RunMaskSQL(b, actor, rk.Start, true); err != nil {
		return fmt.Errorf("starting %s.%s's new masks: %w", schema, table, err)
	}
	if err := branch.RunMaskScript(b, rk.Fill); err != nil {
		return fmt.Errorf("writing %s.%s's new masks: %w (masked readers still read the old ones; run it again)", schema, table, err)
	}
	if err := branch.RunMaskSQL(b, actor, append(rk.Swap, tableKeySQL(schema, table, domain, gen)), true); err != nil {
		return fmt.Errorf("swapping in %s.%s's new masks: %w (masked readers still read the old ones; run it again)", schema, table, err)
	}
	return nil
}

// useDomain puts a table's masks on a branch under another domain: only that
// table's masks are written again, and masked readers read the old ones until
// they are.
func useDomain(b, schema, table, domain, actor string) error {
	if !hasSetup(b) {
		return fmt.Errorf("%w: masking is not set up on %s: %s mask setup --branch %s", branch.ErrInvalidRequest, b, brand.CLI, b)
	}
	if !branch.MaskKeyFileExists(domain) {
		return fmt.Errorf("%w: the key of domain %q is not on this install", branch.ErrInvalidRequest, domain)
	}
	cur, err := tableDomain(b, schema, table)
	if err != nil {
		return err
	}
	if cur == domain {
		return nil
	}
	k, _ := branch.MaskKeyFor(domain)
	return rekey(b, schema, table, cur, domain, domain, max(k.Gen, 1), actor)
}

// rotate makes a domain's new key and moves every running branch's tables in
// the domain to it, then puts it in the domain's file, which deletes the old
// key. Run again after being cut short, it carries on.
func rotate(domain, actor string, say func(string)) error {
	k, _ := branch.MaskKeyFor(domain)
	gen := max(k.Gen, 1)
	if !k.Pending {
		if err := branch.MakeNextMaskKey(domain, false); err != nil {
			return fmt.Errorf("making %s's new key: %w", domain, err)
		}
		k.Pending = true
		if err := branch.RecordMaskKey(k); err != nil {
			return err
		}
	} else if err := branch.MakeNextMaskKey(domain, true); err != nil {
		return err
	}
	next := branch.NextMaskKey(domain)

	before, err := branch.RunningBranches()
	if err != nil {
		return err
	}
	for _, b := range before {
		if !hasSetup(b) {
			continue
		}
		if err := ensureKeysTable(b); err != nil {
			return err
		}
		ts, err := branch.MaskTableKeys(b)
		if err != nil {
			return err
		}
		for _, t := range ts {
			// Done before a cut-short run stopped: under the next key already.
			if t.Domain != domain || !t.Keyed || t.Gen > gen {
				continue
			}
			if err := rekey(b, t.Schema, t.Table, domain, next, domain, gen+1, actor); err != nil {
				return fmt.Errorf("on %s: %w", b, err)
			}
			say(fmt.Sprintf("%s: %s.%s written again under the new key", b, t.Schema, t.Table))
		}
	}

	// The new key into the domain's own file: the old key is gone, and both
	// names hold the new one until the triggers are pointed back at the
	// domain's name.
	if err := branch.PromoteMaskKey(domain); err != nil {
		return fmt.Errorf("putting %s's new key in place: %w", domain, err)
	}
	after, err := branch.RunningBranches()
	if err != nil {
		return err
	}
	for _, b := range after {
		if !hasSetup(b) {
			continue
		}
		if !slices.Contains(before, b) {
			// Started, or made, during the rotation: its masks are made again
			// under the keys as they are now.
			if err := setup(b, actor); err != nil {
				return fmt.Errorf("on %s, started during the rotation: %w", b, err)
			}
			say(fmt.Sprintf("%s: started during the rotation, its masks made again", b))
			continue
		}
		if err := repoint(b, domain, gen+1, actor); err != nil {
			return fmt.Errorf("on %s: %w", b, err)
		}
	}
	var gone []string
	for _, b := range before {
		if !slices.Contains(after, b) {
			gone = append(gone, b)
		}
	}
	if len(gone) == 0 {
		if err := branch.RemoveMaskKey(next); err != nil {
			return err
		}
	} else {
		// Their triggers may still write under the next key's name, which now
		// holds the domain's key: kept, so their writes keep working.
		say(fmt.Sprintf("%v stopped during the rotation: run `%s mask setup --branch <name>` once each starts, "+
			"to make its masks again under the new key", gone, brand.CLI))
	}
	k.Gen, k.Pending = gen+1, false
	k.Rotated, k.RotBy = time.Now().UTC().Format(time.RFC3339), actor
	return branch.RecordMaskKey(k)
}

// repoint has the triggers of a branch's tables rotated in a domain write
// under the domain's name again, which now holds the new key.
func repoint(b, domain string, gen int, actor string) error {
	ts, err := branch.MaskTableKeys(b)
	if err != nil {
		return err
	}
	rules, err := branch.MaskRulesOn(b)
	if err != nil {
		return err
	}
	for _, t := range ts {
		if t.Domain != domain || !t.Keyed || t.Gen != gen {
			continue
		}
		cols, err := branch.MaskColumns(b, t.Schema, t.Table)
		if err != nil {
			return err
		}
		stmts, err := repointTable(t.Schema, t.Table, cols, rulesFor(rules, t.Schema, t.Table), domain)
		if err != nil {
			return err
		}
		if len(stmts) > 0 {
			if err := branch.RunMaskSQL(b, actor, stmts, false); err != nil {
				return err
			}
		}
	}
	return nil
}
