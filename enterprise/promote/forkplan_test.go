//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package promote

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// planAllAtOnce is how build chose its rows before the ledgers were streamed:
// both held whole, split at their common prefix. The reference forkPlan must
// agree with.
func planAllAtOnce(src, tgt []ledger.Row, maskedFork int64, masked bool,
	promoted map[int64]bool, fromUs map[string]bool) (int64, []ledger.Row, map[string]bool) {
	n := branch.CommonPrefix(src, tgt)
	var forkAfterID int64
	if n > 0 {
		forkAfterID = src[n-1].ID
	}
	ns, nt := n, n
	if masked && n == 0 {
		ns, nt, forkAfterID = 0, len(tgt), maskedFork
		for i, r := range tgt {
			if r.ID > maskedFork {
				nt = i
				break
			}
		}
	}
	touched := map[string]bool{}
	for _, r := range tgt[nt:] {
		if r.ObjectIdentity == "" || r.Status == "BLOCKED" || fromUs[r.Session] {
			continue
		}
		touched[r.ObjectIdentity] = true
	}
	var cands []ledger.Row
	for _, r := range src[ns:] {
		if replayable(r, promoted) {
			cands = append(cands, r)
		}
	}
	return forkAfterID, cands, touched
}

func rowsFrom(start int64, prev string, specs ...string) []ledger.Row {
	var out []ledger.Row
	for i, s := range specs {
		r := ledger.Row{ID: start + int64(i), At: time.Date(2026, 9, 1, 0, 0, i, 0, time.UTC),
			ObjectIdentity: s, Statement: "ALTER TABLE " + s + " ADD c int", Status: "APPLIED",
			Session: fmt.Sprintf("s%d", i%3), PrevHash: prev}
		switch i % 5 {
		case 3:
			r.Status = "BLOCKED"
		case 4:
			r.Statement = ""
		}
		r.RowHash = ledger.RowHash(r)
		prev = r.RowHash
		out = append(out, r)
	}
	return out
}

func TestForkPlanMatchesTheWholeLedgerSplit(t *testing.T) {
	shared := rowsFrom(1, "", "public.a", "public.b", "public.c", "public.d")
	last := shared[len(shared)-1].RowHash
	src := append(append([]ledger.Row(nil), shared...), rowsFrom(5, last, "public.a", "public.x", "public.y", "public.z", "public.q", "public.b")...)
	tgt := append(append([]ledger.Row(nil), shared...), rowsFrom(5, "other", "public.b", "public.w", "public.a")...)
	fresh := rowsFrom(1, "", "public.m", "public.n", "public.b") // a masked branch's own Blackbox
	cases := map[string]struct {
		src, tgt []ledger.Row
		fork     int64
		masked   bool
	}{
		"forked":                 {src, tgt, 0, false},
		"nothing shared":         {fresh, tgt, 0, false},
		"masked":                 {fresh, tgt, 6, true},
		"masked past the target": {fresh, tgt, 99, true},
		"masked but shared":      {src, tgt, 2, true},
		"target empty":           {src, nil, 0, false},
	}
	promoted := map[int64]bool{6: true}
	fromUs := map[string]bool{"s1": true}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := newForkPlan(promoted, fromUs)
			p.maskedFork, p.masked = c.fork, c.masked
			branch.WalkRowsFork(c.src, c.tgt, p.visitor())
			fork, cands, touched := planAllAtOnce(c.src, c.tgt, c.fork, c.masked, promoted, fromUs)
			if p.forkAfterID != fork || !reflect.DeepEqual(p.candidates, cands) || !reflect.DeepEqual(p.tgtTouched, touched) {
				t.Errorf("streamed plan: fork %d, %d candidates, touched %v\nwant: fork %d, %d candidates, touched %v",
					p.forkAfterID, len(p.candidates), p.tgtTouched, fork, len(cands), touched)
			}
		})
	}
}
