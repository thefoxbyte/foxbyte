// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

// What an erasure request removes beside the branches (F4, Gate 1 step 3b;
// docs/FOX_F4_Erasure_Design.md, sections 8 and 9), after main and every
// branch are applied:
//
//   - query history: every entry, any actor's, whose statement or error holds
//     one of the values, deleted (decision 8); saved queries holding one are
//     listed for their owners, never deleted;
//   - the audit log's forensic text holding one, removed from its day file
//     (the chain holds only the text's hash, so it still verifies); the raw
//     files not yet collected are listed with when they go;
//   - decided change requests: a statement holding one gets placeholders, a
//     note holding one has it replaced; an open request is listed, as what it
//     shows is what its approver approves;
//   - the Aadhaar log report's places in the entries removed;
//   - the vault: the record of the person's Aadhaar number deleted, unless a
//     law keeps the number (section 8), which the request then says.
//
// Each is found by value, as the Blackbox is (ErasureEngine.Forms), and none
// keeps a value: the request records counts, and the saved queries' and open
// requests' owners and names.

// ErasureCopies is what a plan finds of the person beside the branches.
type ErasureCopies struct {
	History      int              `json:"history"`  // query history entries to delete
	Saved        []auth.SavedHeld `json:"saved"`    // saved queries holding a value, for their owners
	Forensic     int              `json:"forensic"` // the audit log's texts to remove
	RawAudit     int              `json:"rawAudit"` // raw audit files not yet collected, which may hold one
	RawUntil     *time.Time       `json:"rawUntil,omitempty"`
	Requests     int              `json:"requests"`     // decided change requests to rewrite
	OpenRequests []int64          `json:"openRequests"` // open ones, listed
	Vault        int              `json:"vault"`        // vault records of the Aadhaar numbers given
	Notes        []string         `json:"notes"`
}

// ErasureCopiesDone is what removing them did.
type ErasureCopiesDone struct {
	History   int      `json:"history"`
	Forensic  int      `json:"forensic"`
	Requests  int      `json:"requests"`
	Vault     int      `json:"vault"`
	VaultKept int      `json:"vaultKept"` // records a law keeps
	LogPlaces int      `json:"logPlaces"` // the Aadhaar log report's places removed
	Notes     []string `json:"notes"`
}

// erasureVaultRefs finds the vault's reference keys for the request's Aadhaar
// numbers. No key, and a note saying why, where there is no vault, or no
// number was given. A vault that cannot be asked is said, never ignored.
var erasureVaultRefs = func(s *auth.Store, eng *ErasureEngine, values []ErasureValue, actor string) ([]string, string) {
	var nums []string
	for _, v := range values {
		refs, err := eng.Refs([]ErasureValue{v})
		if err != nil || len(refs) == 0 {
			continue
		}
		for _, c := range refs[0].Categories {
			if c == "aadhaar" {
				nums = append(nums, v.Value)
				break
			}
		}
	}
	if len(nums) == 0 {
		return nil, ""
	}
	if err := requireVault(); err != nil {
		return nil, "The vault is not set up here, so it was not asked for the Aadhaar number."
	}
	body, _ := json.Marshal(vaultRequest{Kind: "aadhaar", Values: nums})
	out, _, err := VaultCall(s, actor, "", "find", body)
	if err != nil {
		return nil, "The vault could not be asked for the Aadhaar number: " + firstLine(err.Error())
	}
	var reply struct {
		Refs    []string `json:"refs"`
		Results []string `json:"results"`
		Error   string   `json:"error"`
	}
	if err := json.Unmarshal(out, &reply); err != nil || reply.Error != "" {
		return nil, "The vault could not be asked for the Aadhaar number: " + reply.Error
	}
	var refs []string
	for i, r := range reply.Results {
		if r == "done" && i < len(reply.Refs) && reply.Refs[i] != "" {
			refs = append(refs, reply.Refs[i])
		}
	}
	return refs, ""
}

// previewCopies is what the plan says of the copies beside the branches.
func previewCopies(s *auth.Store, eng *ErasureEngine, values []ErasureValue, refs []string, vaultNote string) *ErasureCopies {
	c := &ErasureCopies{Saved: []auth.SavedHeld{}, OpenRequests: []int64{}, Notes: []string{}, Vault: len(refs)}
	if vaultNote != "" {
		c.Notes = append(c.Notes, vaultNote)
	}
	forms := eng.Forms(values)
	if n, err := s.HistoryHolding(forms); err == nil {
		c.History = n
	} else {
		c.Notes = append(c.Notes, "Query history could not be read: "+firstLine(err.Error()))
	}
	if saved, err := s.SavedHolding(forms); err == nil {
		c.Saved = saved
	}
	if n, err := ForensicHolding(forms); err == nil {
		c.Forensic = n
	} else if !strings.Contains(err.Error(), "no audit") {
		c.Notes = append(c.Notes, "The audit log's text could not be read: "+firstLine(err.Error()))
	}
	c.RawAudit, c.RawUntil = rawAuditPending()
	if decided, open, err := requestsHolding(s, forms); err == nil {
		c.Requests = len(decided)
		for _, r := range open {
			c.OpenRequests = append(c.OpenRequests, r.ID)
		}
	} else {
		c.Notes = append(c.Notes, "Change requests could not be read: "+firstLine(err.Error()))
	}
	return c
}

// holds reports whether t holds any of forms, case-blind, as the Blackbox's
// redaction compares.
func holds(t string, forms []string) bool {
	lt := strings.ToLower(t)
	for _, f := range forms {
		if len([]rune(f)) >= 4 && strings.Contains(lt, strings.ToLower(f)) {
			return true
		}
	}
	return false
}

// erase replaces each of forms in t, case-blind, with [erased].
func erase(t string, forms []string) string {
	for _, f := range forms {
		if len([]rune(f)) < 4 {
			continue
		}
		t = regexp.MustCompile("(?i)"+regexp.QuoteMeta(f)).ReplaceAllString(t, "[erased]")
	}
	return t
}

// requestsHolding splits the change requests holding a value into those
// decided, which are rewritten, and those open, which are listed.
func requestsHolding(s *auth.Store, forms []string) (decided, open []auth.ChangeRequest, err error) {
	all, err := s.AllChangeRequests()
	if err != nil {
		return nil, nil, err
	}
	for _, c := range all {
		if !holds(c.Entries, forms) && !holds(c.Note, forms) {
			continue
		}
		if c.Status == auth.RequestOpen {
			open = append(open, c)
		} else {
			decided = append(decided, c)
		}
	}
	return decided, open, nil
}

// placeholdersOn is the statement with its literals as placeholders, read by
// main's own lexer (bb._placeholders); the statement with the values erased
// where that cannot be had, or still holds one (one in an identifier).
var placeholdersOn = func(stmt string, forms []string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := OpenSuper(ctx, "main")
	if err == nil {
		defer conn.Close(context.Background())
		var ph *string
		if conn.QueryRow(ctx, "SELECT CASE WHEN to_regprocedure('bb._placeholders(text)') IS NULL THEN NULL ELSE bb._placeholders($1) END", stmt).Scan(&ph) == nil &&
			ph != nil && *ph != stmt && !holds(*ph, forms) {
			return *ph
		}
	}
	return erase(stmt, forms)
}

// applyCopies removes what the plan found beside the branches, after main and
// every branch were applied, and records what it did.
func applyCopies(s *auth.Store, eng *ErasureEngine, v ErasureView, values []ErasureValue, actor string, refs []string) *ErasureCopiesDone {
	d := &ErasureCopiesDone{Notes: []string{}}
	note := func(what string, err error) { d.Notes = append(d.Notes, what+": "+firstLine(err.Error())) }
	forms := eng.Forms(values)

	if ids, err := s.DeleteHistoryHolding(forms); err != nil {
		note("Query history was not erased", err)
	} else {
		d.History = len(ids)
		n, _ := s.DeleteAadhaarLogPlaces("history", "", ids)
		d.LogPlaces += int(n)
	}
	if seqs, err := PurgeForensicHolding(forms); err != nil {
		if !strings.Contains(err.Error(), "no audit") {
			note("The audit log's text was not erased", err)
		}
	} else {
		d.Forensic = len(seqs)
		n, _ := s.DeleteAadhaarLogPlaces("audit", "", seqs)
		d.LogPlaces += int(n)
	}
	if v.Result != nil && v.Result.Blackbox != nil {
		n, _ := s.DeleteAadhaarLogPlaces("blackbox", v.Branch, v.Result.Blackbox.IDs)
		d.LogPlaces += int(n)
	}

	if decided, _, err := requestsHolding(s, forms); err != nil {
		note("Change requests were not rewritten", err)
	} else {
		for _, c := range decided {
			entries, err := UnmarshalEntries(c.Entries)
			if err != nil {
				note(fmt.Sprintf("Change request #%d was not rewritten", c.ID), err)
				continue
			}
			for i := range entries {
				if holds(entries[i].Statement, forms) {
					entries[i].Statement = placeholdersOn(entries[i].Statement, forms)
				}
			}
			ej, err := MarshalEntries(entries)
			if err == nil {
				err = s.RewriteChangeRequestText(c.ID, ej, erase(c.Note, forms))
			}
			if err != nil {
				note(fmt.Sprintf("Change request #%d was not rewritten", c.ID), err)
				continue
			}
			d.Requests++
		}
	}

	if len(refs) > 0 {
		if keptByLaw(v, "aadhaar") {
			d.VaultKept = len(refs)
			d.Notes = append(d.Notes, "The vault's record of the Aadhaar number is kept: a law keeps the number on a branch (the request's exceptions say which).")
		} else {
			n, err := erasureVaultDelete(s, actor, refs, fmt.Sprintf("erasure request #%d", v.ID))
			if err != nil {
				note("The vault's record was not deleted", err)
			}
			d.Vault = n
		}
	}
	return d
}

// erasureVaultDelete deletes the vault's records by reference key, as an
// erasure's purpose, and says how many went.
var erasureVaultDelete = func(s *auth.Store, actor string, refs []string, purpose string) (int, error) {
	body, _ := json.Marshal(vaultRequest{Kind: "aadhaar", Refs: refs, Purpose: purpose})
	out, _, err := VaultCall(s, actor, "", "delete", body)
	if err != nil {
		return 0, err
	}
	var reply vaultReply
	if err := json.Unmarshal(out, &reply); err != nil {
		return 0, err
	}
	if reply.Error != "" {
		return 0, fmt.Errorf("%s", reply.Error)
	}
	n := 0
	for _, r := range reply.Results {
		if r == "done" {
			n++
		}
	}
	return n, nil
}

// keptByLaw reports whether a law keeps a place holding category on main or
// any branch the request planned.
func keptByLaw(v ErasureView, category string) bool {
	plans := []ErasurePlan{v.Plan}
	for _, b := range v.Branches {
		if b.Plan != nil {
			plans = append(plans, *b.Plan)
		}
	}
	for _, p := range plans {
		for _, t := range p.Tables {
			for _, x := range t.Exceptions {
				for _, c := range x.Categories {
					if c == category {
						return true
					}
				}
			}
		}
	}
	return false
}
