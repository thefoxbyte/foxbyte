// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"errors"
	"testing"
)

func TestErasureRequestStore(t *testing.T) {
	s := testStore(t)
	r, err := s.CreateErasure(NewErasureRequest{Branch: "main", Refs: `[{"last4":".com"}]`, Events: "{}", Plan: `{"rows":2}`, Fingerprint: "a", Actor: "admin@x"})
	if err != nil {
		t.Fatal(err)
	}
	if r.ID == 0 || len(r.UID) != 32 || r.State != ErasurePlanned || r.CreatedBy != "admin@x" || r.PlannedBy != "admin@x" {
		t.Fatalf("made: %+v", r)
	}
	r2, _ := s.CreateErasure(NewErasureRequest{Branch: "main", Refs: "[]", Events: "{}", Plan: "{}", Actor: "admin@x"})
	if r2.UID == r.UID {
		t.Fatal("two requests share a name")
	}
	if r, err = s.SaveErasurePlan(r.ID, `{"rows":3}`, "b", "other@x"); err != nil || r.Fingerprint != "b" || r.PlannedBy != "other@x" {
		t.Fatalf("planned again: %v %+v", err, r)
	}
	// The claim is on the fingerprint: a plan changed meanwhile is not claimed.
	if err := s.ClaimErasure(r.ID, "a", "admin@x"); !errors.Is(err, ErrErasureMoved) {
		t.Fatalf("claimed an old plan: %v", err)
	}
	if err := s.ClaimErasure(r.ID, "b", "admin@x"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.WithdrawErasure(r.ID, "admin@x"); !errors.Is(err, ErrErasureMoved) {
		t.Fatalf("withdrew a request being applied: %v", err)
	}
	if err := s.ReleaseErasure(r.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimErasure(r.ID, "b", "admin@x"); err != nil {
		t.Fatal(err)
	}
	if r, err = s.FinishErasure(r.ID, `{"rows":3}`, "admin@x"); err != nil || r.State != ErasureApplied || r.Applied == nil || r.AppliedBy != "admin@x" {
		t.Fatalf("finished: %v %+v", err, r)
	}
	if r, err = s.SaveErasureResult(r.ID, `{"rows":3,"x":1}`); err != nil || r.Result != `{"rows":3,"x":1}` {
		t.Fatalf("result: %v %+v", err, r)
	}
	if _, err := s.SaveErasurePlan(r.ID, "{}", "c", "x"); !errors.Is(err, ErrErasureMoved) {
		t.Fatalf("planned an applied request again: %v", err)
	}
	if w, err := s.WithdrawErasure(r2.ID, "admin@x"); err != nil || w.State != ErasureWithdrawn || w.Withdrawn == nil {
		t.Fatalf("withdraw: %v %+v", err, w)
	}
	all, err := s.Erasures()
	if err != nil || len(all) != 2 || all[0].ID != r2.ID {
		t.Fatalf("newest first: %v %+v", err, all)
	}
	if _, err := s.Erasure(999); !errors.Is(err, ErrNoErasure) {
		t.Fatalf("a request that is not there: %v", err)
	}
}
