// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"sync"
	"testing"
)

func TestSecurityLogChains(t *testing.T) {
	s := testStore(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); s.Audit(EvLoginOK, "a@x.com", "", "127.0.0.1", "") }()
	}
	wg.Wait()
	evs, err := s.SecurityEvents(0, 0)
	if err != nil || len(evs) != 20 {
		t.Fatalf("%d events, %v; want 20", len(evs), err)
	}
	if id, why := CheckEventChain(evs); id != 0 {
		t.Fatalf("a fresh log does not verify: %s", why)
	}
	// The store refuses to change or remove history.
	if _, err := s.db.Exec(`UPDATE security_events SET actor='x' WHERE id=3`); err == nil {
		t.Error("an event could be updated")
	}
	if _, err := s.db.Exec(`DELETE FROM security_events WHERE id=3`); err == nil {
		t.Error("an event could be deleted")
	}
	// Whoever gets around the store's triggers still breaks the chain.
	edited := append([]SecurityEvent(nil), evs...)
	edited[5].Actor = "someone-else"
	if id, _ := CheckEventChain(edited); id != 6 {
		t.Errorf("an edited event: first bad id %d, want 6", id)
	}
	dropped := append(append([]SecurityEvent(nil), evs[:9]...), evs[10:]...)
	if id, _ := CheckEventChain(dropped); id != 11 {
		t.Errorf("a removed event: first bad id %d, want 11", id)
	}
	recent, _ := s.RecentSecurityEvents(3)
	if len(recent) != 3 || recent[0].ID != 20 {
		t.Errorf("recent: %+v", recent)
	}
}
