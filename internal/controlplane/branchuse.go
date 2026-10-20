// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"log"
	"sync"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

// touchEvery is how often one branch's use is written down: well inside any
// idle window the reaper is given (two minutes by default, seconds in the test
// suites), so a branch in steady use never looks idle between two writes, and
// still not a write per query.
const touchEvery = 2 * time.Second

// throttledTouch records a branch's use in the store the gateway reads, at most
// once per touchEvery per branch.
func throttledTouch(store *auth.Store) func(string) {
	var mu sync.Mutex
	last := map[string]time.Time{}
	return func(name string) {
		mu.Lock()
		if time.Since(last[name]) < touchEvery {
			mu.Unlock()
			return
		}
		last[name] = time.Now()
		mu.Unlock()
		if err := store.TouchBranch(name); err != nil {
			log.Printf("recording use of %s: %v", name, err)
		}
	}
}
