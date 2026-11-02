// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// One provisioning at a time per role: twenty askers at once never overlap.
func TestLockRoleSerialises(t *testing.T) {
	var inside, most int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer lockRole("user\x00main\x00a@example.com")()
			n := atomic.AddInt32(&inside, 1)
			for {
				m := atomic.LoadInt32(&most)
				if n <= m || atomic.CompareAndSwapInt32(&most, m, n) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			atomic.AddInt32(&inside, -1)
		}()
	}
	wg.Wait()
	if most != 1 {
		t.Errorf("%d provisionings of one role ran at once", most)
	}
}

// The SQL retries what another session doing the same causes, and still
// raises anything else, and on the last attempt.
func TestRetryingRoleSQL(t *testing.T) {
	sql := userRoleSQL("o'neil@example.com", "pw")
	for _, want := range []string{
		"DECLARE r text := 'o''neil@example.com';",
		"FOR attempt IN 1..5 LOOP",
		"EXCEPTION WHEN duplicate_object OR unique_violation OR internal_error THEN",
		"IF attempt = 5 THEN RAISE; END IF;",
		"CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB INHERIT IN ROLE db_client",
		"ALTER ROLE %I WITH LOGIN PASSWORD %L', r, 'pw');",
		"EXIT;",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("userRoleSQL should contain %q:\n%s", want, sql)
		}
	}
	for name, s := range map[string]string{"agent key": agentKeyRoleSQL("agent:a@example.com", "pw"), "db_agent": agentClientRoleSQL("pw")} {
		if !strings.Contains(s, "FOR attempt IN 1..5 LOOP") || !strings.Contains(s, "IN ROLE db_client") {
			t.Errorf("%s's SQL should retry too:\n%s", name, s)
		}
	}
	if !strings.Contains(agentKeyRoleSQL("agent:a@example.com", "pw"), "IN ROLE db_client, db_agent") {
		t.Error("an agent key's role is still a member of db_agent")
	}
}
