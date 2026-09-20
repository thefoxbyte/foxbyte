// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"strings"
	"testing"
)

func TestParseReplication(t *testing.T) {
	r, err := parseReplication("rep", func() ([]string, error) {
		return []string{`{"replicating" : true, "tables" : 3, "tables_ready" : 2, "last_message_at" : "2026-09-17T10:00:00Z", "received_lsn" : "0/3000060"}`}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.Branch != "rep" || !r.Replicating || r.Tables != 3 || r.TablesReady != 2 || r.LastMessageAt == "" {
		t.Errorf("parsed %+v", r)
	}
	if r.Ready() {
		t.Error("2 of 3 tables copied is not ready")
	}
	r.TablesReady = 3
	if !r.Ready() {
		t.Error("all tables copied should be ready")
	}
	if (Replication{Replicating: true}).Ready() {
		t.Error("a subscription covering no tables is not ready")
	}
	if _, err := parseReplication("rep", func() ([]string, error) { return nil, errors.New("boom") }); err == nil || !strings.Contains(err.Error(), "rep") {
		t.Errorf("error should name the branch: %v", err)
	}
	for _, s := range []string{"subscription", "bb_sub", "srsubstate = 'r'"} {
		if !strings.Contains(replicationSQL, s) {
			t.Errorf("replicationSQL lacks %q", s)
		}
	}
}
