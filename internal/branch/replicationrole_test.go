// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The role that copies the database must not be the one that owns it, and must
// not be able to read anything. Verified against a live install as well
// (integration section 6), but the shape of the SQL is worth holding here.
func TestReplicationRoleIsNarrow(t *testing.T) {
	if ReplicationRole == pgUser {
		t.Fatalf("the replication role is the superuser %q", pgUser)
	}
	// Its password is its own, and not the install secret.
	for what, pw := range map[string]string{
		"the install secret": pgPass(),
		"db_client":          ClientRolePassword(),
		"db_realtime":        RealtimeRolePassword(),
	} {
		if ReplicationRolePassword() == pw {
			t.Errorf("the replication role shares a password with %s", what)
		}
	}
	if ReplicationRolePassword() != ReplicationRolePassword() {
		t.Error("the replication role's password is not stable")
	}
}

// pg_hba is first-match-wins, so a wide rule anywhere in the file still admits
// everyone it names. Leaving the old one below the narrow one would look like a
// narrowing and be none.
func TestTheWideRuleIsRemovedNotOutranked(t *testing.T) {
	sh := mustHBAScript(t, "")
	if !strings.Contains(sh, "sed -i") || !strings.Contains(sh, "/d") {
		t.Errorf("the wide rule is not deleted:\n%s", sh)
	}
	// The narrow rule names the role and an address, and is appended only when
	// it is not already there.
	if !strings.Contains(sh, replicationHBALine) {
		t.Errorf("the script does not write the narrow rule:\n%s", sh)
	}
	if !strings.Contains(sh, "grep -qF") {
		t.Errorf("the script is not idempotent; `ha enable` runs more than once:\n%s", sh)
	}
	// `set -e`, or a failed sed would be followed by an append and the file
	// would carry both rules.
	if !strings.HasPrefix(sh, "set -e") {
		t.Errorf("the script continues after a failed edit:\n%s", sh)
	}
}

// What the narrow rule says, written out. `all` in the address column was the
// old behaviour and is the thing being fixed; `samenet` is this install's own
// network, which is as narrow as it gets until a standby on another machine has
// an address to name.
func TestTheNarrowRuleNamesARoleAndANetwork(t *testing.T) {
	f := strings.Fields(replicationHBALine)
	if len(f) != 5 {
		t.Fatalf("pg_hba rules have five fields: %q", replicationHBALine)
	}
	if f[0] != "host" || f[1] != "replication" {
		t.Errorf("not a replication rule: %q", replicationHBALine)
	}
	if f[2] != ReplicationRole {
		t.Errorf("the rule admits %q rather than the replication role", f[2])
	}
	if f[3] == "all" {
		t.Error("the rule still admits any address, which is what it replaced")
	}
	if f[4] != "scram-sha-256" {
		t.Errorf("the rule does not require a password: %q", f[4])
	}
}

// The pattern that finds the old rule has to match what older versions wrote,
// whatever spacing they used.
func TestTheLegacyPatternMatchesWhatWasWritten(t *testing.T) {
	// What `ha enable` appended, and what Postgres's own formatting looks like.
	for _, line := range []string{
		"host replication all all scram-sha-256",
		"host    replication     all             all             scram-sha-256",
		"host\treplication\tall\tall\tscram-sha-256",
	} {
		if !basicREMatches(legacyHBAPattern, line) {
			t.Errorf("the legacy pattern does not match %q", line)
		}
	}
	// And must not take the narrow rule with it.
	if basicREMatches(legacyHBAPattern, replicationHBALine) {
		t.Errorf("the legacy pattern also deletes the narrow rule %q", replicationHBALine)
	}
	// Nor the image's own localhost rules, which are how a container talks to
	// itself.
	for _, keep := range []string{
		"local   replication     all                                     trust",
		"host    replication     all             127.0.0.1/32            trust",
	} {
		if basicREMatches(legacyHBAPattern, keep) {
			t.Errorf("the legacy pattern deletes the image's own rule %q", keep)
		}
	}
}

// basicREMatches applies a POSIX basic regular expression the way sed does,
// which Go's regexp does not speak: `\+` is one-or-more there and a literal
// plus in Go's syntax. Translated rather than approximated, so what the test
// checks is what sed will run.
func basicREMatches(bre, line string) bool {
	ere := strings.ReplaceAll(bre, `\+`, `+`)
	return mustMatch(ere, line)
}

func mustMatch(ere, line string) bool {
	re, err := regexp.Compile(ere)
	if err != nil {
		panic(err)
	}
	return re.MatchString(line)
}

// The peer rule: the whole of "TLS on replication traffic", and the whole of
// "from that machine only".
func TestPeerRuleRequiresTLSAndNamesOneMachine(t *testing.T) {
	line := peerHBALine("192.168.105.3/32")
	f := strings.Fields(line)
	if len(f) != 5 {
		t.Fatalf("pg_hba rules have five fields: %q", line)
	}
	// hostssl, not host. `host` matches a plaintext connection too, so a
	// standby that failed to negotiate TLS would still be admitted and would
	// still send its password.
	if f[0] != "hostssl" {
		t.Errorf("the peer rule is %q, which would admit a plaintext connection", f[0])
	}
	if f[1] != "replication" || f[2] != ReplicationRole {
		t.Errorf("the peer rule does not admit the replication role alone: %q", line)
	}
	if f[3] != "192.168.105.3/32" {
		t.Errorf("the peer rule admits %q rather than the machine named", f[3])
	}
	if f[4] != "scram-sha-256" {
		t.Errorf("the peer rule does not require a password: %q", line)
	}
	// Nothing published, nothing admitted.
	if peerHBALine("") != "" || peerHBALine("   ") != "" {
		t.Error("an install that publishes nothing still got a peer rule")
	}
}

func mustHBAScript(t *testing.T, peer string) string {
	t.Helper()
	sh, err := hbaScript(peer)
	if err != nil {
		t.Fatalf("hbaScript(%q): %v", peer, err)
	}
	return sh
}

// An install that publishes nothing has the pg_hba it had before any of this
// existed, and one that does gets exactly one peer rule however many times the
// command runs.
func TestTheScriptReplacesPeerRulesRatherThanStacking(t *testing.T) {
	bare := mustHBAScript(t, "")
	// It must not write one. It does still mention hostssl, in the pattern
	// that deletes a stale rule, which is the point: an install that stops
	// publishing must stop admitting the peer it used to.
	if strings.Contains(bare, "hostssl replication "+ReplicationRole+" ") {
		t.Errorf("an unpublished install is given a peer rule:\n%s", bare)
	}
	if !strings.Contains(bare, "sed -i '/^hostssl") {
		t.Errorf("stale peer rules are never removed:\n%s", bare)
	}
	withPeer := mustHBAScript(t, "10.0.0.5/32")
	if strings.Count(withPeer, "hostssl replication "+ReplicationRole) != 1 {
		t.Errorf("expected exactly one peer rule to be written:\n%s", withPeer)
	}
	// The whole file is replaced, so a second run cannot stack a second rule.
	if strings.Contains(withPeer, ">> \"$f\"") {
		t.Errorf("a published install's rules are appended to rather than replaced:\n%s", withPeer)
	}
}

// hbaRules is a pg_hba.conf as its rules: comments and blank lines dropped,
// each rule's fields separated by one space.
func hbaRules(file string) []string {
	var out []string
	for _, l := range strings.Split(file, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, strings.Join(strings.Fields(l), " "))
	}
	return out
}

// What a published main admits, rule by rule. The finding this answers: the
// stock `host all all all` rule stayed on the published port, so every role was
// admitted from every network.
func TestExposedHBAAdmitsOnlyThePeerFromOutside(t *testing.T) {
	file, err := exposedHBA("192.168.105.3/32")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(file, hbaManagedMarker+"\n") {
		t.Errorf("the file does not start with the marker a second expose looks for:\n%s", file)
	}
	rules := hbaRules(file)
	want := []string{
		"local all all trust",
		"host all all 127.0.0.1/32 trust",
		"host all all ::1/128 trust",
		"local replication all trust",
		"host replication all 127.0.0.1/32 trust",
		"host replication all ::1/128 trust",
		"host all all samenet scram-sha-256",
		"host replication " + ReplicationRole + " samenet scram-sha-256",
		"hostssl replication " + ReplicationRole + " 192.168.105.3/32 scram-sha-256",
		"host all all all reject",
		"host replication all all reject",
	}
	if strings.Join(rules, "\n") != strings.Join(want, "\n") {
		t.Fatalf("published rules are\n%s\nwant\n%s", strings.Join(rules, "\n"), strings.Join(want, "\n"))
	}
	// Said as properties too, so a later edit that reorders the list still has
	// to keep them.
	for i, r := range rules {
		f := strings.Fields(r)
		if f[0] == "local" {
			continue
		}
		addr := f[3]
		last := i >= len(rules)-2
		switch {
		case last:
			if f[4] != "reject" || addr != "all" {
				t.Errorf("the file does not end by rejecting everything else: %q", r)
			}
		case addr == "all" || addr == "0.0.0.0/0" || addr == "::/0":
			t.Errorf("a rule other than the closing reject admits every address: %q", r)
		case f[1] == "replication" && f[2] == ReplicationRole && addr != "samenet":
			if f[0] != "hostssl" || addr != "192.168.105.3/32" {
				t.Errorf("replication from outside is admitted without TLS or not from the peer alone: %q", r)
			}
		case addr != "samenet" && addr != "127.0.0.1/32" && addr != "::1/128":
			t.Errorf("a rule admits a network the engine does not use: %q", r)
		}
	}
}

// A peer that is not a CIDR is an error, never a rule: written into the file it
// would either match nothing or be read as something else.
func TestExposedHBARefusesABadPeer(t *testing.T) {
	for _, bad := range []string{"db1.internal", "10.0.0.5", "10.0.0.5/99", "all", "samenet",
		"10.0.0.5/32\nhost all all all trust", "10.0.0.5/32 trust"} {
		if _, err := exposedHBA(bad); err == nil {
			t.Errorf("exposedHBA(%q) was accepted", bad)
		}
		if _, err := hbaScript(bad); err == nil {
			t.Errorf("hbaScript(%q) was accepted", bad)
		}
	}
}

// Running the real script, against a directory standing in for PGDATA: expose
// replaces the file and keeps the original, a second expose (with a new peer)
// does not back up its own output, and unexpose puts the original back with
// the replication rule narrowed in it. Skipped where there is no POSIX shell
// with GNU sed, which is what the container runs.
func TestHBAScriptExposeAndUnexposeRoundTrip(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	if strings.Contains(strings.ToLower(bash), `\windows\system32`) {
		t.Skip("bash here is WSL's launcher, not a shell this test can hand a Windows path")
	}
	if out, err := exec.Command(bash, "-c", "sed --version").CombinedOutput(); err != nil ||
		!strings.Contains(string(out), "GNU") {
		t.Skip("no GNU sed")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "pg_hba.conf")
	original := stockHBA + "host replication all all scram-sha-256\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	runScript := func(peer string) string {
		t.Helper()
		cmd := exec.Command(bash, "-c", mustHBAScript(t, peer))
		cmd.Env = append(os.Environ(), "PGDATA="+filepath.ToSlash(dir))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("script for peer %q: %v\n%s", peer, err, out)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	first := runScript("10.0.0.5/32")
	want, _ := exposedHBA("10.0.0.5/32")
	if first != want {
		t.Fatalf("exposed file is\n%s\nwant\n%s", first, want)
	}
	if strings.Contains(first, "host all all all scram-sha-256") ||
		len(hbaRules(first)) == 0 || !strings.Contains(first, "host    all          all          all             reject") {
		t.Errorf("the published file still admits everyone, or does not end in a reject:\n%s", first)
	}
	backup, err := os.ReadFile(filepath.Join(dir, hbaBackupName))
	if err != nil || string(backup) != original {
		t.Fatalf("the original was not kept beside it: %q, %v", backup, err)
	}

	// Again, with a different peer: idempotent, one peer rule, and the backup
	// is still the original rather than the file the first run wrote.
	second := runScript("10.0.0.6/32")
	if strings.Count(second, "hostssl") != 1 || !strings.Contains(second, "10.0.0.6/32") ||
		strings.Contains(second, "10.0.0.5/32") {
		t.Errorf("a second expose left the wrong peer rules:\n%s", second)
	}
	if again := runScript("10.0.0.6/32"); again != second {
		t.Errorf("the same expose twice gave two different files")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, hbaBackupName)); string(b) != original {
		t.Errorf("a second expose overwrote the backup with its own output:\n%s", b)
	}

	// Unexpose: the original rules, narrowed, and no backup left behind.
	restored := runScript("")
	if _, err := os.Stat(filepath.Join(dir, hbaBackupName)); !os.IsNotExist(err) {
		t.Errorf("the backup is still there after unexpose: %v", err)
	}
	if strings.Contains(restored, hbaManagedMarker) || strings.Contains(restored, "hostssl") ||
		strings.Contains(restored, "reject") {
		t.Errorf("unexpose left the published rules:\n%s", restored)
	}
	if !strings.Contains(restored, "host    all             all             all                     scram-sha-256") {
		t.Errorf("unexpose did not bring back the rules from before:\n%s", restored)
	}
	if mustMatch(`(?m)^host\s+replication\s+all\s+all`, restored) {
		t.Errorf("the wide replication rule came back with the original:\n%s", restored)
	}
	if strings.Count(restored, replicationHBALine) != 1 {
		t.Errorf("the local standby's rule is not there exactly once:\n%s", restored)
	}
	if again := runScript(""); again != restored {
		t.Errorf("unexpose twice gave two different files")
	}

	// A published-shape file whose backup has gone gets the image's own rules.
	runScript("10.0.0.5/32")
	if err := os.Remove(filepath.Join(dir, hbaBackupName)); err != nil {
		t.Fatal(err)
	}
	if got := runScript(""); strings.Contains(got, hbaManagedMarker) || strings.Contains(got, "reject") {
		t.Errorf("with the backup gone, unexpose left the published rules:\n%s", got)
	}
}
