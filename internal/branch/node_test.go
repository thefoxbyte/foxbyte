// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The width of the door. A bare address becomes one machine; a range is only a
// range because somebody said so.
func TestNormalisePeer(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"192.168.105.3", "192.168.105.3/32"},
		{" 10.0.0.7 ", "10.0.0.7/32"},
		{"10.0.0.0/24", "10.0.0.0/24"},
		{"fd00::5", "fd00::5/128"},
	} {
		got, err := normalisePeer(c.in)
		if err != nil || got != c.want {
			t.Errorf("normalisePeer(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	// A name cannot be a pg_hba address, and saying so beats a rule that
	// silently matches nothing.
	// And a range of every address is the rule this exists to avoid.
	for _, bad := range []string{"", "   ", "db1.internal", "not-an-address", "10.0.0.0/99", "0.0.0.0/0", "::/0"} {
		if _, err := normalisePeer(bad); err == nil {
			t.Errorf("normalisePeer(%q) was accepted", bad)
		}
	}
}

// Refused before anything restarts, rather than after.
func TestValidateExposeAddress(t *testing.T) {
	for _, ok := range []string{"192.168.105.2", "fd00::2"} {
		if err := validateExposeAddress(ok); err != nil {
			t.Errorf("validateExposeAddress(%q) = %v", ok, err)
		}
	}
	for _, bad := range []struct{ in, because string }{
		{"", "no address"},
		{"127.0.0.1", "loopback: another machine cannot reach it"},
		{"::1", "loopback"},
		{"0.0.0.0", "every interface: the certificate could not name one"},
		{"db1.internal", "a name cannot be bound, and binding every interface instead is not what was asked"},
		{"10.0.0.1/24", "not an address"},
	} {
		if err := validateExposeAddress(bad.in); err == nil {
			t.Errorf("validateExposeAddress(%q) was accepted (%s)", bad.in, bad.because)
		}
	}
}

// TLS on the command line, from a mount — and never from the data directory.
func TestExposeArgs(t *testing.T) {
	if exposeArgs(false) != nil || exposeMount(false) != nil {
		t.Error("an install that publishes nothing is given TLS settings")
	}
	args := strings.Join(exposeArgs(true), " ")
	for _, want := range []string{"ssl=on", "ssl_cert_file=" + nodeCertMount, "ssl_key_file=" + nodeCertMount} {
		if !strings.Contains(args, want) {
			t.Errorf("exposeArgs is missing %q: %s", want, args)
		}
	}
	// The certificate directory is mounted read-only. It holds a private key.
	mount := strings.Join(exposeMount(true), " ")
	if !strings.HasSuffix(mount, ":ro") {
		t.Errorf("the certificate mount is writable: %s", mount)
	}
	// And it is not inside the data directory: pg_basebackup copies PGDATA, so
	// a key kept there would be handed to every standby that joins.
	if strings.Contains(nodePGCertDir(), "pgdata") {
		t.Errorf("the key lives in the data directory, which a base backup copies: %s", nodePGCertDir())
	}
}

// The port is published on the one address asked for, not on every interface.
func TestExposePublishBindsOneAddress(t *testing.T) {
	got := strings.Join(exposePublish(NodeExposure{Address: "192.168.105.2", Port: 5432}, true), " ")
	if got != "-p 192.168.105.2:5432:5432" {
		t.Errorf("published as %q", got)
	}
	if exposePublish(NodeExposure{Address: "1.2.3.4", Port: 5432}, false) != nil {
		t.Error("an unpublished install was given a host port")
	}
	// A hostname or every-interface address cannot be a bind address. There is
	// no fallback to every interface, and main still starts: just unpublished.
	for _, bad := range []string{"db1.internal", "0.0.0.0", "::", ""} {
		if got := exposePublish(NodeExposure{Address: bad, Port: 5555}, true); got != nil {
			t.Errorf("exposePublish(%q) = %q, want main left unpublished", bad, got)
		}
	}
	for _, bad := range []string{"db1.internal", "", "not an address", "0.0.0.0", "::"} {
		if _, err := exposeBindAddress(NodeExposure{Address: bad, Port: 5432}); err == nil {
			t.Errorf("exposeBindAddress(%q) was accepted", bad)
		}
	}
	if a, err := exposeBindAddress(NodeExposure{Address: " 192.168.105.2 ", Port: 5432}); err != nil || a != "192.168.105.2" {
		t.Errorf("exposeBindAddress of a plain address = %q, %v", a, err)
	}
}

// What the token carries, and what it must never carry.
func TestJoinTokenCarriesOneCredential(t *testing.T) {
	p := joinPayload{
		Version: 1, Address: "192.168.105.2", Port: 5432,
		Role: ReplicationRole, Password: "pw", CACert: "-----BEGIN CERTIFICATE-----\nx\n",
		Database: pgDatabase,
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	tok := base64.RawURLEncoding.EncodeToString(b)
	back, err := ParseJoinToken(tok)
	if err != nil {
		t.Fatalf("a token we minted could not be read: %v", err)
	}
	if back.Address != p.Address || back.Role != p.Role || back.Password != p.Password || back.CACert != p.CACert {
		t.Errorf("the token did not round-trip: %+v", back)
	}
	// The install secret is what every role password is derived from. A token
	// carrying it would let the other machine derive the superuser's.
	if strings.Contains(string(b), pgPass()) {
		t.Error("the join token carries the install secret")
	}
	// Survives being pasted: no characters a shell or a terminal would eat.
	if strings.ContainsAny(tok, "+/= \n\t'\"\\") {
		t.Errorf("the token is not safe to paste: %q", tok)
	}
}

// A token it cannot use is refused with a sentence, not a parse error.
func TestParseJoinTokenRefusals(t *testing.T) {
	mint := func(p joinPayload) string {
		b, _ := json.Marshal(p)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	full := joinPayload{Version: 1, Address: "a", Port: 5432, Role: "r", Password: "p", CACert: "c", Database: "d"}

	if _, err := ParseJoinToken("not a token"); err == nil {
		t.Error("nonsense was accepted as a token")
	}
	v2 := full
	v2.Version = 2
	if _, err := ParseJoinToken(mint(v2)); err == nil || !strings.Contains(err.Error(), "different releases") {
		t.Errorf("a future token's refusal does not explain itself: %v", err)
	}
	for _, blank := range []func(joinPayload) joinPayload{
		func(p joinPayload) joinPayload { p.Address = ""; return p },
		func(p joinPayload) joinPayload { p.Password = ""; return p },
		func(p joinPayload) joinPayload { p.CACert = ""; return p },
		func(p joinPayload) joinPayload { p.Role = ""; return p },
		func(p joinPayload) joinPayload { p.Database = ""; return p },
	} {
		if _, err := ParseJoinToken(mint(blank(full))); err == nil {
			t.Error("a token missing something it needs was accepted")
		}
	}
	badPort := full
	badPort.Port = 0
	if _, err := ParseJoinToken(mint(badPort)); err == nil {
		t.Error("a token with no port was accepted")
	}
}

// The two properties that the first version of the certificate handover broke,
// both found by the suite rather than by reading.
//
// It chowned the whole directory to the database user. `node expose` then
// worked exactly once: the next run could not create a temporary file in a
// directory it no longer owned, and failed with "permission denied". And `fox
// uninstall` removes ~/.fox with rm -rf as this user, which a directory it
// cannot enter stops outright — so a single expose left the install
// un-uninstallable.
//
// A file is deleted by permission on its directory, not by owning the file. So
// the directory stays this user's and only the key changes hands.
func TestOnlyTheKeyChangesHands(t *testing.T) {
	src, err := os.ReadFile("node.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	// chown of the directory, recursive or not, is the mistake.
	for _, bad := range []string{
		`run("chown", "-R", pgUID`,
		`run("chown", pgUID+":"+pgUID, nodePGCertDir())`,
		`run("chown", pgUID+":"+pgUID, dir)`,
	} {
		if strings.Contains(body, bad) {
			t.Errorf("the certificate directory is given to the database user (%s), which breaks "+
				"a second `node expose` and `fox uninstall`", bad)
		}
	}
	// And the key is handed over by name.
	if !strings.Contains(body, `run("chown", pgUID+":"+pgUID, key)`) {
		t.Error("the private key is never given to the database user, so Postgres will refuse it")
	}
}

// The rules are written into the running main before its port is published,
// and put back only after the port is gone. Otherwise there is a window, on
// either side, in which the published port carries the stock rules.
func TestExposeNarrowsBeforePublishingAndRestoresAfter(t *testing.T) {
	src, err := os.ReadFile("node.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	fn := func(name string) string {
		i := strings.Index(body, "func "+name+"(")
		if i < 0 {
			t.Fatalf("%s is gone", name)
		}
		s := body[i:]
		return s[:strings.Index(s, "\n}\n")]
	}
	exp := fn("NodeExpose")
	narrow := strings.Index(exp, "allowReplicationFor(PrimaryContainer(), cidr)")
	restart := strings.Index(exp, `startContainer("main", true)`)
	if narrow < 0 || restart < 0 || narrow > restart {
		t.Error("NodeExpose publishes the port before narrowing pg_hba.conf")
	}
	un := fn("NodeUnexpose")
	restart = strings.LastIndex(un, `startContainer("main", true)`)
	restore := strings.LastIndex(un, `allowReplicationFor(PrimaryContainer(), "")`)
	if restart < 0 || restore < 0 || restore < restart {
		t.Error("NodeUnexpose puts the stock rules back while the port is still published")
	}
}
