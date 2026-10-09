//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"strings"
	"testing"
)

func TestParseDSN(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want DSN
	}{
		{"what the CLI prints",
			"fox-realtime://rtk_abc@127.0.0.1:8080/app",
			DSN{Host: "127.0.0.1:8080", Branch: "app", Key: "rtk_abc", SSL: SSLRequire}},
		{"no key, for a deployment template",
			"fox-realtime://127.0.0.1:8080/app",
			DSN{Host: "127.0.0.1:8080", Branch: "app", SSL: SSLRequire}},
		{"a real certificate",
			"fox-realtime://rtk_abc@db.example.com:8080/app?sslmode=verify-full",
			DSN{Host: "db.example.com:8080", Branch: "app", Key: "rtk_abc", SSL: SSLVerifyFull}},
		{"the loopback fallback, asked for by name",
			"fox-realtime://rtk_abc@127.0.0.1:8080/app?sslmode=disable",
			DSN{Host: "127.0.0.1:8080", Branch: "app", Key: "rtk_abc", SSL: SSLDisable}},
		// Somebody transcribing a Postgres URL puts the secret in the password
		// position. Accepting both is one less way to be stuck with a string
		// that looks right.
		{"key as userinfo password",
			"fox-realtime://ignored:rtk_abc@127.0.0.1:8080/app",
			DSN{Host: "127.0.0.1:8080", Branch: "app", Key: "rtk_abc", SSL: SSLRequire}},
		{"IPv6 host",
			"fox-realtime://rtk_abc@[::1]:8080/app",
			DSN{Host: "[::1]:8080", Branch: "app", Key: "rtk_abc", SSL: SSLRequire}},
		{"trailing slash",
			"fox-realtime://rtk_abc@127.0.0.1:8080/app/",
			DSN{Host: "127.0.0.1:8080", Branch: "app", Key: "rtk_abc", SSL: SSLRequire}},
		{"surrounding whitespace, as a copy-paste leaves it",
			"  fox-realtime://rtk_abc@127.0.0.1:8080/app\n",
			DSN{Host: "127.0.0.1:8080", Branch: "app", Key: "rtk_abc", SSL: SSLRequire}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseDSN(c.in)
			if err != nil {
				t.Fatalf("ParseDSN(%q): %v", c.in, err)
			}
			if got != c.want {
				t.Fatalf("ParseDSN(%q)\n got %+v\nwant %+v", c.in, got, c.want)
			}
		})
	}
}

func TestParseDSNRefusals(t *testing.T) {
	cases := []struct{ name, in, wantIn string }{
		{"empty", "", "empty"},
		{"a Postgres URL, which this is not", "postgres://u@h:5432/db", "starts with fox-realtime://"},
		{"no scheme at all", "127.0.0.1:8080/app", "starts with fox-realtime://"},
		// A port is required rather than defaulted: the control plane's port is
		// configurable, so a guess produces a connection refused somewhere the
		// user never asked to connect.
		{"no port", "fox-realtime://rtk_abc@127.0.0.1/app", "no port"},
		{"no branch", "fox-realtime://rtk_abc@127.0.0.1:8080/", "no branch"},
		{"no path at all", "fox-realtime://rtk_abc@127.0.0.1:8080", "no branch"},
		{"more than a branch", "fox-realtime://rtk_abc@127.0.0.1:8080/app/table", "more than one path segment"},
		{"an sslmode nobody implements", "fox-realtime://rtk_abc@127.0.0.1:8080/app?sslmode=prefer",
			"not one of require, verify-full, disable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseDSN(c.in)
			if err == nil {
				t.Fatalf("ParseDSN(%q) was accepted; want a refusal", c.in)
			}
			if !strings.Contains(err.Error(), c.wantIn) {
				t.Fatalf("ParseDSN(%q) said %q; want something containing %q", c.in, err, c.wantIn)
			}
		})
	}
}

// A DSN this package prints must be one it can read back. The round trip is
// what makes `fox realtime key create` trustworthy: the string handed to an
// application is the string a client will parse.
func TestDSNRoundTrip(t *testing.T) {
	for _, d := range []DSN{
		{Host: "127.0.0.1:8080", Branch: "app", Key: "rtk_abc", SSL: SSLRequire},
		{Host: "db.example.com:443", Branch: "main", Key: "rtk_xyz", SSL: SSLVerifyFull},
		{Host: "127.0.0.1:8080", Branch: "main", Key: "rtk_xyz", SSL: SSLDisable},
		{Host: "[::1]:8080", Branch: "b", Key: "rtk_1", SSL: SSLRequire},
		{Host: "127.0.0.1:8080", Branch: "app", SSL: SSLRequire}, // keyless
	} {
		back, err := ParseDSN(d.String())
		if err != nil {
			t.Fatalf("ParseDSN(%q): %v", d.String(), err)
		}
		if back != d {
			t.Fatalf("round trip of %q\n got %+v\nwant %+v", d.String(), back, d)
		}
	}
}

// The key must never reach a URL — not the path, not the query. This is the one
// property the whole shape exists to protect, so it is asserted on the strings
// a client actually requests rather than trusted to the comment that says so.
func TestKeyNeverInRequestURL(t *testing.T) {
	d := DSN{Host: "127.0.0.1:8080", Branch: "app", Key: "rtk_secret", SSL: SSLRequire}
	for _, u := range []string{d.StreamURL(""), d.StreamURL("0/1A2B3C"), d.TablesURL(), d.BaseURL()} {
		if strings.Contains(u, "rtk_secret") {
			t.Fatalf("the key is in a request URL: %q", u)
		}
	}
	if got, want := d.StreamURL(""), "https://127.0.0.1:8080/realtime/v1/branches/app/stream"; got != want {
		t.Fatalf("StreamURL() = %q, want %q", got, want)
	}
	if got, want := d.StreamURL("0/1A2B3C"), "https://127.0.0.1:8080/realtime/v1/branches/app/stream?since=0%2F1A2B3C"; got != want {
		t.Fatalf("StreamURL(since) = %q, want %q", got, want)
	}
	if got, want := d.TablesURL(), "https://127.0.0.1:8080/realtime/v1/branches/app/tables"; got != want {
		t.Fatalf("TablesURL() = %q, want %q", got, want)
	}
}

// sslmode=disable is the only one that drops TLS, and it has to be asked for.
func TestDSNScheme(t *testing.T) {
	for _, c := range []struct {
		mode SSLMode
		want string
	}{{SSLRequire, "https://h:1"}, {SSLVerifyFull, "https://h:1"}, {SSLDisable, "http://h:1"}} {
		d := DSN{Host: "h:1", Branch: "b", SSL: c.mode}
		if got := d.BaseURL(); got != c.want {
			t.Fatalf("sslmode=%s: BaseURL() = %q, want %q", c.mode, got, c.want)
		}
	}
	// And the zero value must not silently mean "no TLS". A DSN nobody set a
	// mode on is a programming mistake, not an instruction to drop encryption.
	if (DSN{Host: "h:1", Branch: "b"}).BaseURL() != "https://h:1" {
		t.Fatal("an unset sslmode dropped TLS")
	}
}

// Redacted is what goes in a log or a listing.
func TestRedacted(t *testing.T) {
	// Deliberately low-entropy. A realistic-looking key here reads as a real
	// one to secret scanning — the first version of this fixture failed the
	// security job in CI — and an allowlist entry would weaken the scanner for
	// a test's convenience. The repeated runs keep the prefix and the tail
	// distinguishable, which is all this test needs.
	const key = "rtk_aaaabbbbccccdddd"
	d := DSN{Host: "127.0.0.1:8080", Branch: "app", Key: key, SSL: SSLRequire}
	got := d.Redacted()
	if strings.Contains(got, "ccccdddd") {
		t.Fatalf("Redacted() leaked the key: %q", got)
	}
	if !strings.Contains(got, "rtk_aaaabbbb") {
		t.Fatalf("Redacted() = %q; want the visible prefix so a key can be identified", got)
	}
	// A keyless DSN redacts to itself rather than growing an empty userinfo.
	if k := (DSN{Host: "h:1", Branch: "b", SSL: SSLRequire}); k.Redacted() != k.String() {
		t.Fatalf("keyless Redacted() = %q, want %q", k.Redacted(), k.String())
	}
}
