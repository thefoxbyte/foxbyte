// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"
)

func newKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestRegisterAppAndKeys(t *testing.T) {
	s := testStore(t)
	if _, err := s.CreateUser("shop@example.com", "password123"); err != nil {
		t.Fatal(err)
	}
	a, err := s.RegisterApp("shop", "shop@example.com", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if a.Account != "shop@example.com" || a.MaxLife != 300 || a.OnInvalid != "none" || len(a.Keys) != 0 {
		t.Fatalf("registered %+v, want the account, 5 minutes, none, and no keys yet", a)
	}
	if _, err := s.RegisterApp("shop", "shop@example.com", 0, ""); !errors.Is(err, ErrAppExists) {
		t.Errorf("a second registration under one name: %v, want ErrAppExists", err)
	}

	pub := newKey(t)
	k, err := s.AddAppKey("shop", "", pub)
	if err != nil {
		t.Fatal(err)
	}
	if k.Kid != Thumbprint(pub) || k.PublicKey != hex.EncodeToString(pub) || !k.Active() {
		t.Errorf("key %+v: want the thumbprint as its id, the key in hex, and active", k)
	}
	if _, err := s.AddAppKey("shop", k.Kid, newKey(t)); !errors.Is(err, ErrAppKeyFound) {
		t.Errorf("a second key under one id: %v, want ErrAppKeyFound", err)
	}
	if _, err := s.RegisterApp("other", "shop@example.com", 0, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddAppKey("other", "", pub); err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Errorf("one key for two applications: %v, want a refusal", err)
	}

	since := time.Unix(1_700_000_000, 0)
	if err := s.RevokeAppKey("shop", k.Kid, &since); err != nil {
		t.Fatal(err)
	}
	got, err := s.App("shop")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Keys) != 1 || got.Keys[0].Active() || got.Keys[0].CompromisedSince == nil || *got.Keys[0].CompromisedSince != since.Unix() {
		t.Errorf("after revoking with a compromise time: %+v", got.Keys)
	}
	// Revoking again keeps the first revocation's time.
	first := *got.Keys[0].Revoked
	time.Sleep(1100 * time.Millisecond)
	if err := s.RevokeAppKey("shop", k.Kid, nil); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.App("shop"); *again.Keys[0].Revoked != first || again.Keys[0].CompromisedSince == nil {
		t.Errorf("a second revocation changed the record: %+v", again.Keys[0])
	}
	if err := s.RevokeAppKey("shop", "nope", nil); !errors.Is(err, ErrAppNoKey) {
		t.Errorf("revoking a key that is not there: %v, want ErrAppNoKey", err)
	}
	if err := s.RevokeAppKey("nope", "nope", nil); !errors.Is(err, ErrAppNotFound) {
		t.Errorf("revoking for an application that is not there: %v, want ErrAppNotFound", err)
	}

	if err := s.RemoveApp("shop"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.App("shop"); !errors.Is(err, ErrAppNotFound) {
		t.Errorf("after removal: %v", err)
	}
	var n int
	_ = s.db.QueryRow(`SELECT count(*) FROM app_keys WHERE app = 'shop'`).Scan(&n)
	if n != 0 {
		t.Errorf("removing an application left %d of its keys", n)
	}
	if err := s.RemoveApp("shop"); !errors.Is(err, ErrAppNotFound) {
		t.Errorf("removing it twice: %v", err)
	}
}

func TestRegisterAppRefuses(t *testing.T) {
	s := testStore(t)
	if _, err := s.CreateUser("shop@example.com", "password123"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, account, onInvalid string
		life                     time.Duration
		want                     string
	}{
		{"Shop", "shop@example.com", "", 0, "lower-case"},
		{"", "shop@example.com", "", 0, "lower-case"},
		{"shop app", "shop@example.com", "", 0, "lower-case"},
		{"shop", "nobody@example.com", "", 0, "no account"},
		{"shop", "shop@example.com", "", 61 * time.Minute, "at most"},
		{"shop", "shop@example.com", "", 500 * time.Millisecond, "at least a second"},
		{"shop", "shop@example.com", "ignore", 0, "neither"},
	} {
		if _, err := s.RegisterApp(c.name, c.account, c.life, c.onInvalid); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("RegisterApp(%q, %q, %s, %q) = %v, want an error saying %q", c.name, c.account, c.life, c.onInvalid, err, c.want)
		}
	}
	a, err := s.RegisterApp("shop", "shop@example.com", 60*time.Minute, "refuse")
	if err != nil || a.MaxLife != 3600 || a.OnInvalid != "refuse" {
		t.Errorf("the limits themselves: %+v, %v", a, err)
	}
	if _, err := s.AddAppKey("shop", "a kid with spaces", newKey(t)); err == nil {
		t.Error("a key id with spaces was taken")
	}
	if _, err := s.AddAppKey("nope", "", newKey(t)); !errors.Is(err, ErrAppNotFound) {
		t.Errorf("a key for an application that is not there: %v", err)
	}
}

// The install id is made once, and every later ask gets the same one.
func TestInstallID(t *testing.T) {
	s := testStore(t)
	a, err := s.InstallID()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := s.InstallID()
	if a != b || !strings.HasPrefix(a, "install-") || len(a) != len("install-")+20 {
		t.Errorf("install ids %q and %q: want one, install- and 20 hex digits", a, b)
	}
}

// RFC 8037, appendix A.3: the thumbprint of its example Ed25519 key.
func TestThumbprintMatchesRFC8037(t *testing.T) {
	x, _ := base64.RawURLEncoding.DecodeString("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
	if got := Thumbprint(x); got != "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" {
		t.Errorf("thumbprint %s", got)
	}
}

func TestParsePublicKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	pemPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	pder, _ := x509.MarshalPKCS8PrivateKey(priv)
	pemPriv := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pder})
	x := base64.RawURLEncoding.EncodeToString(pub)
	for name, in := range map[string]string{
		"PEM":       string(pemPub),
		"JWK":       `{"kty":"OKP","crv":"Ed25519","x":"` + x + `"}`,
		"hex":       hex.EncodeToString(pub),
		"base64":    base64.StdEncoding.EncodeToString(pub),
		"base64url": x,
		"padded":    "  " + hex.EncodeToString(pub) + "\n",
	} {
		got, err := ParsePublicKey([]byte(in))
		if err != nil || !got.Equal(pub) {
			t.Errorf("%s: %v, %v", name, got, err)
		}
	}
	for name, c := range map[string]struct{ in, want string }{
		"private PEM": {string(pemPriv), "private key"},
		"private JWK": {`{"kty":"OKP","crv":"Ed25519","x":"` + x + `","d":"xx"}`, "private key"},
		"other curve": {`{"kty":"EC","crv":"P-256","x":"abc"}`, "Ed25519"},
		"short":       {hex.EncodeToString(pub[:16]), "bytes"},
		"nonsense":    {"not a key at all!", "not an Ed25519 public key"},
	} {
		if _, err := ParsePublicKey([]byte(c.in)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error saying %q", name, err, c.want)
		}
	}
}

// The applications reach the standby with the accounts, and a document from a
// node older than them leaves this node's applications alone.
func TestAppsAreCarried(t *testing.T) {
	a := testStore(t)
	if _, err := a.CreateUser("shop@example.com", "password123"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RegisterApp("shop", "shop@example.com", 0, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddAppKey("shop", "k1", newKey(t)); err != nil {
		t.Fatal(err)
	}
	id, _ := a.InstallID()
	doc, _, err := a.SharedState()
	if err != nil {
		t.Fatal(err)
	}
	b := testStore(t)
	if _, err := b.ApplySharedState(doc); err != nil {
		t.Fatal(err)
	}
	got, err := b.App("shop")
	if err != nil || len(got.Keys) != 1 || got.Keys[0].Kid != "k1" {
		t.Fatalf("on the other node: %+v, %v", got, err)
	}
	if bid, _ := b.InstallID(); bid != id {
		t.Errorf("install id %q on the other node, want %q", bid, id)
	}

	old := strings.NewReplacer(`"apps":`, `"x_apps":`, `"app_keys":`, `"x_app_keys":`, `"install_info":`, `"x_install_info":`).Replace(string(doc))
	if _, err := b.ApplySharedState([]byte(old)); err != nil {
		t.Fatalf("a document without the application tables: %v", err)
	}
	if _, err := b.App("shop"); err != nil {
		t.Errorf("a document from an older node removed the application: %v", err)
	}
}
