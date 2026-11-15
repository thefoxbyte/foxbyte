// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"
)

// The version line (finding SUP-4) must read as an ordinary checksum line to
// every parser already released, and as the version to this one.
func TestVersionLine(t *testing.T) {
	line := VersionLine("v2.3.0")
	if line != strings.Repeat("0", 64)+"  VERSION=v2.3.0" {
		t.Fatalf("VersionLine = %q", line)
	}
	if m := sumLine.FindStringSubmatch(line); m == nil || m[2] != "VERSION=v2.3.0" {
		t.Fatalf("the line is not a checksum line to the parser fox has always used: %v", m)
	}
	body := line + "\n" + strings.Repeat("a", 64) + "  fox-linux-amd64\n"
	sums, v, err := ParseSignedSums(strings.NewReader(body))
	if err != nil || v != "v2.3.0" || len(sums) != 1 || sums["fox-linux-amd64"] == "" {
		t.Fatalf("ParseSignedSums = %v, %q, %v", sums, v, err)
	}
	if _, listed := sums["VERSION=v2.3.0"]; listed {
		t.Error("the version line is listed as a file")
	}
	if _, v, _ := ParseSignedSums(strings.NewReader(strings.Repeat("a", 64) + "  fox\n")); v != "" {
		t.Errorf("a file without the line names version %q", v)
	}
	two := VersionLine("v2.3.0") + "\n" + VersionLine("v2.0.0") + "\n"
	if _, _, err := ParseSignedSums(strings.NewReader(two)); err == nil {
		t.Error("a file naming two versions was accepted")
	}
}

func TestCheckSignedVersion(t *testing.T) {
	cases := []struct {
		tag, signed string
		ok          bool
	}{
		{"v2.3.0", "v2.3.0", true},
		{"v2.3", "v2.3.0", true}, // the same version, written two ways
		{"v99.0.0", "v2.3.0", false},
		{"v2.3.0", "v2.3.0-rc1", false},
		{"v" + FirstVersionedRelease, "", false},
		{"v3.0.0", "", false},
		{"v2.2.1", "", true}, // older releases never had the line
		{"v2.3.0-rc1", "", true},
		{"v2.3.0", "garbage", false},
	}
	for _, c := range cases {
		if err := checkSignedVersion(c.tag, c.signed); (err == nil) != c.ok {
			t.Errorf("checkSignedVersion(%q, %q) = %v, want ok=%v", c.tag, c.signed, err, c.ok)
		}
	}
}

// An old signed release republished under a newer tag must not install,
// whether `fox update` finds it on its own or is pointed at it, and neither
// must `fox setup`.
func TestRetaggedReleaseIsRefused(t *testing.T) {
	linux := Target{GOOS: "linux", HostArch: "amd64"}
	ctx := context.Background()

	t.Run("signed for another version", func(t *testing.T) {
		f := newFakeGitHub(t)
		f.publishAs("v99.0.0", "v2.3.0", map[string]string{engLinuxAMD64: "old but signed"})
		c := f.client(t.TempDir() + "/cache.json")
		off, err := c.Resolve(ctx, mustVersion(t, "2.2.1"), linux, "")
		if off != nil || err == nil || !strings.Contains(err.Error(), "different release") {
			t.Fatalf("resolve = %+v, %v; want the retagged release reported", off, err)
		}
		// With the genuine release there too, that one is offered: the
		// retagged one is passed over, as a badly signed one is.
		f.publishAs("v2.3.0", "v2.3.0", map[string]string{engLinuxAMD64: "genuine"})
		c = f.client(t.TempDir() + "/cache.json")
		if off, err := c.Resolve(ctx, mustVersion(t, "2.2.1"), linux, ""); err != nil || off == nil || off.Release.Tag != "v2.3.0" {
			t.Fatalf("resolve = %+v, %v; want v2.3.0", off, err)
		}
		if _, err := c.Resolve(ctx, mustVersion(t, "2.2.1"), linux, "v99.0.0"); err == nil || !strings.Contains(err.Error(), "different release") {
			t.Errorf("pinning the retagged release: %v", err)
		}
		if _, err := c.Release(ctx, "latest", linux); err == nil || !strings.Contains(err.Error(), "different release") {
			t.Errorf("setup took the retagged release: %v", err)
		}
		off, err = c.Resolve(ctx, mustVersion(t, "2.2.1"), linux, "v2.3.0")
		if err != nil || off == nil || off.Release.Tag != "v2.3.0" {
			t.Errorf("the genuine release: %+v, %v", off, err)
		}
	})

	t.Run("no version line at or after the cutoff", func(t *testing.T) {
		f := newFakeGitHub(t)
		f.publish("v"+FirstVersionedRelease, map[string]string{engLinuxAMD64: "unversioned"})
		c := f.client(t.TempDir() + "/cache.json")
		if off, err := c.Resolve(ctx, mustVersion(t, "2.2.1"), linux, ""); off != nil || err == nil ||
			!strings.Contains(err.Error(), "does not say which version") {
			t.Fatalf("resolve = %+v, %v; want the unversioned release refused", off, err)
		}
		if _, err := c.Release(ctx, "v"+FirstVersionedRelease, linux); err == nil {
			t.Error("setup took an unversioned release past the cutoff")
		}
	})

	t.Run("an older release without the line still installs", func(t *testing.T) {
		f := newFakeGitHub(t)
		f.publish("v2.2.1", map[string]string{engLinuxAMD64: "old"})
		c := f.client(t.TempDir() + "/cache.json")
		off, err := c.Resolve(ctx, mustVersion(t, "2.2.0"), linux, "")
		if err != nil || off == nil || off.Release.Tag != "v2.2.1" {
			t.Fatalf("resolve = %+v, %v", off, err)
		}
		if o, err := c.Release(ctx, "v2.2.1", linux); err != nil || o.Release.Tag != "v2.2.1" {
			t.Errorf("setup of an explicit older release: %+v, %v", o, err)
		}
	})

	t.Run("never to a lower version, even when asked by tag", func(t *testing.T) {
		f := newFakeGitHub(t)
		f.publishAs("v2.3.0", "v2.3.0", map[string]string{engLinuxAMD64: "older"})
		c := f.client(t.TempDir() + "/cache.json")
		if off, err := c.Resolve(ctx, mustVersion(t, "2.4.0"), linux, ""); off != nil || err != nil {
			t.Errorf("an older release was offered: %+v, %v", off, err)
		}
		if _, err := c.Resolve(ctx, mustVersion(t, "2.4.0"), linux, "v2.3.0"); err == nil || !strings.Contains(err.Error(), "not newer") {
			t.Errorf("pinning an older release: %v", err)
		}
	})
}

// addP256 signs tag's SHA256SUMS with key and attaches it as SigP256Asset.
func (f *fakeGitHub) addP256(t *testing.T, tag string, key *ecdsa.PrivateKey) {
	t.Helper()
	h := sha256.Sum256(f.files["/dl/"+tag+"/SHA256SUMS"])
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	p := "/dl/" + tag + "/" + SigP256Asset
	f.files[p] = sig
	for i := range f.releases {
		if f.releases[i].Tag == tag {
			f.releases[i].Assets = append(f.releases[i].Assets, Asset{Name: SigP256Asset, URL: f.srv.URL + p})
		}
	}
}

// fox checks the P-256 signature too (finding SUP-5) whenever it has the key
// and the release has the signature, and a bad one is refused even though the
// Ed25519 signature is good.
func TestP256Signature(t *testing.T) {
	linux := Target{GOOS: "linux", HostArch: "amd64"}
	ctx := context.Background()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	t.Run("good", func(t *testing.T) {
		f := newFakeGitHub(t)
		t.Cleanup(TrustReleaseP256KeyForTest(&key.PublicKey))
		f.publishAs("v2.3.0", "v2.3.0", map[string]string{engLinuxAMD64: "x"})
		f.addP256(t, "v2.3.0", key)
		if off, err := f.client(t.TempDir()+"/c.json").Resolve(ctx, mustVersion(t, "2.2.1"), linux, ""); err != nil || off == nil {
			t.Fatalf("resolve = %+v, %v", off, err)
		}
	})
	t.Run("by another key", func(t *testing.T) {
		f := newFakeGitHub(t)
		t.Cleanup(TrustReleaseP256KeyForTest(&key.PublicKey))
		f.publishAs("v2.3.0", "v2.3.0", map[string]string{engLinuxAMD64: "x"})
		f.addP256(t, "v2.3.0", other)
		off, err := f.client(t.TempDir()+"/c.json").Resolve(ctx, mustVersion(t, "2.2.1"), linux, "")
		if off != nil || err == nil || !strings.Contains(err.Error(), "P-256") {
			t.Fatalf("resolve = %+v, %v; want the P-256 signature refused", off, err)
		}
	})
	t.Run("listed but not served", func(t *testing.T) {
		f := newFakeGitHub(t)
		t.Cleanup(TrustReleaseP256KeyForTest(&key.PublicKey))
		f.publishAs("v2.3.0", "v2.3.0", map[string]string{engLinuxAMD64: "x"})
		f.addP256(t, "v2.3.0", key)
		delete(f.files, "/dl/v2.3.0/"+SigP256Asset)
		if off, err := f.client(t.TempDir()+"/c.json").Resolve(ctx, mustVersion(t, "2.2.1"), linux, "v2.3.0"); off != nil || err == nil {
			t.Fatalf("resolve = %+v, %v; want an error", off, err)
		}
	})
	t.Run("a release from before the P-256 signature", func(t *testing.T) {
		f := newFakeGitHub(t)
		t.Cleanup(TrustReleaseP256KeyForTest(&key.PublicKey))
		f.publish("v2.2.1", map[string]string{engLinuxAMD64: "x"})
		if off, err := f.client(t.TempDir()+"/c.json").Resolve(ctx, mustVersion(t, "2.2.0"), linux, ""); err != nil || off == nil {
			t.Fatalf("resolve = %+v, %v", off, err)
		}
	})
	t.Run("a build without the key ignores it", func(t *testing.T) {
		f := newFakeGitHub(t)
		t.Cleanup(TrustReleaseP256KeyForTest(nil))
		f.publishAs("v2.3.0", "v2.3.0", map[string]string{engLinuxAMD64: "x"})
		f.addP256(t, "v2.3.0", other)
		if off, err := f.client(t.TempDir()+"/c.json").Resolve(ctx, mustVersion(t, "2.2.1"), linux, ""); err != nil || off == nil {
			t.Fatalf("resolve = %+v, %v", off, err)
		}
	})
	t.Run("VerifySumsP256", func(t *testing.T) {
		t.Cleanup(TrustReleaseP256KeyForTest(&key.PublicKey))
		msg := []byte("SHA256SUMS\n")
		h := sha256.Sum256(msg)
		sig, _ := ecdsa.SignASN1(rand.Reader, key, h[:])
		if err := VerifySumsP256(msg, sig); err != nil {
			t.Errorf("good signature: %v", err)
		}
		if err := VerifySumsP256(append(msg, '\n'), sig); err == nil {
			t.Error("altered file accepted")
		}
		restore := TrustReleaseP256KeyForTest(nil)
		defer restore()
		if err := VerifySumsP256(msg, sig); err != ErrNoReleaseKey {
			t.Errorf("no key: %v", err)
		}
	})
}
