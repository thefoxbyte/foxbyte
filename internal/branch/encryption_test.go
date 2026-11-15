// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/secrets"
)

// Client-side encryption of the backups (PRIV-6). wal-g decrypts every object
// it reads once a key is configured, and an object written without one does
// not open, so these hold the two things that keep an archive restorable: the
// key reaches every wal-g run the same way, and a target that was plain stays
// plain.

func encryptedTestTarget(t *testing.T) (Target, string) {
	t.Helper()
	k, err := secrets.EnsureBackupKey()
	if err != nil {
		t.Fatal(err)
	}
	return Target{Kind: "s3", Endpoint: "https://s3.example.com", Bucket: "fox-backups", Prefix: "enc", Region: "eu-west-1",
		AccessKey: "AK", SecretKey: "SK", Encrypted: true, KeyID: secrets.BackupKeyID(k)}, k
}

func TestEncryptionEnvironment(t *testing.T) {
	tg, k := encryptedTestTarget(t)
	env := s3EnvContent(tg)
	for _, want := range []string{"WALG_LIBSODIUM_KEY=" + k + "\n", "WALG_LIBSODIUM_KEY_TRANSFORM=hex\n"} {
		if !strings.Contains(env, want) {
			t.Errorf("an encrypted target's env is missing %q", want)
		}
	}

	// A plain target and the local store get no encryption settings at all:
	// an archive written without a key must be read without one.
	plain := tg
	plain.Encrypted, plain.KeyID = false, ""
	for name, tt := range map[string]Target{"plain remote": plain, "local": localTarget()} {
		if strings.Contains(s3EnvContent(tt), "WALG_LIBSODIUM") {
			t.Errorf("%s target has encryption settings:\n%s", name, s3EnvContent(tt))
		}
	}

	// A key that is not the archive's is never handed over, and neither is
	// nothing: wal-g gets a key file that does not exist, and fails rather than
	// writing plain objects into an encrypted archive.
	wrong := tg
	wrong.KeyID = "0000000000000000"
	env = s3EnvContent(wrong)
	if strings.Contains(env, k) || !strings.Contains(env, "WALG_LIBSODIUM_KEY_PATH="+missingKeyPath+"\n") {
		t.Errorf("a target whose key is not here got:\n%s", env)
	}
	if wrong.KeyProblem() == nil || tg.KeyProblem() != nil || plain.KeyProblem() != nil {
		t.Error("KeyProblem misjudged a target")
	}
}

// Every wal-g run gets its environment from the one env file, through
// walgEnvFor, and the key is in the file, not in the arguments.
func TestEncryptionReachesEveryWalgRun(t *testing.T) {
	tg, k := encryptedTestTarget(t)
	if err := SaveTarget(tg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = SaveTarget(Target{Kind: "local"}) })

	for name, args := range map[string][]string{
		"walgEnv":                 walgEnvFor("s3://fox-backups/enc"),
		"the standby":             standbyRunArgs("/data/standby"),
		"an upgraded prefix (pg)": walgEnvFor(walgPrefixFor("pg18-abc")),
	} {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, k) {
			t.Errorf("%s: the backup key is on the command line", name)
		}
		if !strings.Contains(joined, "--env-file "+s3EnvFile()) {
			t.Errorf("%s: no env file in %s", name, joined)
		}
	}
	b, err := os.ReadFile(s3EnvFile())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "WALG_LIBSODIUM_KEY="+k+"\n") {
		t.Error("the env file every wal-g run reads has no key")
	}

	// Each container that runs wal-g — main (archive_command, backup-push),
	// backup-list and delete, the point-in-time restores (backup-fetch,
	// wal-fetch) and the standby — is given walgEnv. One that is not would read
	// an encrypted archive without the key.
	files, _ := filepath.Glob("*.go")
	launches := regexp.MustCompile(`pgImage\(\), "wal-g"|restorePITRScript,|restoreBeforeScript\)`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, _ := os.ReadFile(f)
		lines := strings.Split(string(src), "\n")
		for i, l := range lines {
			if !launches.MatchString(l) || strings.HasPrefix(strings.TrimSpace(l), "//") {
				continue
			}
			found := false
			for j := max(0, i-25); j < i; j++ {
				if strings.Contains(lines[j], "walgEnv()") {
					found = true
				}
			}
			if !found {
				t.Errorf("%s:%d runs wal-g without walgEnv: %s", f, i+1, strings.TrimSpace(l))
			}
		}
		// Only target.go writes the encryption settings, into the env file.
		if f != "target.go" && strings.Contains(string(src), "WALG_LIBSODIUM") {
			t.Errorf("%s sets wal-g encryption itself", f)
		}
	}
}

// A target file written before encryption existed has no "encrypted" field. It
// must load as plain and get no key, or every backup already in it stops
// restoring the moment the engine is upgraded.
func TestExistingPlainTargetKeepsRestoring(t *testing.T) {
	old := `{"kind":"s3","endpoint":"https://s3.example.com","bucket":"fox-backups","region":"eu-west-1","access_key":"a","secret_key":"s","path_style":false}`
	var tg Target
	if err := json.Unmarshal([]byte(old), &tg); err != nil {
		t.Fatal(err)
	}
	if tg.Encrypted || strings.Contains(s3EnvContent(tg), "WALG_LIBSODIUM") || tg.KeyProblem() != nil {
		t.Fatalf("an old target became encrypted: %+v", tg)
	}
	// Setting the same target again (new keys, say) keeps it plain.
	if enc, err := chooseEncryption(tg, tg, "", true, nil); err != nil || enc {
		t.Errorf("re-setting the plain target in force: encrypted=%v, %v", enc, err)
	}
	// And it reads back from disk as plain, too.
	if err := SaveTarget(tg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = SaveTarget(Target{Kind: "local"}) })
	got, err := CurrentTarget()
	if err != nil || got.Encrypted {
		t.Errorf("read back: %+v, %v", got, err)
	}
}

func TestChooseEncryption(t *testing.T) {
	fresh := Target{Kind: "s3", Endpoint: "https://s3.example.com", Bucket: "b", Prefix: "new"}
	cur := Target{Kind: "s3", Endpoint: "https://s3.example.com", Bucket: "b", Prefix: "old"}
	listErr := errors.New("access denied")
	for _, c := range []struct {
		name    string
		choice  string
		holds   bool
		listErr error
		want    bool
		wantErr bool
	}{
		{"an empty location is encrypted", "", false, nil, true, false},
		{"a location with an archive needs a choice", "", true, nil, false, true},
		{"a location that cannot be listed needs a choice", "", false, listErr, false, true},
		{"--no-encrypt for an old plain archive", EncryptOff, true, nil, false, false},
		{"--encrypt", EncryptOn, true, nil, true, false},
		{"nonsense", "maybe", false, nil, false, true},
	} {
		got, err := chooseEncryption(fresh, cur, c.choice, c.holds, c.listErr)
		if got != c.want || (err != nil) != c.wantErr {
			t.Errorf("%s: %v, %v", c.name, got, err)
		}
	}
	// The encrypted target in force, set again, stays encrypted.
	encCur := fresh
	encCur.Encrypted = true
	if got, err := chooseEncryption(fresh, encCur, "", true, nil); !got || err != nil {
		t.Errorf("re-setting an encrypted target: %v, %v", got, err)
	}
}

func TestListingHoldsArchive(t *testing.T) {
	if !listingHoldsArchive("[2026-01-01 00:00:00 UTC]     0B basebackups_005/\n[2026-01-01 00:00:00 UTC]     0B wal_005/\n") {
		t.Error("a wal-g archive was not seen")
	}
	if !listingHoldsArchive("[2026-01-01 00:00:00 UTC]     0B pg18-abc/\n[2026-01-01 00:00:00 UTC]     0B wal_005/\n") {
		t.Error("an upgraded cluster's archive was not seen")
	}
	if listingHoldsArchive("") || listingHoldsArchive("[2026-01-01 00:00:00 UTC]     0B anchors/\n") {
		t.Error("an empty location, or one with only anchors, counted as an archive")
	}
}
