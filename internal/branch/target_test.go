// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestParseTargetURL(t *testing.T) {
	for in, want := range map[string][2]string{
		"s3://my-backups":           {"my-backups", ""},
		"s3://my-backups/prod/fox/": {"my-backups", "prod/fox"},
	} {
		b, p, err := ParseTargetURL(in)
		if err != nil || b != want[0] || p != want[1] {
			t.Errorf("ParseTargetURL(%q) = %q, %q, %v", in, b, p, err)
		}
	}
	for _, bad := range []string{"https://x/y", "s3://A_B", "s3://ok-bucket/../x", "s3://x", "s3://ok-bucket/sp ace"} {
		if _, _, err := ParseTargetURL(bad); err == nil {
			t.Errorf("ParseTargetURL(%q) accepted", bad)
		}
	}
}

func TestTargetValidate(t *testing.T) {
	ok := Target{Kind: "s3", Endpoint: "https://s3.example.com", Bucket: "fox-backups", Region: "eu-west-1", AccessKey: "a", SecretKey: "s"}
	if err := ok.Validate(false); err != nil {
		t.Fatalf("a good target: %v", err)
	}
	plain := ok
	plain.Endpoint = "http://minio.internal:9000"
	if err := plain.Validate(false); err == nil || !strings.Contains(err.Error(), "--allow-http") {
		t.Errorf("plain HTTP without --allow-http: %v", err)
	}
	if err := plain.Validate(true); err != nil {
		t.Errorf("plain HTTP with --allow-http: %v", err)
	}
	noKey := ok
	noKey.SecretKey = ""
	if noKey.Validate(false) == nil {
		t.Error("a target without a secret key was accepted")
	}
}

func TestTargetEnvironment(t *testing.T) {
	tg := Target{Kind: "s3", Endpoint: "https://s3.example.com", Bucket: "b", Prefix: "p/q", Region: "eu-west-1",
		AccessKey: "AK", SecretKey: "s/e:cr@t", PathStyle: false}
	if tg.Root() != "s3://b/p/q" {
		t.Errorf("Root = %q", tg.Root())
	}
	env := s3EnvContent(tg)
	for _, want := range []string{"AWS_ACCESS_KEY_ID=AK\n", "AWS_SECRET_ACCESS_KEY=s/e:cr@t\n", "AWS_ENDPOINT=https://s3.example.com\n",
		"AWS_S3_FORCE_PATH_STYLE=false\n", "AWS_REGION=eu-west-1\n"} {
		if !strings.Contains(env, want) {
			t.Errorf("s3 env is missing %q:\n%s", want, env)
		}
	}
	// The secret has characters that mean something in a URL; mc must get it whole.
	if got := mcEnvContent(tg); got != "MC_HOST_t=https://AK:s%2Fe%3Acr%40t@s3.example.com\n" {
		t.Errorf("mc env = %q", got)
	}
	if strings.Contains(tg.Describe(), "s/e:cr@t") {
		t.Error("Describe shows the secret key")
	}
	if !localTarget().PathStyle || localTarget().Remote() || localTarget().Root() != "s3://"+walBucket {
		t.Errorf("local target: %+v", localTarget())
	}
}

// The target file holds the secret key: 0600, and removed for the local store.
func TestSaveTarget(t *testing.T) {
	tg := Target{Kind: "s3", Endpoint: "https://s3.example.com", Bucket: "fox-backups", Region: "r", AccessKey: "a", SecretKey: "s"}
	if err := SaveTarget(tg); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(targetPath())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("target file mode %v, want 0600", fi.Mode().Perm())
	}
	if got, err := CurrentTarget(); err != nil || got.Root() != "s3://fox-backups" {
		t.Errorf("read back: %+v, %v", got, err)
	}
	if err := SaveTarget(Target{Kind: "local"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := CurrentTarget(); got.Remote() {
		t.Error("going back to local left the remote target in force")
	}
}

func TestBackupSchedule(t *testing.T) {
	for v, want := range map[string]time.Duration{"": 24 * time.Hour, "6h": 6 * time.Hour, "off": 0, "10s": 24 * time.Hour} {
		t.Setenv("FOX_BACKUP_INTERVAL", v)
		if got := backupInterval(); got != want {
			t.Errorf("FOX_BACKUP_INTERVAL=%q: %v, want %v", v, got, want)
		}
	}
	for v, want := range map[string]int{"": 7, "3": 3, "0": 7, "x": 7} {
		t.Setenv("FOX_BACKUP_RETAIN", v)
		if got := backupRetain(); got != want {
			t.Errorf("FOX_BACKUP_RETAIN=%q: %d, want %d", v, got, want)
		}
	}
}
