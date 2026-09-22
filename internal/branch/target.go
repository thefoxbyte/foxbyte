// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// Where backups go (audit v2 G18). By default the WAL archive and every base
// backup go to the object store the engine runs beside main — on the same
// disk, so one disk or host failure takes main and every backup of it. A
// remote target is any S3-compatible bucket, ideally created with Object Lock
// so nothing written there can be changed or deleted before its retention
// ends; the Blackbox and security-log anchors are copied there too.
//
// The target is a file in the state directory (0600: it holds the bucket's
// secret key), set with `fox backup target set`. No file means the local
// object store, exactly as before.

// Target is where the WAL archive, base backups and anchor copies go.
type Target struct {
	Kind      string `json:"kind"`             // "local" or "s3"
	Endpoint  string `json:"endpoint"`         // https://s3.eu-west-1.amazonaws.com
	Bucket    string `json:"bucket"`           //
	Prefix    string `json:"prefix,omitempty"` // a path inside the bucket
	Region    string `json:"region"`           //
	AccessKey string `json:"access_key"`       //
	SecretKey string `json:"secret_key"`       //
	PathStyle bool   `json:"path_style"`       // bucket in the path, not the host name (MinIO and most non-AWS stores)
}

func targetPath() string { return brand.StatePath("backup-target.json") }

// localTarget is the object store beside main.
func localTarget() Target {
	return Target{Kind: "local", Endpoint: objStoreEndpoint, Bucket: walBucket, Region: "us-east-1",
		AccessKey: minioUser(), SecretKey: minioPass(), PathStyle: true}
}

// CurrentTarget is the target in force. A file that cannot be read is an
// error rather than a silent fall back to the local store: backups would go
// somewhere the owner did not choose.
func CurrentTarget() (Target, error) {
	b, err := os.ReadFile(targetPath())
	if errors.Is(err, os.ErrNotExist) {
		return localTarget(), nil
	}
	if err != nil {
		return Target{}, err
	}
	var t Target
	if err := json.Unmarshal(b, &t); err != nil {
		return Target{}, fmt.Errorf("%s: %w", targetPath(), err)
	}
	if t.Kind != "s3" {
		return localTarget(), nil
	}
	return t, nil
}

// target is CurrentTarget for the paths that cannot return an error; a broken
// file is reported once per call site by the commands that read it directly.
func target() Target {
	t, err := CurrentTarget()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: backup target: %v — using the local object store\n", err)
		return localTarget()
	}
	return t
}

// Remote reports whether backups leave this machine.
func (t Target) Remote() bool { return t.Kind == "s3" }

// Root is the target's s3:// URL: the bucket and, when set, the prefix.
func (t Target) Root() string {
	if p := strings.Trim(t.Prefix, "/"); p != "" {
		return "s3://" + t.Bucket + "/" + p
	}
	return "s3://" + t.Bucket
}

// Describe is the target as a person reads it, without the secret.
func (t Target) Describe() string {
	if !t.Remote() {
		return "the local object store (" + objStore + ", on this machine)"
	}
	return fmt.Sprintf("%s at %s (region %s, key %s)", t.Root(), t.Endpoint, t.Region, t.AccessKey)
}

var (
	bucketRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	prefixRe = regexp.MustCompile(`^[A-Za-z0-9._/-]{0,200}$`)
)

// ParseTargetURL reads s3://bucket[/prefix].
func ParseTargetURL(s string) (bucket, prefix string, err error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), "s3://")
	if !ok {
		return "", "", fmt.Errorf("the target must be s3://bucket[/prefix], not %q", s)
	}
	bucket, prefix, _ = strings.Cut(rest, "/")
	prefix = strings.Trim(prefix, "/")
	if !bucketRe.MatchString(bucket) {
		return "", "", fmt.Errorf("%q is not a bucket name", bucket)
	}
	if !prefixRe.MatchString(prefix) || strings.Contains(prefix, "..") {
		return "", "", fmt.Errorf("%q is not a usable prefix", prefix)
	}
	return bucket, prefix, nil
}

// Validate checks a remote target's fields. allowHTTP permits an endpoint
// without TLS, which sends the secret key and every backup in the clear.
func (t Target) Validate(allowHTTP bool) error {
	u, err := url.Parse(t.Endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("the endpoint must be an http(s) URL, not %q", t.Endpoint)
	}
	if u.Scheme == "http" && !allowHTTP {
		return fmt.Errorf("%s is not HTTPS: the secret key and every backup would cross the network in the clear (pass --allow-http to accept that)", t.Endpoint)
	}
	if !bucketRe.MatchString(t.Bucket) {
		return fmt.Errorf("%q is not a bucket name", t.Bucket)
	}
	if t.AccessKey == "" || t.SecretKey == "" {
		return errors.New("an access key and a secret key are needed")
	}
	if t.Region == "" {
		return errors.New("a region is needed (us-east-1 for most non-AWS stores)")
	}
	return nil
}

// SaveTarget writes the target file (0600), or removes it for the local store.
func SaveTarget(t Target) error {
	if !t.Remote() {
		err := os.Remove(targetPath())
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(targetPath()), 0o700); err != nil {
		return err
	}
	return writeSecretFile(targetPath(), b)
}

// ---- how containers reach the target ----
//
// Like the Postgres password (pgenv.go), the target's keys reach docker in
// 0600 env files in the state directory, never as command-line arguments.

// s3EnvContent is the wal-g environment for a target, without the prefix
// (which differs per cluster; see walgPrefixFor).
func s3EnvContent(t Target) string {
	pathStyle := "false"
	if t.PathStyle {
		pathStyle = "true"
	}
	return "AWS_ACCESS_KEY_ID=" + t.AccessKey + "\n" +
		"AWS_SECRET_ACCESS_KEY=" + t.SecretKey + "\n" +
		"AWS_ENDPOINT=" + t.Endpoint + "\n" +
		"AWS_S3_FORCE_PATH_STYLE=" + pathStyle + "\n" +
		"AWS_REGION=" + t.Region + "\n"
}

// mcEnvContent is the MinIO client's environment for a target: alias "t".
func mcEnvContent(t Target) string {
	u, err := url.Parse(t.Endpoint)
	if err != nil {
		return ""
	}
	u.User = url.UserPassword(t.AccessKey, t.SecretKey)
	return "MC_HOST_t=" + u.String() + "\n"
}

// s3EnvFile and mcEnvFile write their files when the content differs, and
// return the path for --env-file.
func s3EnvFile() string { return envFile("s3.env", s3EnvContent(target())) }
func mcEnvFile() string { return envFile("mc.env", mcEnvContent(target())) }

// localMCEnvFile is the MinIO client's environment for the local store,
// whatever the target: Up prepares its bucket.
func localMCEnvFile() string { return envFile("mc-local.env", mcEnvContent(localTarget())) }

// minioEnvFile holds the local object store's root credentials.
func minioEnvFile() string {
	return envFile("minio.env", "MINIO_ROOT_USER="+minioUser()+"\nMINIO_ROOT_PASSWORD="+minioPass()+"\n")
}

func envFile(name, content string) string {
	p := brand.StatePath(name)
	if cur, err := os.ReadFile(p); err == nil && string(cur) == content {
		return p
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err == nil {
		if err := writeSecretFile(p, []byte(content)); err != nil {
			fmt.Fprintf(os.Stderr, "warning: writing %s: %v\n", p, err)
		}
	}
	return p
}

// writeSecretFile writes a 0600 file beside its destination and renames it
// over, so no reader sees half of it.
func writeSecretFile(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(b)
	cerr := tmp.Close()
	if werr == nil && cerr == nil {
		if err := os.Chmod(tmp.Name(), 0o600); err == nil {
			if err := os.Rename(tmp.Name(), path); err == nil {
				return nil
			}
		}
	}
	_ = os.Remove(tmp.Name())
	if werr != nil {
		return werr
	}
	if cerr != nil {
		return cerr
	}
	return fmt.Errorf("could not replace %s", path)
}
