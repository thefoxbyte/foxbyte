// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func mustVersion(t *testing.T, s string) Version {
	t.Helper()
	v, err := ParseVersion(s)
	if err != nil {
		t.Fatalf("ParseVersion(%q): %v", s, err)
	}
	return v
}

func TestParseVersion(t *testing.T) {
	for in, want := range map[string]string{
		"v0.8.1": "0.8.1", "0.8.1": "0.8.1", "v0.8": "0.8.0", "1": "1.0.0",
		"0.1.0-dev": "0.1.0-dev", "v0.9.0-rc1": "0.9.0-rc1", " v2.10.3 ": "2.10.3",
	} {
		if got := mustVersion(t, in).String(); got != want {
			t.Errorf("ParseVersion(%q) = %s, want %s", in, got, want)
		}
	}
	for _, bad := range []string{"", "v", "vx", "1.2.3.4", "1..2", "1.-2", "1.2.3-", "+1.2"} {
		if _, err := ParseVersion(bad); err == nil {
			t.Errorf("ParseVersion(%q) accepted", bad)
		}
	}
	if !mustVersion(t, "0.1.0-dev").IsDev() || mustVersion(t, "0.9.0-rc1").IsDev() || mustVersion(t, "0.9.0").IsDev() {
		t.Error("IsDev is wrong")
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v0.8", "0.8.0", 0},
		{"0.8.1", "v0.8", 1},
		{"0.10.0", "0.9.9", 1},
		{"0.9.0-rc1", "0.9.0", -1},
		{"0.9.0-rc1", "0.9.0-rc2", -1},
		{"0.8.2", "0.1.0-dev", 1},
		{"1.0.0", "0.99.99", 1},
	}
	for _, c := range cases {
		if got := mustVersion(t, c.a).Compare(mustVersion(t, c.b)); got != c.want {
			t.Errorf("%s vs %s = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestRequiredAssets(t *testing.T) {
	for _, c := range []struct {
		t    Target
		want string
	}{
		{Target{GOOS: "darwin", HostArch: "arm64", GuestArch: "arm64"}, "fox-darwin-arm64 fox-linux-arm64"},
		{Target{GOOS: "darwin", HostArch: "amd64"}, "fox-darwin-amd64 fox-linux-amd64"},
		{Target{GOOS: "windows", HostArch: "amd64"}, "fox-windows-amd64.exe fox-linux-amd64 foxbyte-docker-context.tar.gz"},
		{Target{GOOS: "linux", HostArch: "arm64"}, "fox-linux-arm64"},
	} {
		if got := strings.Join(RequiredAssets(c.t), " "); got != c.want {
			t.Errorf("RequiredAssets(%+v) = %q, want %q", c.t, got, c.want)
		}
	}
}

func rel(tag string, draft, pre bool, names ...string) Release {
	r := Release{Tag: tag, Draft: draft, Prerelease: pre, HTMLURL: "https://example/" + tag}
	for _, n := range names {
		r.Assets = append(r.Assets, Asset{Name: n, URL: "https://example/" + tag + "/" + n})
	}
	return r
}

func TestCandidates(t *testing.T) {
	linux := Target{GOOS: "linux", HostArch: "amd64"}
	full := []string{"SHA256SUMS", "SHA256SUMS.sig", "fox-linux-amd64", "fox-darwin-arm64"}
	rels := []Release{
		rel("v1.0.0", false, false, "SHA256SUMS"), // still publishing: only checksums so far
		rel("v0.9.5", false, true, full...),       // prerelease
		rel("v0.9.4", true, false, full...),       // draft
		rel("v0.9.2", false, false, full...),
		rel("v0.9", false, false, full...),
		rel("nightly", false, false, full...), // not a version
		rel("v0.8.2", false, false, full...),  // current
		rel("v0.8.1", false, false, full...),  // older
	}
	got, err := Candidates(rels, mustVersion(t, "0.8.2"), linux, "")
	if err != nil {
		t.Fatal(err)
	}
	var tags []string
	for _, r := range got {
		tags = append(tags, r.Tag)
	}
	if strings.Join(tags, ",") != "v0.9.2,v0.9" {
		t.Fatalf("candidates = %v", tags)
	}
	// darwin needs fox-linux-arm64, which none of these have.
	if got, _ := Candidates(rels, mustVersion(t, "0.8.2"), Target{GOOS: "darwin", HostArch: "arm64", GuestArch: "arm64"}, ""); len(got) != 0 {
		t.Fatalf("incomplete releases offered to darwin: %v", got)
	}
	// Pins.
	if got, err := Candidates(rels, mustVersion(t, "0.8.2"), linux, "v0.9.5"); err != nil || len(got) != 1 || got[0].Tag != "v0.9.5" {
		t.Fatalf("pinned prerelease: %v %v", got, err)
	}
	if _, err := Candidates(rels, mustVersion(t, "0.8.2"), linux, "v0.8.1"); err == nil || !strings.Contains(err.Error(), "not newer") {
		t.Fatalf("pinned older: %v", err)
	}
	if _, err := Candidates(rels, mustVersion(t, "0.8.2"), linux, "v1.0.0"); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("pinned incomplete: %v", err)
	}
	if _, err := Candidates(rels, mustVersion(t, "0.8.2"), linux, "v7.0.0"); err == nil {
		t.Fatal("pinned unknown release accepted")
	}
}

func TestChecksums(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fox-linux-amd64")
	os.WriteFile(path, []byte("binary"), 0o755)
	sum := sha256.Sum256([]byte("binary"))
	hexsum := hex.EncodeToString(sum[:])
	text := strings.ToUpper(hexsum) + " *fox-linux-amd64\r\n\r\n# comment\n" + strings.Repeat("a", 64) + "  other file.tar.gz\n"
	sums, err := ParseChecksums(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if sums["other file.tar.gz"] == "" || sums["fox-linux-amd64"] != hexsum {
		t.Fatalf("parsed %v", sums)
	}
	if err := sums.Verify("fox-linux-amd64", path); err != nil {
		t.Fatalf("verify: %v", err)
	}
	os.WriteFile(path, []byte("tampered"), 0o755)
	if err := sums.Verify("fox-linux-amd64", path); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("tampered file accepted: %v", err)
	}
	if err := sums.Verify("missing", path); err == nil {
		t.Fatal("unlisted file accepted")
	}
	for _, bad := range []string{"not a checksum line\n", strings.Repeat("a", 64) + "  x\n" + strings.Repeat("b", 64) + "  x\n"} {
		if _, err := ParseChecksums(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// fakeGitHub serves a releases list plus assets, like the GitHub API does.
type fakeGitHub struct {
	srv      *httptest.Server
	releases []Release
	files    map[string][]byte // path -> content
	delay    time.Duration
	lists    atomic.Int32
	assets   atomic.Int32 // asset downloads (SHA256SUMS, binaries)
	key      ed25519.PrivateKey
}

// newFakeGitHub serves releases signed by a key of the test's own, which the
// code under test is told to trust for the test's duration.
func newFakeGitHub(t *testing.T) *fakeGitHub {
	pub, key, _ := ed25519.GenerateKey(nil)
	old := releasePublicKey
	releasePublicKey = base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { releasePublicKey = old })
	f := &fakeGitHub{files: map[string][]byte{}, key: key}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.delay > 0 {
			time.Sleep(f.delay)
		}
		if r.URL.Path == "/repos/thefoxbyte/foxbyte/releases" {
			f.lists.Add(1)
			// Like GitHub, the ETag changes when the list does; a fixed ETag
			// would answer "not modified" right after a new release.
			etag := fmt.Sprintf(`"v%d"`, len(f.releases))
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", etag)
			json.NewEncoder(w).Encode(f.releases)
			return
		}
		if b, ok := f.files[r.URL.Path]; ok {
			f.assets.Add(1)
			w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// publish adds a release with the given files and a matching SHA256SUMS
// (skipping names in unlisted).
func (f *fakeGitHub) publish(tag string, files map[string]string, unlisted ...string) {
	r := Release{Tag: tag, HTMLURL: f.srv.URL + "/releases/" + tag}
	var sums strings.Builder
	skip := map[string]bool{}
	for _, u := range unlisted {
		skip[u] = true
	}
	for name, content := range files {
		p := "/dl/" + tag + "/" + name
		f.files[p] = []byte(content)
		r.Assets = append(r.Assets, Asset{Name: name, Size: int64(len(content)), URL: f.srv.URL + p})
		if !skip[name] {
			s := sha256.Sum256([]byte(content))
			fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(s[:]), name)
		}
	}
	p := "/dl/" + tag + "/SHA256SUMS"
	f.files[p] = []byte(sums.String())
	r.Assets = append(r.Assets, Asset{Name: "SHA256SUMS", URL: f.srv.URL + p})
	sp := "/dl/" + tag + "/SHA256SUMS.sig"
	f.files[sp] = ed25519.Sign(f.key, []byte(sums.String()))
	r.Assets = append(r.Assets, Asset{Name: "SHA256SUMS.sig", URL: f.srv.URL + sp})
	f.releases = append([]Release{r}, f.releases...)
}

func (f *fakeGitHub) client(cache string) *Client {
	return NewClient(func(k string) string {
		if k == "FOX_UPDATE_BASE_URL" {
			return f.srv.URL
		}
		return ""
	}, cache)
}

func TestResolveAndDownload(t *testing.T) {
	f := newFakeGitHub(t)
	linux := Target{GOOS: "linux", HostArch: "amd64"}
	f.publish("v0.98.0", map[string]string{"fox-linux-amd64": "old"})
	f.publish("v0.99.0", map[string]string{"fox-linux-amd64": "new"})
	f.publish("v0.99.1", map[string]string{"fox-linux-amd64": "unlisted"}, "fox-linux-amd64") // SHA256SUMS doesn't list it
	c := f.client(filepath.Join(t.TempDir(), "cache.json"))
	ctx := context.Background()

	o, err := c.Resolve(ctx, mustVersion(t, "0.98.0"), linux, "")
	if err != nil || o == nil {
		t.Fatalf("resolve: %v %v", o, err)
	}
	if o.Release.Tag != "v0.99.0" {
		t.Fatalf("offered %s, want v0.99.0 (v0.99.1's checksums are incomplete)", o.Release.Tag)
	}
	if n := Notice("0.98.0", o); n != "FoxByte v0.99.0 is available (you have 0.98.0). Run `fox update` to get the new capabilities." {
		t.Fatalf("notice %q", n)
	}
	if o, err := c.Resolve(ctx, mustVersion(t, "0.99.0"), linux, ""); err != nil || o != nil {
		t.Fatalf("up to date: %v %v", o, err)
	}
	if _, err := c.Resolve(ctx, mustVersion(t, "0.98.0"), linux, "v0.99.1"); err == nil {
		t.Fatal("pinned release with unlisted assets accepted")
	}
	// The releases list was answered from the cache after the first request.
	if f.lists.Load() < 3 {
		t.Fatalf("expected several list requests, got %d", f.lists.Load())
	}

	dir := t.TempDir()
	a, _ := o.Release.Asset("fox-linux-amd64")
	path, err := c.Download(ctx, a, o.Sums["fox-linux-amd64"], dir)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "new" {
		t.Fatalf("downloaded %q", b)
	}
	// A mismatch leaves nothing behind.
	bad := t.TempDir()
	if _, err := c.Download(ctx, a, strings.Repeat("0", 64), bad); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("mismatch: %v", err)
	}
	if entries, _ := os.ReadDir(bad); len(entries) != 0 {
		t.Fatalf("left behind: %v", entries)
	}
	if _, err := c.Download(ctx, Asset{Name: "x", URL: f.srv.URL + "/nope"}, "", t.TempDir()); err == nil {
		t.Fatal("404 accepted")
	}
}

func TestReleaseListCache(t *testing.T) {
	f := newFakeGitHub(t)
	f.publish("v0.99.0", map[string]string{"fox-linux-amd64": "new"})
	cache := filepath.Join(t.TempDir(), "cache.json")
	c := f.client(cache)
	for i := 0; i < 2; i++ {
		rels, err := c.ListReleases(context.Background())
		if err != nil || len(rels) != 1 {
			t.Fatalf("list %d: %v %v", i, rels, err)
		}
	}
	if _, err := os.Stat(cache); err != nil {
		t.Fatalf("cache not written: %v", err)
	}
}

func TestBackgroundCheck(t *testing.T) {
	f := newFakeGitHub(t)
	f.publish("v0.99.0", map[string]string{"fox-linux-amd64": "new"})
	linux := Target{GOOS: "linux", HostArch: "amd64"}

	got := BackgroundCheck(f.client(""), "0.98.0", linux, 5*time.Second)()
	if !strings.Contains(got, "v0.99.0 is available") {
		t.Fatalf("notice %q", got)
	}
	// A slow server doesn't hold start up: nothing is printed after the timeout.
	f.delay = 2 * time.Second
	start := time.Now()
	if got := BackgroundCheck(f.client(""), "0.98.0", linux, 200*time.Millisecond)(); got != "" {
		t.Fatalf("slow check printed %q", got)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("waited %s", time.Since(start))
	}
	// Offline.
	off := NewClient(func(k string) string {
		if k == "FOX_UPDATE_BASE_URL" {
			return "http://127.0.0.1:1"
		}
		return ""
	}, "")
	if got := BackgroundCheck(off, "0.98.0", linux, time.Second)(); got != "" {
		t.Fatalf("offline check printed %q", got)
	}
}

// The start-time check must not download release assets: GitHub throttles
// repeated downloads of the same asset (seconds to a minute), which kept the
// notice silent. The update path must still verify against SHA256SUMS.
func TestAvailableMakesNoAssetRequests(t *testing.T) {
	f := newFakeGitHub(t)
	linux := Target{GOOS: "linux", HostArch: "amd64"}
	f.publish("v0.99.0", map[string]string{"fox-linux-amd64": "new"})
	c := f.client("")
	ctx := context.Background()

	o, err := c.Available(ctx, mustVersion(t, "0.98.0"), linux)
	if err != nil || o == nil || o.Release.Tag != "v0.99.0" {
		t.Fatalf("available = %v, %v", o, err)
	}
	if o.Sums != nil {
		t.Error("the notice check downloaded SHA256SUMS")
	}
	if n := f.assets.Load(); n != 0 {
		t.Fatalf("the notice check made %d asset request(s), want 0", n)
	}
	if o, err := c.Available(ctx, mustVersion(t, "0.99.0"), linux); err != nil || o != nil {
		t.Fatalf("up to date: %v, %v", o, err)
	}
	if _, err := c.Resolve(ctx, mustVersion(t, "0.98.0"), linux, ""); err != nil {
		t.Fatal(err)
	}
	if f.assets.Load() == 0 {
		t.Error("the update path didn't download SHA256SUMS")
	}
}

func TestNoticeIsRememberedBetweenStarts(t *testing.T) {
	f := newFakeGitHub(t)
	linux := Target{GOOS: "linux", HostArch: "amd64"}
	f.publish("v0.99.0", map[string]string{"fox-linux-amd64": "new"})
	c := f.client(filepath.Join(t.TempDir(), "update-check.json"))

	first := BackgroundCheck(c, "0.98.0", linux, 5*time.Second)()
	if !strings.Contains(first, "v0.99.0 is available") {
		t.Fatalf("notice %q", first)
	}
	calls := f.lists.Load()
	if got := BackgroundCheck(c, "0.98.0", linux, 5*time.Second)(); got != first {
		t.Fatalf("remembered notice = %q, want %q", got, first)
	}
	if f.lists.Load() != calls {
		t.Error("the remembered check still asked GitHub")
	}
	// After an update the installed version differs, so the answer is refetched.
	if got := BackgroundCheck(c, "0.99.0", linux, 5*time.Second)(); got != "" {
		t.Errorf("after updating, notice = %q", got)
	}
	if f.lists.Load() == calls {
		t.Error("a different installed version reused the cache")
	}
	// "Up to date" is not remembered: the next start asks again.
	calls = f.lists.Load()
	if got := BackgroundCheck(c, "0.99.0", linux, 5*time.Second)(); got != "" || f.lists.Load() == calls {
		t.Error("an up-to-date answer was reused instead of asking GitHub again")
	}
	// Interval 0 checks on every start.
	t.Setenv(EnvCheckInterval, "0")
	calls = f.lists.Load()
	_ = BackgroundCheck(c, "0.99.0", linux, 5*time.Second)()
	if f.lists.Load() == calls {
		t.Error("interval 0 used the cache")
	}
	if CheckInterval(func(string) string { return "" }) != 6*time.Hour ||
		CheckInterval(func(string) string { return "30m" }) != 30*time.Minute {
		t.Error("CheckInterval")
	}
}

// A release published after a start found nothing must show on the very next
// start. Remembering "up to date" hid v0.8.7 for hours while `fox update
// --check` reported it.
func TestNewReleaseShowsOnNextStart(t *testing.T) {
	f := newFakeGitHub(t)
	linux := Target{GOOS: "linux", HostArch: "amd64"}
	f.publish("v0.98.0", map[string]string{"fox-linux-amd64": "current"})
	cache := filepath.Join(t.TempDir(), "update-check.json")
	c := f.client(cache)

	if got := BackgroundCheck(c, "0.98.0", linux, 5*time.Second)(); got != "" {
		t.Fatalf("up to date, but notice = %q", got)
	}
	f.publish("v0.99.0", map[string]string{"fox-linux-amd64": "new"})
	if got := BackgroundCheck(c, "0.98.0", linux, 5*time.Second)(); !strings.Contains(got, "v0.99.0 is available") {
		t.Fatalf("release published after an up-to-date check: next start printed %q", got)
	}

	// A cache written by an earlier version holds "up to date" as an empty
	// notice; it must not hide the release either.
	c2 := f.client(filepath.Join(t.TempDir(), "update-check.json"))
	old, _ := json.Marshal(noticeCache{CheckedAt: time.Now(), Repo: c2.Repo, Current: "0.98.0", Notice: ""})
	if err := os.WriteFile(c2.NoticePath, old, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := BackgroundCheck(c2, "0.98.0", linux, 5*time.Second)(); !strings.Contains(got, "v0.99.0 is available") {
		t.Fatalf("an old up-to-date cache hid the release: %q", got)
	}
}

// Release is what `fox setup` installs from: any published release with this
// platform's files, newest first, regardless of what is installed now.
func TestReleaseForSetup(t *testing.T) {
	f := newFakeGitHub(t)
	linux := Target{GOOS: "linux", HostArch: "amd64"}
	ctx := context.Background()
	f.publish("v0.98.0", map[string]string{"fox-linux-amd64": "old"})
	f.publish("v0.99.0", map[string]string{"fox-linux-amd64": "new"})
	c := f.client("")

	// Newest complete release, and its checksums come with it.
	o, err := c.Release(ctx, "latest", linux)
	if err != nil || o == nil || o.Release.Tag != "v0.99.0" {
		t.Fatalf("latest = %v, %v", o, err)
	}
	if o.Sums["fox-linux-amd64"] == "" {
		t.Error("Release didn't bring the checksums setup needs")
	}
	// "" means the same as "latest".
	if o, err := c.Release(ctx, "", linux); err != nil || o.Release.Tag != "v0.99.0" {
		t.Fatalf("empty tag = %v, %v", o, err)
	}
	// An older tag installs fine — setup is not an upgrade.
	if o, err := c.Release(ctx, "v0.98.0", linux); err != nil || o.Release.Tag != "v0.98.0" {
		t.Fatalf("pinned older = %v, %v", o, err)
	}
	if _, err := c.Release(ctx, "v7.0.0", linux); err == nil {
		t.Error("an unknown tag was accepted")
	}
	// A release still being published (no engine yet) is skipped, not offered.
	f.publish("v1.0.0", map[string]string{"fox-darwin-arm64": "wrong platform"})
	if o, err := c.Release(ctx, "latest", linux); err != nil || o.Release.Tag != "v0.99.0" {
		t.Fatalf("incomplete release offered: %v, %v", o, err)
	}
	if _, err := c.Release(ctx, "v1.0.0", linux); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Errorf("pinned incomplete release = %v, want a 'missing' error", err)
	}
}

func TestShouldCheck(t *testing.T) {
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	if !ShouldCheck(get, "0.8.2") {
		t.Error("release build should check")
	}
	if ShouldCheck(get, "0.1.0-dev") || ShouldCheck(get, "garbage") {
		t.Error("dev or unknown builds must not check")
	}
	env[EnvNoCheck] = "1"
	if ShouldCheck(get, "0.8.2") {
		t.Error("FOX_NO_UPDATE_CHECK=1 must turn the check off")
	}
	env["FOX_UPDATE_CHECK_TIMEOUT"] = "3s"
	if CheckTimeout(get) != 3*time.Second || CheckTimeout(func(string) string { return "" }) != 1500*time.Millisecond {
		t.Error("CheckTimeout")
	}
}

func TestInstallBinary(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "new")
	dest := filepath.Join(dir, "bin", "fox")
	os.MkdirAll(filepath.Dir(dest), 0o755)
	os.WriteFile(src, []byte("v2"), 0o644)
	os.WriteFile(dest, []byte("v1"), 0o755)
	prev := filepath.Join(dir, "updates", "prev", "fox")
	if err := InstallBinary(src, dest, prev); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "v2" {
		t.Fatalf("dest = %q", b)
	}
	if b, _ := os.ReadFile(prev); string(b) != "v1" {
		t.Fatalf("prev = %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "bin", ".update.new")); err == nil {
		t.Fatal("temporary file left behind")
	}
	if err := InstallBinary(filepath.Join(dir, "missing"), dest, prev); err == nil {
		t.Fatal("missing source accepted")
	}
	if b, _ := os.ReadFile(dest); string(b) != "v2" {
		t.Fatalf("failed install changed dest to %q", b)
	}
}

func TestSwapExecutable(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "new.exe")
	dest := filepath.Join(dir, "fox.exe")
	prev := filepath.Join(dir, "prev", "fox.exe")
	os.WriteFile(src, []byte("v2"), 0o644)
	os.WriteFile(dest, []byte("v1"), 0o755)
	if err := SwapExecutable(src, dest, prev); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{dest: "v2", prev: "v1", dest + ".old": "v1"} {
		if b, _ := os.ReadFile(path); string(b) != want {
			t.Errorf("%s = %q, want %q", filepath.Base(path), b, want)
		}
	}
	// A second swap replaces the leftover .old.
	os.WriteFile(src, []byte("v3"), 0o644)
	if err := SwapExecutable(src, dest, prev); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dest + ".old"); string(b) != "v2" {
		t.Errorf(".old = %q", b)
	}
	// A missing source changes nothing.
	if err := SwapExecutable(filepath.Join(dir, "missing"), dest, prev); err == nil {
		t.Fatal("missing source accepted")
	}
	if b, _ := os.ReadFile(dest); string(b) != "v3" {
		t.Fatalf("dest = %q", b)
	}
}

func writeTarGz(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg})
		tw.Write([]byte(content))
	}
	tw.Close()
	gz.Close()
	f.Close()
}

func TestReplaceDirFromTarGz(t *testing.T) {
	dir := t.TempDir()
	ctx := filepath.Join(dir, "docker-context")
	os.MkdirAll(ctx, 0o755)
	os.WriteFile(filepath.Join(ctx, "Dockerfile"), []byte("old"), 0o644)
	archive := filepath.Join(dir, "ctx.tar.gz")
	writeTarGz(t, archive, map[string]string{"./Dockerfile": "new", "./scripts/entry.sh": "#!/bin/sh"})
	if err := ReplaceDirFromTarGz(archive, ctx); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(ctx, "Dockerfile")); string(b) != "new" {
		t.Fatalf("Dockerfile = %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(ctx, "scripts", "entry.sh")); string(b) != "#!/bin/sh" {
		t.Fatalf("entry.sh = %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(ctx+".prev", "Dockerfile")); string(b) != "old" {
		t.Fatalf("prev Dockerfile = %q", b)
	}
	evil := filepath.Join(dir, "evil.tar.gz")
	writeTarGz(t, evil, map[string]string{"../escaped": "x"})
	if err := ReplaceDirFromTarGz(evil, ctx); err == nil {
		t.Fatal("path traversal accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "escaped")); err == nil {
		t.Fatal("file written outside the directory")
	}
	if b, _ := os.ReadFile(filepath.Join(ctx, "Dockerfile")); string(b) != "new" {
		t.Fatalf("failed replace changed the directory: %q", b)
	}
}

// The release workflow must publish every file `fox update` needs, for every
// platform, or updates to that platform silently never happen.
func TestReleaseWorkflowPublishesUpdateAssets(t *testing.T) {
	wf, err := os.ReadFile("../../.github/workflows/release.yml")
	if err != nil {
		t.Skip("release.yml not found")
	}
	check, err := os.ReadFile("../../scripts/check-release-assets.sh")
	if err != nil {
		t.Fatalf("scripts/check-release-assets.sh: %v", err)
	}
	for _, target := range []Target{
		{GOOS: "darwin", HostArch: "arm64", GuestArch: "arm64"},
		{GOOS: "darwin", HostArch: "amd64", GuestArch: "amd64"},
		{GOOS: "linux", HostArch: "arm64"},
		{GOOS: "linux", HostArch: "amd64"},
		{GOOS: "windows", HostArch: "amd64"},
	} {
		for _, name := range RequiredAssets(target) {
			if !strings.Contains(string(wf), name) {
				t.Errorf("release.yml doesn't build %s (needed to update %s/%s)", name, target.GOOS, target.HostArch)
			}
			if !strings.Contains(string(check), name) {
				t.Errorf("check-release-assets.sh doesn't check %s", name)
			}
		}
	}
}

// A release is installed only when its SHA256SUMS is signed with the release
// key: one signed by another key, or not signed at all, is passed over.
func TestResolveRequiresTheReleaseSignature(t *testing.T) {
	f := newFakeGitHub(t)
	linux := Target{GOOS: "linux", HostArch: "amd64"}
	f.publish("v0.9.0", map[string]string{"fox-linux-amd64": "good"})
	f.publish("v0.9.1", map[string]string{"fox-linux-amd64": "forged"})
	_, other, _ := ed25519.GenerateKey(nil)
	f.files["/dl/v0.9.1/SHA256SUMS.sig"] = ed25519.Sign(other, f.files["/dl/v0.9.1/SHA256SUMS"])
	f.publish("v0.9.2", map[string]string{"fox-linux-amd64": "unsigned"})
	f.releases[0].Assets = f.releases[0].Assets[:len(f.releases[0].Assets)-1] // no .sig asset
	off, err := f.client(t.TempDir()).Resolve(context.Background(), mustVersion(t, "0.8.0"), linux, "")
	if err != nil || off == nil || off.Release.Tag != "v0.9.0" {
		t.Fatalf("resolve = %+v, %v; want v0.9.0, the newest signed with the release key", off, err)
	}
	if _, err := f.client(t.TempDir()).Resolve(context.Background(), mustVersion(t, "0.8.0"), linux, "v0.9.1"); err == nil ||
		!strings.Contains(err.Error(), "not signed with the FoxByte release key") {
		t.Errorf("pinning the wrongly signed release: %v", err)
	}
}

func TestNoReleaseKeyNoUpdate(t *testing.T) {
	old := releasePublicKey
	releasePublicKey = ""
	defer func() { releasePublicKey = old }()
	if err := VerifySums([]byte("x"), make([]byte, 64)); err != ErrNoReleaseKey {
		t.Errorf("VerifySums with no key = %v", err)
	}
}
