// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	// DefaultBaseURL is the GitHub API. FOX_UPDATE_BASE_URL points elsewhere (tests).
	DefaultBaseURL = "https://api.github.com"
	// DefaultRepo matches the installers; FOX_REPO overrides it.
	DefaultRepo = "foxbyte/foxbyte"
)

// Asset is one file attached to a release.
type Asset struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	URL  string `json:"browser_download_url"`
}

// Release is a GitHub release as the API lists it.
type Release struct {
	Tag        string  `json:"tag_name"`
	Draft      bool    `json:"draft"`
	Prerelease bool    `json:"prerelease"`
	HTMLURL    string  `json:"html_url"`
	Assets     []Asset `json:"assets"`
}

// Asset finds an attached file by name.
func (r Release) Asset(name string) (Asset, bool) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a, true
		}
	}
	return Asset{}, false
}

// Client talks to GitHub releases.
type Client struct {
	BaseURL    string
	Repo       string
	HTTP       *http.Client
	CachePath  string // optional: remembers the last releases list (with its ETag)
	NoticePath string // optional: remembers the last start-time check (see BackgroundCheck)
}

// NewClient builds a client from the environment (FOX_UPDATE_BASE_URL, FOX_REPO).
func NewClient(getenv func(string) string, cachePath string) *Client {
	base := strings.TrimRight(strings.TrimSpace(getenv("FOX_UPDATE_BASE_URL")), "/")
	if base == "" {
		base = DefaultBaseURL
	}
	repo := strings.TrimSpace(getenv("FOX_REPO"))
	if repo == "" {
		repo = DefaultRepo
	}
	c := &Client{BaseURL: base, Repo: repo, HTTP: &http.Client{}, CachePath: cachePath}
	if cachePath != "" {
		c.NoticePath = filepath.Join(filepath.Dir(cachePath), "update-notice.json")
	}
	return c
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) request(ctx context.Context, url string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "fox-updater")
	return req, nil
}

type releaseCache struct {
	URL  string          `json:"url"`
	ETag string          `json:"etag"`
	Body json.RawMessage `json:"body"`
}

func (c *Client) readCache(url string) *releaseCache {
	if c.CachePath == "" {
		return nil
	}
	b, err := os.ReadFile(c.CachePath)
	if err != nil {
		return nil
	}
	var rc releaseCache
	if json.Unmarshal(b, &rc) != nil || rc.URL != url || len(rc.Body) == 0 {
		return nil
	}
	return &rc
}

func (c *Client) writeCache(rc releaseCache) {
	if c.CachePath == "" {
		return
	}
	b, err := json.Marshal(rc)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(c.CachePath), 0o755)
	tmp := c.CachePath + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		_ = os.Rename(tmp, c.CachePath)
	}
}

// ListReleases lists the repository's releases, newest first as GitHub orders
// them. An unchanged list is answered from the cache (HTTP 304), which doesn't
// count against GitHub's rate limit.
func (c *Client) ListReleases(ctx context.Context) ([]Release, error) {
	url := fmt.Sprintf("%s/repos/%s/releases?per_page=50", c.BaseURL, c.Repo)
	req, err := c.request(ctx, url)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	cached := c.readCache(url)
	if cached != nil && cached.ETag != "" {
		req.Header.Set("If-None-Match", cached.ETag)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		if cached == nil {
			return nil, fmt.Errorf("github: unexpected 304 without a cached list")
		}
		return ParseReleases(bytes.NewReader(cached.Body))
	case http.StatusOK:
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		if err != nil {
			return nil, err
		}
		rels, err := ParseReleases(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		if etag := resp.Header.Get("ETag"); etag != "" {
			c.writeCache(releaseCache{URL: url, ETag: etag, Body: body})
		}
		return rels, nil
	}
	return nil, fmt.Errorf("github: listing releases: HTTP %d", resp.StatusCode)
}

// ParseReleases decodes the GitHub API's releases list.
func ParseReleases(r io.Reader) ([]Release, error) {
	var rels []Release
	if err := json.NewDecoder(r).Decode(&rels); err != nil {
		return nil, fmt.Errorf("github: reading releases: %w", err)
	}
	return rels, nil
}

// fetchSmall downloads a small file (such as SHA256SUMS) into memory.
func (c *Client) fetchSmall(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := c.request(ctx, url)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("downloading %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// Download fetches an asset into dir, checking its size and SHA-256 as it
// streams. On any mismatch or error nothing is left behind.
func (c *Client) Download(ctx context.Context, a Asset, wantSHA, dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	dest := filepath.Join(dir, a.Name)
	part := dest + ".part"
	req, err := c.request(ctx, a.URL)
	if err != nil {
		return "", err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("downloading %s: %w", a.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("downloading %s: HTTP %d", a.Name, resp.StatusCode)
	}
	mode := os.FileMode(0o755)
	if strings.HasSuffix(a.Name, ".tar.gz") {
		mode = 0o644
	}
	f, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), resp.Body)
	closeErr := f.Close()
	fail := func(err error) (string, error) {
		_ = os.Remove(part)
		return "", err
	}
	if copyErr != nil {
		return fail(fmt.Errorf("downloading %s: %w", a.Name, copyErr))
	}
	if closeErr != nil {
		return fail(closeErr)
	}
	if a.Size > 0 && n != a.Size {
		return fail(fmt.Errorf("%s: downloaded %d bytes, expected %d", a.Name, n, a.Size))
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, wantSHA) {
		return fail(fmt.Errorf("%s: checksum mismatch — the download doesn't match SHA256SUMS; nothing was installed", a.Name))
	}
	_ = os.Chmod(part, mode)
	if err := os.Rename(part, dest); err != nil {
		return fail(err)
	}
	return dest, nil
}
