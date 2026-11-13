//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// The protocol between the engine and the vault service (design, section 5):
// JSON over HTTP on a Unix socket only the engine can open, with a
// per-install secret. The caller names the actor; the service trusts it
// because only the engine holds the secret.

// Request is every call's body.
type Request struct {
	Kind    string   `json:"kind"`
	Values  []string `json:"values,omitempty"`
	Refs    []string `json:"refs,omitempty"`
	Format  string   `json:"format,omitempty"`
	Purpose string   `json:"purpose,omitempty"`
}

// Response is every call's answer. Refs, Values and Results are in the order
// of the request's Values or Refs.
type Response struct {
	Refs    []string `json:"refs,omitempty"`
	New     []bool   `json:"new,omitempty"`
	Values  []string `json:"values,omitempty"`
	Results []string `json:"results,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// Results, per value or reference key.
const (
	ResultDone        = "done"
	ResultNotFound    = "not found"
	ResultRefused     = "refused"
	ResultNotVerified = "did not verify"
)

// Status is GET /v1/status.
type Status struct {
	Token struct {
		Label    string `json:"label"`
		Maker    string `json:"maker"`
		Model    string `json:"model"`
		Serial   string `json:"serial"`
		Software bool   `json:"software"`
	} `json:"token"`
	Kinds []KindStatus `json:"kinds"`
	Log   struct {
		Entries int64 `json:"entries"`
		// BrokenAt is the first entry that does not chain; 0 when all do.
		BrokenAt int64 `json:"broken_at"`
	} `json:"log"`
}

// KindStatus is one kind in the status: its keys and records.
type KindStatus struct {
	Name        string      `json:"name"`
	Prefix      string      `json:"prefix"`
	Rules       string      `json:"rules"`
	HSMRequired bool        `json:"hsm_required"`
	Compliant   string      `json:"compliant"`
	Records     int64       `json:"records"`
	Keys        []KeyStatus `json:"keys"`
}

// KeyStatus is a key as the HSM reports it back.
type KeyStatus struct {
	Label            string `json:"label"`
	Role             string `json:"role"`
	Current          bool   `json:"current"`
	Destroyed        bool   `json:"destroyed"`
	Uses             int64  `json:"uses"`
	Records          int64  `json:"records"`
	Sensitive        bool   `json:"sensitive"`
	Extractable      bool   `json:"extractable"`
	AlwaysSensitive  bool   `json:"always_sensitive"`
	NeverExtractable bool   `json:"never_extractable"`
	Local            bool   `json:"local"`
}

// Client calls the vault service.
type Client struct {
	hc     *http.Client
	secret string
	actor  string
}

// NewClient talks to the service on socket, as actor.
func NewClient(socket, secret, actor string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		MaxIdleConnsPerHost: 64,
	}
	return &Client{hc: &http.Client{Transport: tr, Timeout: 10 * time.Minute}, secret: strings.TrimSpace(secret), actor: actor}
}

// Call posts req to path (tokenise, find, detokenise, delete, rotate).
func (c *Client) Call(path string, req Request) (*Response, int, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, 0, err
	}
	r, err := http.NewRequest(http.MethodPost, "http://vault/v1/"+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	return c.do(r)
}

// Status reads the service's status.
func (c *Client) Status() (*Status, error) {
	r, err := http.NewRequest(http.MethodGet, "http://vault/v1/status", nil)
	if err != nil {
		return nil, err
	}
	c.sign(r)
	resp, err := c.hc.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status: %d %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var s Status
	return &s, json.Unmarshal(b, &s)
}

func (c *Client) sign(r *http.Request) {
	if c.secret != "" {
		r.Header.Set("Authorization", "Bearer "+c.secret)
	}
	r.Header.Set("X-Fox-Actor", c.actor)
	r.Header.Set("Content-Type", "application/json")
}

func (c *Client) do(r *http.Request) (*Response, int, error) {
	c.sign(r)
	resp, err := c.hc.Do(r)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	var out Response
	b, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("%d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if resp.StatusCode != http.StatusOK {
		return &out, resp.StatusCode, fmt.Errorf("%d: %s", resp.StatusCode, out.Error)
	}
	return &out, resp.StatusCode, nil
}
