// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/foxbyte/foxbyte/internal/update"
)

// fakeEngine stands in for the VM: it records what the updater runs there.
type fakeEngine struct {
	calls         []string
	oldV, newV    string
	engineSwapped bool
	failInstall   bool
}

func (f *fakeEngine) where() string  { return "the fake VM" }
func (f *fakeEngine) prepare() error { f.calls = append(f.calls, "prepare"); return nil }
func (f *fakeEngine) stage(local string) (string, error) {
	f.calls = append(f.calls, "stage "+filepath.Base(local))
	return "/staged", nil
}
func (f *fakeEngine) installed() (string, error) { return "/usr/local/bin/fox", nil }
func (f *fakeEngine) run(bin string, args ...string) error {
	f.calls = append(f.calls, bin+" "+strings.Join(args, " "))
	if len(args) > 1 && args[1] == "install-engine" {
		if f.failInstall {
			return errors.New("disk full")
		}
		f.engineSwapped = true
	}
	return nil
}
func (f *fakeEngine) output(bin string, args ...string) (string, error) {
	if bin == "/staged" || f.engineSwapped {
		return "fox " + f.newV + "\n", nil
	}
	return "fox " + f.oldV + "\n", nil
}

// fakeReleases serves a GitHub releases list with one release, v0.99.0.
func fakeReleases(t *testing.T, tamper bool) *httptest.Server {
	files := map[string]string{"fox-linux-amd64": "engine 0.99.0"}
	var mux http.ServeMux
	srv := httptest.NewServer(&mux)
	t.Cleanup(srv.Close)
	rel := update.Release{Tag: "v0.99.0", HTMLURL: srv.URL + "/releases/tag/v0.99.0"}
	var sums bytes.Buffer
	for name, content := range files {
		s := sha256.Sum256([]byte(content))
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(s[:]), name)
		body := content
		if tamper {
			body = "evil 0.99.0!!"
		}
		mux.HandleFunc("/dl/"+name, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) })
		rel.Assets = append(rel.Assets, update.Asset{Name: name, URL: srv.URL + "/dl/" + name})
	}
	mux.HandleFunc("/dl/SHA256SUMS", func(w http.ResponseWriter, r *http.Request) { w.Write(sums.Bytes()) })
	rel.Assets = append(rel.Assets, update.Asset{Name: "SHA256SUMS", URL: srv.URL + "/dl/SHA256SUMS"})
	mux.HandleFunc("/repos/foxbyte/foxbyte/releases", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]update.Release{rel})
	})
	return srv
}

type updateRun struct {
	eng          *fakeEngine
	out          bytes.Buffer
	hostReplaced bool
	err          error
}

func runFakeUpdate(t *testing.T, current string, opts UpdateOptions, tamper bool, mutate func(*updater, *fakeEngine)) *updateRun {
	t.Helper()
	srv := fakeReleases(t, tamper)
	r := &updateRun{eng: &fakeEngine{oldV: current, newV: "0.99.0"}}
	u := &updater{
		opts:    opts,
		current: current,
		client: update.NewClient(func(k string) string {
			if k == "FOX_UPDATE_BASE_URL" {
				return srv.URL
			}
			return ""
		}, ""),
		eh: r.eng,
		hooks: updateHooks{
			target: func() update.Target { return update.Target{GOOS: "linux", HostArch: "amd64"} },
			replaceHost: func(files map[string]string, _ update.Target) error {
				r.hostReplaced = true
				return nil
			},
		},
		in:   strings.NewReader(""),
		out:  &r.out,
		home: t.TempDir(),
	}
	if mutate != nil {
		mutate(u, r.eng)
	}
	r.err = u.run(context.Background())
	return r
}

func TestUpdateFlow(t *testing.T) {
	r := runFakeUpdate(t, "0.98.0", UpdateOptions{Yes: true}, false, nil)
	if r.err != nil {
		t.Fatalf("update: %v\n%s", r.err, r.out.String())
	}
	want := []string{
		"prepare",
		"stage fox-linux-amd64",
		"/staged _update-guest stop-services",
		"/staged _update-guest install-engine --src /staged --dest /usr/local/bin/fox",
		"/usr/local/bin/fox up",
		"/usr/local/bin/fox ledger upgrade --all",
		"/usr/local/bin/fox start",
	}
	if got := strings.Join(r.eng.calls, "\n"); got != strings.Join(want, "\n") {
		t.Fatalf("steps:\n%s\nwant:\n%s", got, strings.Join(want, "\n"))
	}
	if !r.hostReplaced {
		t.Fatal("fox on the host wasn't replaced")
	}
	for _, s := range []string{"[6/6] Updating fox on this computer", "Done — FoxByte is now v0.99.0. Your data was not touched.", "What's new: "} {
		if !strings.Contains(r.out.String(), s) {
			t.Errorf("output lacks %q:\n%s", s, r.out.String())
		}
	}
}

func TestUpdateChangesNothingUnlessReady(t *testing.T) {
	cases := []struct {
		name    string
		current string
		opts    UpdateOptions
		tamper  bool
		mutate  func(*updater, *fakeEngine)
		wantErr string
		wantOut string
	}{
		{name: "check only", current: "0.98.0", opts: UpdateOptions{Check: true}, wantOut: "v0.99.0 is available"},
		{name: "up to date", current: "0.99.0", opts: UpdateOptions{Yes: true}, wantOut: "0.99.0 is up to date"},
		{name: "dev build", current: "0.1.0-dev", opts: UpdateOptions{Yes: true}, wantErr: "development build"},
		{name: "tampered download", current: "0.98.0", opts: UpdateOptions{Yes: true}, tamper: true, wantErr: "checksum mismatch"},
		{name: "no terminal, no --yes", current: "0.98.0", wantErr: "--yes"},
		{name: "stdin closed", current: "0.98.0", wantErr: "--yes", mutate: func(u *updater, _ *fakeEngine) {
			u.interactive, u.in = true, strings.NewReader("")
		}},
		{name: "answered no", current: "0.98.0", wantOut: "Not updated.", mutate: func(u *updater, _ *fakeEngine) {
			u.interactive, u.in = true, strings.NewReader("n\n")
		}},
		{name: "engine doesn't run there", current: "0.98.0", opts: UpdateOptions{Yes: true}, wantErr: "doesn't run in the fake VM", mutate: func(_ *updater, e *fakeEngine) {
			e.newV = "garbage"
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := runFakeUpdate(t, c.current, c.opts, c.tamper, c.mutate)
			if c.wantErr == "" && r.err != nil {
				t.Fatalf("error: %v", r.err)
			}
			if c.wantErr != "" && (r.err == nil || !strings.Contains(r.err.Error(), c.wantErr)) {
				t.Fatalf("error = %v, want %q", r.err, c.wantErr)
			}
			if !strings.Contains(r.out.String(), c.wantOut) {
				t.Fatalf("output lacks %q:\n%s", c.wantOut, r.out.String())
			}
			for _, call := range r.eng.calls {
				if call != "prepare" && !strings.HasPrefix(call, "stage ") {
					t.Fatalf("ran %q in the VM", call)
				}
			}
			if r.hostReplaced {
				t.Fatal("host binary replaced")
			}
		})
	}
}

func TestUpdateInstallFailureRestartsOldEngine(t *testing.T) {
	r := runFakeUpdate(t, "0.98.0", UpdateOptions{Yes: true}, false, func(_ *updater, e *fakeEngine) { e.failInstall = true })
	if r.err == nil || !strings.Contains(r.err.Error(), "still on 0.98.0") {
		t.Fatalf("error = %v", r.err)
	}
	last := r.eng.calls[len(r.eng.calls)-1]
	if last != "/usr/local/bin/fox start" {
		t.Fatalf("servers weren't restarted on the old engine; last step %q", last)
	}
	if r.hostReplaced {
		t.Fatal("host binary replaced after a failed engine install")
	}
}
