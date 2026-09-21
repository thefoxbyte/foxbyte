// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// recorder stands in for the three steps and remembers what ran, in order.
type recorder struct {
	calls      []string
	planErr    error
	exportErr  error
	exportedTo string
}

func (r *recorder) steps() UpgradeSteps {
	return UpgradeSteps{
		Plan: func() error { r.calls = append(r.calls, "plan"); return r.planErr },
		Export: func(out string) error {
			r.calls = append(r.calls, "export")
			r.exportedTo = out
			return r.exportErr
		},
		Apply: func() error { r.calls = append(r.calls, "apply"); return nil },
	}
}

func run(r *recorder, o UpgradeOptions, typed string) (error, string) {
	var out bytes.Buffer
	err := RunUpgrade(r.steps(), o, strings.NewReader(typed), &out)
	return err, out.String()
}

func TestRunUpgradeOrder(t *testing.T) {
	cases := []struct {
		name  string
		r     recorder
		o     UpgradeOptions
		typed string
		want  string // calls, comma-separated
		fails bool
	}{
		{"confirmed: plan, export, then apply", recorder{}, UpgradeOptions{}, "fox\n", "plan,export,apply", false},
		{"not confirmed: nothing after the plan", recorder{}, UpgradeOptions{}, "yes\n", "plan", true},
		{"no answer at all is a no", recorder{}, UpgradeOptions{}, "", "plan", true},
		{"dry run stops after the plan", recorder{}, UpgradeOptions{DryRun: true}, "fox\n", "plan", false},
		{"refused plan stops everything", recorder{planErr: errors.New("HA is on")}, UpgradeOptions{Yes: true}, "", "plan", true},
		{"up to date is not a failure", recorder{planErr: ErrUpToDate}, UpgradeOptions{Yes: true}, "", "plan", false},
		{"--yes still exports", recorder{}, UpgradeOptions{Yes: true}, "", "plan,export,apply", false},
		{"--i-have-a-backup skips only the export", recorder{}, UpgradeOptions{Yes: true, HaveBackup: true}, "", "plan,apply", false},
		{"a failed export stops the upgrade", recorder{exportErr: errors.New("disk full")}, UpgradeOptions{Yes: true}, "", "plan,export", true},
	}
	for _, c := range cases {
		r := c.r
		err, out := run(&r, c.o, c.typed)
		if got := strings.Join(r.calls, ","); got != c.want {
			t.Errorf("%s: ran %q, want %q", c.name, got, c.want)
		}
		if (err != nil) != c.fails {
			t.Errorf("%s: err = %v, want failure %v", c.name, err, c.fails)
		}
		if c.name == "a failed export stops the upgrade" && !strings.Contains(err.Error(), "nothing was upgraded") {
			t.Errorf("a failed export should say nothing was upgraded: %v", err)
		}
		if c.o.DryRun && !strings.Contains(out, "nothing was changed") {
			t.Errorf("%s: a dry run should say nothing was changed", c.name)
		}
	}
}

func TestRunUpgradeExportsWhereAsked(t *testing.T) {
	r := recorder{}
	if err, _ := run(&r, UpgradeOptions{Yes: true, ExportTo: "/tmp/before.tar"}, ""); err != nil {
		t.Fatal(err)
	}
	if r.exportedTo != "/tmp/before.tar" {
		t.Errorf("exported to %q", r.exportedTo)
	}
	r = recorder{}
	if err, _ := run(&r, UpgradeOptions{Yes: true}, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(r.exportedTo, ".tar") || !strings.Contains(r.exportedTo, "exports") {
		t.Errorf("the default export should go to the exports directory: %q", r.exportedTo)
	}
}

func TestParsePgUpgradeArgs(t *testing.T) {
	a, err := ParsePgUpgradeArgs([]string{"--dry-run", "--yes", "--export", "x.tar"})
	if err != nil || !a.DryRun || !a.Yes || a.ExportTo != "x.tar" {
		t.Errorf("got %+v, %v", a, err)
	}
	for _, bad := range [][]string{
		{"--rollback", "--finalize"},
		{"--export", "x.tar", "--i-have-a-backup"},
		{"--export"},
		{"--force"},
	} {
		if _, err := ParsePgUpgradeArgs(bad); err == nil {
			t.Errorf("%v should be refused", bad)
		}
	}
}

func TestParseExportAndRestoreArgs(t *testing.T) {
	e, err := ParseExportArgs([]string{"--out", "a.tar", "--branch", "qa", "--branch", "main"})
	if err != nil || e.Out != "a.tar" || strings.Join(e.Branches, ",") != "qa,main" {
		t.Errorf("got %+v, %v", e, err)
	}
	if _, err := ParseExportArgs([]string{"--branch", "--out"}); err == nil {
		t.Error("a flag where a value belongs should be refused")
	}
	r, err := ParseRestoreArgs([]string{"e.tar", "--as", "copy"})
	if err != nil || r.File != "e.tar" || r.Branch != "main" || r.As != "copy" {
		t.Errorf("got %+v, %v", r, err)
	}
	for _, bad := range [][]string{{"e.tar"}, {"--as", "copy"}, {"a.tar", "b.tar", "--as", "c"}} {
		if _, err := ParseRestoreArgs(bad); err == nil {
			t.Errorf("%v should be refused: a restore needs one file and a new name", bad)
		}
	}
}
