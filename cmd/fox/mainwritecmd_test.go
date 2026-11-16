// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/auth"
)

// `fox check` warns, in plain words and with the command, while every
// account can change main, and is quiet once main is read-only for them.
func TestCheckMainWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.db")
	t.Setenv("FOX_DB", path)
	s, err := auth.Open(auth.Config{DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if l := checkMainWrite(); l.state != stateOK {
		t.Errorf("a new install (granted): %+v", l)
	}
	_ = s.SetMainWriteMode(auth.MainWriteAll)
	l := checkMainWrite()
	if l.state != stateWarn || !strings.Contains(l.detail, "every account can change data on main") ||
		!strings.Contains(l.fix, "access main-write granted") {
		t.Errorf("mode all: %+v", l)
	}
}

func TestLoseWriteWarningAndList(t *testing.T) {
	w := loseWriteWarning([]string{"alice@x.com", "bob@x.com"})
	if !strings.Contains(w, "2 account(s) will lose write on main") || !strings.Contains(w, "  bob@x.com\n") ||
		!strings.Contains(w, "access write grant <email>") {
		t.Errorf("warning: %q", w)
	}
	if !strings.Contains(loseWriteWarning(nil), "nobody loses write") {
		t.Error("an empty list still warns")
	}
	var b bytes.Buffer
	printMainWrite(&b, access.MainWriteView{Mode: auth.MainWriteGranted, Accounts: []access.MainWriteAccount{
		{Email: "admin@x.com", Admin: true, Writes: true},
		{Email: "bob@x.com", Granted: true, Writes: true},
		{Email: "carl@x.com"},
	}})
	out := b.String()
	for _, want := range []string{"granted: only admins", "admin@x.com  yes", "bob@x.com    yes", "carl@x.com   no (reads)"} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
}
