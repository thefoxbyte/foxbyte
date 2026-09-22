// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"os"
	"testing"
)

// TestMain gives the package's tests a home of their own. The engine keeps its
// secrets and env files in the state directory under $HOME, and a test that
// builds a docker command writes them — into the real ~/.fox of whoever ran
// `go test`, which is how a developer's machine gained a secrets.json and env
// files no install of theirs had made.
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "fox-branch-test-")
	if err != nil {
		panic(err)
	}
	os.Setenv("HOME", home)
	os.Setenv("USERPROFILE", home) // os.UserHomeDir on Windows
	code := m.Run()
	os.RemoveAll(home)
	os.Exit(code)
}
