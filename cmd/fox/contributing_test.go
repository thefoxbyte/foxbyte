// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

// CONTRIBUTING.md names the Go and Node a contributor needs. A version written
// in prose drifts: go.mod moves, the runners move, and the guide keeps naming
// what was true a year ago — which is worse than naming nothing, because
// someone follows it and loses an afternoon to a toolchain they were told to
// install.
//
// Node matters more than Go here. web/.npmrc sets engine-strict, so npm
// refuses outright on an older one; and the first time that floor existed, it
// was discovered by a CI failure reading
// "webidl.util.markAsUncloneable is not a function", which names neither Node
// nor the package that wanted it.
func TestContributorGuideNamesTheToolchainInUse(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return string(b)
	}
	guide := flatten(read("../../CONTRIBUTING.md"))

	// go.mod is the authority for Go. "go 1.26.0" is named as "Go 1.26": the
	// patch is the toolchain's business, not a contributor's.
	m := regexp.MustCompile(`(?m)^go (\d+)\.(\d+)`).FindStringSubmatch(read("../../go.mod"))
	if m == nil {
		t.Fatal("go.mod has no `go` directive to check the guide against")
	}
	wantGo := "Go " + m[1] + "." + m[2]
	if !strings.Contains(guide, wantGo) {
		t.Errorf("CONTRIBUTING.md does not name %q, which is what go.mod requires", wantGo)
	}

	// web/package.json is the authority for Node, and it is enforced rather
	// than suggested (web/.npmrc, engine-strict).
	var pkg struct {
		Engines struct {
			Node string `json:"node"`
		} `json:"engines"`
	}
	if err := json.Unmarshal([]byte(read("../../web/package.json")), &pkg); err != nil {
		t.Fatalf("web/package.json: %v", err)
	}
	node := strings.TrimLeft(pkg.Engines.Node, "><=^~ ")
	if node == "" {
		t.Fatal("web/package.json declares no Node engine, so the guide has nothing to be held to")
	}
	if !strings.Contains(guide, node) {
		t.Errorf("CONTRIBUTING.md does not name Node %s, which web/package.json requires and web/.npmrc enforces", node)
	}
}
