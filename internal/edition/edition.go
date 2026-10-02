// SPDX-License-Identifier: AGPL-3.0-or-later

// Package edition answers two different questions about this build.
//
// Enterprise is a build-time constant: was this binary built with
// `-tags enterprise`, so that the code under enterprise/ is compiled in at all?
// A Standard binary contains none of it, which is what keeps the free build
// purely AGPL and freely redistributable.
//
// Has is a run-time question: is this feature available *right now*? An
// Enterprise binary with no licence must behave exactly like a Standard one, so
// Has stays false until the licence layer supplies an entitlement function. The
// two are deliberately separate — conflating them would make "enterprise build"
// mean "licensed", and nothing would stop a build from unlocking itself.
package edition

import "sort"

// Feature names one thing the Enterprise edition unlocks. The string values are
// what a licence file lists, what /api/status reports and what the console
// matches on, so they are part of the interface and do not change.
type Feature string

const (
	Realtime  Feature = "realtime"  // row-level change feed
	Anchors   Feature = "anchors"   // signed Blackbox anchors + independent verification
	Policy    Feature = "policy"    // the Blackbox policy rule engine (the default guardrails are free)
	Impact    Feature = "impact"    // impact analysis
	Promotion Feature = "promotion" // change requests: propose, review, apply
	Export    Feature = "export"    // ledger export and compliance bundles
	Pipelines Feature = "pipelines" // ETL pipelines (fox import stays free)
)

// descriptions are used in refusals, so each one says what the user is missing
// rather than repeating the feature's identifier back at them.
var descriptions = map[Feature]string{
	Realtime:  "the realtime change feed",
	Anchors:   "signed Blackbox anchors and independent verification",
	Policy:    "the Blackbox policy rule engine",
	Impact:    "impact analysis",
	Promotion: "change requests",
	Export:    "Blackbox export and compliance bundles",
	Pipelines: "ETL pipelines",
}

// Describe names a feature in a sentence. An unknown feature describes itself,
// so a licence naming something this build has never heard of still reads.
func Describe(f Feature) string {
	if d := descriptions[f]; d != "" {
		return d
	}
	return string(f)
}

// Features is every feature this edition knows about, sorted, whether or not
// they are currently available.
func Features() []Feature {
	out := make([]Feature, 0, len(descriptions))
	for f := range descriptions {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// entitled is supplied by the licence layer at start-up. Nil means no licence
// has been presented, and an Enterprise build with no licence is a Standard
// build in every observable way.
var entitled func(Feature) bool

// SetEntitlement installs the licence layer's answer. Passing nil clears it,
// which is how `fox license remove` takes the features away without a restart.
func SetEntitlement(fn func(Feature) bool) { entitled = fn }

// Has reports whether a feature may be used. It is false in a Standard build no
// matter what a licence says, and false in an Enterprise build until a licence
// says otherwise.
func Has(f Feature) bool {
	if !Enterprise || entitled == nil {
		return false
	}
	return entitled(f)
}

// Available is the features Has currently allows — what /api/status reports and
// what the console uses to decide which pages are live.
func Available() []Feature {
	var out []Feature
	for _, f := range Features() {
		if Has(f) {
			out = append(out, f)
		}
	}
	return out
}

// Name is this build's edition, for `fox check`, `fox version` and /api/status.
func Name() string {
	if Enterprise {
		return "enterprise"
	}
	return "standard"
}
