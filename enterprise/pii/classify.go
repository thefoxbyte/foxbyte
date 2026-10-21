//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package pii

import (
	"fmt"
	"strings"
)

// Confidence is how sure a finding is. A reviewer decides what it is (step 3 of
// the plan); this only orders the queue.
type Confidence string

const (
	High   Confidence = "high"
	Medium Confidence = "medium"
	Low    Confidence = "low"
)

// Signal is one category found in one column: what matched, and how much of
// the sample.
type Signal struct {
	Category   Category
	Rule       string // "name", "value" or "name+value"
	Confidence Confidence
	Matched    int
	Sampled    int
	Why        string
}

// longest is the longest value checked against the recognisers. Every
// identifier they know is far shorter; a longer value is free text, which is
// step 4.3 and not read as an identifier here.
const longest = 64

// Classify finds the categories a column holds, from its name, its type
// category (pg_type.typcategory) and a sample of its values (NULLs left out).
// The values are only read; nothing about them is kept but the counts.
func Classify(column, typcat string, sample []string) []Signal {
	ws := words(column)
	var out []Signal
	for _, r := range recognisers {
		named := r.name(ws)
		checkable := strings.Contains(r.types, typcat)
		matched := 0
		if checkable {
			for _, v := range sample {
				if len(v) <= longest && r.value(v) {
					matched++
				}
			}
		}
		n := len(sample)
		if !checkable {
			n = 0 // a value of a type this category cannot take was not checked
		}
		s, ok := judge(r, named, matched, n)
		if !ok {
			continue
		}
		out = append(out, s)
		if r.cat == Birth {
			if c, ok := children(s, sample); ok {
				out = append(out, c)
			}
		}
	}
	return out
}

// judge turns a recogniser's counts into a finding, or none.
//
// The rule, by strength:
//   - a checked value (a check digit passes) is trusted alone: most of the
//     sample passing is high, half is medium, a few is low;
//   - a format with no check digit (an email) needs most of the sample, or the
//     name as well, to be more than medium;
//   - a weak shape (a date) never counts alone, only with the name;
//   - the name alone is medium with nothing to check, and low when the values
//     say otherwise (they may be tokens from a vault, or masked already).
func judge(r recogniser, named bool, matched, n int) (Signal, bool) {
	s := Signal{Category: r.cat, Matched: matched, Sampled: n}
	ratio := 0.0
	if n > 0 {
		ratio = float64(matched) / float64(n)
	}
	switch {
	case named && n == 0:
		s.Rule, s.Confidence = "name", Medium
		s.Why = "the column's name; no values to check"
	case named && ratio >= 0.5:
		s.Rule, s.Confidence = "name+value", High
		if ratio < 0.8 && r.str == weak {
			s.Confidence = Medium
		}
		s.Why = fmt.Sprintf("the column's name, and %d of %d sampled values are %s", matched, n, r.rule)
	case !named && r.str == checked && ratio >= 0.8:
		s.Rule, s.Confidence = "value", High
		s.Why = fmt.Sprintf("%d of %d sampled values are %s", matched, n, r.rule)
	case !named && r.str == checked && ratio >= 0.5,
		!named && r.str == format && ratio >= 0.8:
		s.Rule, s.Confidence = "value", Medium
		s.Why = fmt.Sprintf("%d of %d sampled values are %s", matched, n, r.rule)
	// A quarter, not fewer: a random number passes Luhn or Verhoeff one time
	// in ten, so a column of long numeric IDs passes about that often.
	case !named && r.str == checked && matched >= 3 && ratio >= 0.25:
		s.Rule, s.Confidence = "value", Low
		s.Why = fmt.Sprintf("some values: %d of %d sampled are %s", matched, n, r.rule)
	case named:
		s.Rule, s.Confidence = "name", Low
		s.Why = fmt.Sprintf("the column's name, but only %d of %d sampled values are %s", matched, n, r.rule)
	default:
		return Signal{}, false
	}
	return s, true
}

// children is the dates of birth that make someone under 18: a category of its
// own, because DPDP asks for verifiable parental consent for a child's data. A
// column of dates of birth with none in the sample says nothing about the rows
// not sampled, so it is only a finding when a minor was seen.
func children(birth Signal, sample []string) (Signal, bool) {
	n := 0
	for _, v := range sample {
		if minor(v) {
			n++
		}
	}
	if n == 0 {
		return Signal{}, false
	}
	return Signal{
		Category: Child, Rule: birth.Rule, Confidence: birth.Confidence,
		Matched: n, Sampled: birth.Sampled,
		Why: fmt.Sprintf("%d of %d sampled dates of birth are less than 18 years ago", n, birth.Sampled),
	}, true
}
