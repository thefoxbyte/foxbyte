//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package pii

import (
	"fmt"
	"testing"
	"time"
)

func cats(ss []Signal) map[Category]Signal {
	m := map[Category]Signal{}
	for _, s := range ss {
		m[s.Category] = s
	}
	return m
}

func aadhaars(n int) []string {
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, verhoeffDigit(fmt.Sprintf("2%010d", 1234567+i*7919)))
	}
	return out
}

func TestClassify(t *testing.T) {
	today = func() time.Time { return time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC) }
	defer func() { today = func() time.Time { return time.Now().UTC() } }()

	t.Run("checked values are trusted alone", func(t *testing.T) {
		s := cats(Classify("ref", "S", aadhaars(10)))[Aadhaar]
		if s.Confidence != High || s.Rule != "value" || s.Matched != 10 || s.Sampled != 10 {
			t.Fatalf("got %+v", s)
		}
	})
	t.Run("numbers are checked too", func(t *testing.T) {
		if s, ok := cats(Classify("ref", "N", aadhaars(10)))[Aadhaar]; !ok || s.Confidence != High {
			t.Fatalf("an Aadhaar kept as a bigint should be found: %+v", s)
		}
	})
	t.Run("the name and the values agree", func(t *testing.T) {
		s := cats(Classify("aadhaar_no", "S", aadhaars(4)))[Aadhaar]
		if s.Rule != "name+value" || s.Confidence != High {
			t.Fatalf("got %+v", s)
		}
	})
	t.Run("a name whose values do not match is low: they may be vault tokens", func(t *testing.T) {
		s := cats(Classify("aadhaar_no", "S", []string{"tok_1", "tok_2", "tok_3"}))[Aadhaar]
		if s.Rule != "name" || s.Confidence != Low {
			t.Fatalf("got %+v", s)
		}
	})
	t.Run("a name with nothing to check is medium", func(t *testing.T) {
		s := cats(Classify("pan", "S", nil))[PAN]
		if s.Rule != "name" || s.Confidence != Medium || s.Sampled != 0 {
			t.Fatalf("got %+v", s)
		}
	})
	t.Run("a weak shape never counts without the name", func(t *testing.T) {
		if _, ok := cats(Classify("created_on", "D", []string{"1990-05-17", "1985-01-02"}))[Birth]; ok {
			t.Fatal("a column of dates is not a column of dates of birth")
		}
		if _, ok := cats(Classify("code", "S", []string{"ABC1234567", "XYZ7654321"}))[VoterID]; ok {
			t.Fatal("3 letters and 7 digits alone is not a voter ID")
		}
	})
	t.Run("an unchecked format needs most of the sample", func(t *testing.T) {
		mixed := []string{"a@example.com", "b@example.com", "x", "y", "z"}
		if _, ok := cats(Classify("contact", "S", mixed))[Email]; ok {
			t.Fatal("two emails in five is not a column of emails")
		}
		all := []string{"a@example.com", "b@example.com", "c@example.org", "d@example.net", "e@example.in"}
		if s := cats(Classify("contact", "S", all))[Email]; s.Confidence != Medium || s.Rule != "value" {
			t.Fatalf("got %+v", s)
		}
	})
	t.Run("chance passes of a checksum are not a finding", func(t *testing.T) {
		// Long numeric IDs: about one in ten passes Luhn by chance.
		var ids []string
		for i := 0; i < 100; i++ {
			ids = append(ids, fmt.Sprintf("3%015d", 104729*i+7))
		}
		if s, ok := cats(Classify("order_id", "N", ids))[Card]; ok {
			t.Fatalf("IDs passing Luhn by chance should not be cards: %+v", s)
		}
	})
	t.Run("a few checked values in a mostly other column is low", func(t *testing.T) {
		sample := append(aadhaars(3), "n/a", "n/a", "n/a", "n/a", "n/a", "n/a")
		if s := cats(Classify("ref", "S", sample))[Aadhaar]; s.Confidence != Low {
			t.Fatalf("got %+v", s)
		}
	})
	t.Run("a type a category cannot take is not checked", func(t *testing.T) {
		if _, ok := cats(Classify("ref", "D", aadhaars(5)))[Aadhaar]; ok {
			t.Fatal("a date column cannot hold an Aadhaar")
		}
	})
	t.Run("a date of birth of someone under 18 is a child's data", func(t *testing.T) {
		got := cats(Classify("dob", "D", []string{"1990-05-17", "2015-01-01", "2012-03-04"}))
		if got[Birth].Confidence != High {
			t.Fatalf("dates of birth: %+v", got[Birth])
		}
		if c := got[Child]; c.Matched != 2 || c.Sampled != 3 {
			t.Fatalf("children: %+v", c)
		}
		if _, ok := cats(Classify("dob", "D", []string{"1990-05-17"}))[Child]; ok {
			t.Fatal("no minor in the sample is no finding about children")
		}
	})
	t.Run("long text is not read as an identifier", func(t *testing.T) {
		long := "Customer called about " + aadhaars(1)[0] + " and asked for a callback the next day please"
		if _, ok := cats(Classify("notes", "S", []string{long, long, long}))[Aadhaar]; ok {
			t.Fatal("free text is step 4.3")
		}
	})
	t.Run("a column with nothing personal gives nothing", func(t *testing.T) {
		if got := Classify("status", "S", []string{"open", "closed", "open"}); len(got) != 0 {
			t.Fatalf("got %+v", got)
		}
	})
}
