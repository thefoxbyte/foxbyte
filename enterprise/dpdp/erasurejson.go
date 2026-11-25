//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package dpdp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Clearing a JSON path in a document (F4, section 4): the scanner names a
// place inside a JSON column by a path of its own simple form, $.customer.phone,
// $.items[*].email, $."odd key" (enterprise/pii/jsonwalk.go), and an erasure
// sets every string or number found there to null, leaving the rest of the
// document as it was.

// pathSeg is one step of a path: a key, or every element of an array.
type pathSeg struct {
	key string
	all bool
}

func parsePath(p string) ([]pathSeg, error) {
	if !strings.HasPrefix(p, "$") {
		return nil, fmt.Errorf("the path %q does not start at $", p)
	}
	rest := p[1:]
	var segs []pathSeg
	for rest != "" {
		switch {
		case strings.HasPrefix(rest, "[*]"):
			segs = append(segs, pathSeg{all: true})
			rest = rest[3:]
		case strings.HasPrefix(rest, `."`):
			// A quoted key, as strconv.Quote wrote it: find its closing quote.
			end := -1
			for i := 2; i < len(rest); i++ {
				if rest[i] == '\\' {
					i++
					continue
				}
				if rest[i] == '"' {
					end = i
					break
				}
			}
			if end < 0 {
				return nil, fmt.Errorf("the path %q has an unclosed quote", p)
			}
			k, err := strconv.Unquote(rest[1 : end+1])
			if err != nil {
				return nil, fmt.Errorf("the path %q: %w", p, err)
			}
			segs = append(segs, pathSeg{key: k})
			rest = rest[end+1:]
		case strings.HasPrefix(rest, "."):
			i := 1
			for i < len(rest) && rest[i] != '.' && rest[i] != '[' {
				i++
			}
			if i == 1 {
				return nil, fmt.Errorf("the path %q has an empty key", p)
			}
			segs = append(segs, pathSeg{key: rest[1:i]})
			rest = rest[i:]
		default:
			return nil, fmt.Errorf("the path %q is not one the scanner writes", p)
		}
	}
	return segs, nil
}

// clearJSONPaths sets every string and number at each path to null.
func clearJSONPaths(doc string, paths []string) (string, error) {
	dec := json.NewDecoder(strings.NewReader(doc))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", fmt.Errorf("not a JSON document: %w", err)
	}
	for _, p := range paths {
		segs, err := parsePath(p)
		if err != nil {
			return "", err
		}
		v = clearAt(v, segs)
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(b.String(), "\n"), nil
}

func clearAt(v any, segs []pathSeg) any {
	if len(segs) == 0 {
		switch v.(type) {
		case string, json.Number:
			return nil
		}
		return v
	}
	s := segs[0]
	switch x := v.(type) {
	case map[string]any:
		if s.all {
			return v
		}
		if c, ok := x[s.key]; ok {
			x[s.key] = clearAt(c, segs[1:])
		}
	case []any:
		if !s.all {
			return v
		}
		for i := range x {
			x[i] = clearAt(x[i], segs[1:])
		}
	}
	return v
}
