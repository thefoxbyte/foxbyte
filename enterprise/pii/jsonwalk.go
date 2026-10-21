//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package pii

import (
	"bytes"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
)

// Walking JSON documents path by path (point 4.2): a JSONB column is not one
// thing but many, and $.customer.phone holds something $.status does not. Each
// path is classified like a column, by its last key's name and the values found
// there.

const (
	// maxPaths bounds the distinct paths kept for one column. A column of
	// documents keyed by IDs would otherwise make a path per row.
	maxPaths = 500
	// maxDepth bounds how far into a document the walk goes.
	maxDepth = 32
)

// jsonPath is one path through a column's documents, and the values found at
// it across the sample.
type jsonPath struct {
	path   string   // $.customer.phone, $.items[*].email
	name   string   // the last key: what a column name is to a column
	values []string // leaf values as text; null leaves left out
}

// plainKey is a key that needs no quoting in a path.
var plainKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func childPath(parent, key string) string {
	if plainKey.MatchString(key) {
		return parent + "." + key
	}
	return parent + "." + strconv.Quote(key)
}

// walkJSON reads documents (each a JSON text) and returns their paths in the
// order first seen. Array elements share one path ([*]), so a hundred line items
// are one path rather than a hundred. truncated says more than maxPaths were
// found and the rest were not kept; bad counts documents that were not JSON.
func walkJSON(docs []string, column string) (paths []jsonPath, truncated bool, bad int) {
	index := map[string]int{}
	add := func(path, name string, v *string) {
		i, ok := index[path]
		if !ok {
			if len(paths) >= maxPaths {
				truncated = true
				return
			}
			if name == "" {
				name = column // the document itself, or an array of scalars at its top
			}
			i = len(paths)
			index[path] = i
			paths = append(paths, jsonPath{path: path, name: name})
		}
		if v != nil {
			paths[i].values = append(paths[i].values, *v)
		}
	}

	var walk func(v any, path, name string, depth int)
	walk = func(v any, path, name string, depth int) {
		if depth > maxDepth {
			return
		}
		switch x := v.(type) {
		case map[string]any:
			// In key order, so which paths a column past maxPaths keeps is
			// the same on every scan.
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(x[k], childPath(path, k), k, depth+1)
			}
		case []any:
			for _, child := range x {
				walk(child, path+"[*]", name, depth+1)
			}
		case string:
			add(path, name, &x)
		case json.Number:
			s := x.String()
			add(path, name, &s)
		case nil:
			add(path, name, nil) // its name may still say what it would hold
		}
		// Booleans hold no identifier, and their path is not worth a row.
	}

	for _, d := range docs {
		dec := json.NewDecoder(bytes.NewReader([]byte(d)))
		dec.UseNumber() // 234567890124 stays digits, not 2.34567890124e+11
		var v any
		if err := dec.Decode(&v); err != nil {
			bad++
			continue
		}
		walk(v, "$", "", 0)
	}
	// Sorted, so a column's paths are listed the same way each time.
	sort.Slice(paths, func(i, j int) bool { return paths[i].path < paths[j].path })
	return paths, truncated, bad
}
