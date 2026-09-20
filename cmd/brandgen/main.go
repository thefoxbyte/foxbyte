// SPDX-License-Identifier: AGPL-3.0-or-later

// Command brandgen writes the files generated from brand.json. Run it with
// `make brand`; -check reports what is out of date without writing.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/foxbyte/foxbyte/internal/brand/gen"
)

func main() {

	root := flag.String("root", ".", "repository root (holds brand.json)")
	check := flag.Bool("check", false, "report what would change, write nothing")
	flag.Parse()

	b, err := gen.Load(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "brandgen:", err)
		os.Exit(1)
	}
	files, err := gen.Files(*root, b)
	if err != nil {
		fmt.Fprintln(os.Stderr, "brandgen:", err)
		os.Exit(1)
	}
	stale := 0
	for rel, want := range files {
		path := filepath.Join(*root, rel)
		got, err := os.ReadFile(path)
		if err == nil && string(got) == string(want) {
			continue
		}
		stale++
		if *check {
			fmt.Printf("out of date: %s\n", rel)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "brandgen:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(path, want, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "brandgen:", err)
			os.Exit(1)
		}
		fmt.Printf("wrote %s\n", rel)
	}
	if *check && stale > 0 {
		fmt.Fprintf(os.Stderr, "%d generated file(s) out of date — run `make brand`\n", stale)
		os.Exit(1)
	}
	if stale == 0 {
		fmt.Println("brand files are in step with brand.json")
	}
}
