// SPDX-License-Identifier: AGPL-3.0-or-later

// Command fox-verify independently checks a FoxByte Blackbox against its
// checkpoint anchors.
//
// It trusts neither the database nor the FoxByte engine: it recomputes every
// row hash and every checkpoint Merkle root itself and compares them with the
// anchor files, which are kept outside the database. Rewritten, deleted or wiped
// history is reported even if the ledger's own hash chain was recomputed to hide
// it. The anchor format is documented in docs/ledger-anchor-format.md.
//
//	fox-verify --dsn 'postgresql://dbadmin:<api-key>@localhost:6432/main?sslmode=require' \
//	           --anchors ~/.fox/anchors/main
//	fox-verify --export main-ledger.jsonl --anchors ./anchors/main
//
// Exit status: 0 intact, 1 tampered, 2 usage or connection error.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/thefoxbyte/foxbyte/internal/ledger"
	"github.com/thefoxbyte/foxbyte/internal/version"
)

func main() {
	dsn := flag.String("dsn", os.Getenv("DATABASE_URL"), "Postgres connection string for the branch (default $DATABASE_URL)")
	export := flag.String("export", "", "check a `fox ledger export` JSON-lines file instead of a live database")
	anchorDir := flag.String("anchors", "", "directory holding the branch's anchor files (required)")
	asJSON := flag.Bool("json", false, "print the report as JSON")
	pubKey := flag.String("pubkey", "", "the anchors' public key (fox blackbox anchor-key): every anchor after the first signed one must be signed by it")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: fox-verify (--dsn <postgres-url> | --export <file.jsonl>) --anchors <dir> [--pubkey <file>] [--json]")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVersion {
		fmt.Printf("fox-verify %s\n", version.Version)
		return
	}
	if *anchorDir == "" || (*dsn == "" && *export == "") {
		flag.Usage()
		os.Exit(2)
	}

	var rows []ledger.Row
	var err error
	if *export != "" {
		rows, err = readExport(*export)
	} else {
		rows, err = readDatabase(*dsn)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fox-verify:", err)
		os.Exit(2)
	}
	anchors, err := ledger.LoadAnchors(*anchorDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fox-verify:", err)
		os.Exit(2)
	}
	if len(anchors) == 0 {
		fmt.Fprintf(os.Stderr, "fox-verify: warning: no anchor files in %s — only the hash chain can be checked\n", *anchorDir)
	}

	rep := ledger.Verify(rows, anchors)
	if *pubKey != "" {
		pub, err := ledger.ReadPublicKey(*pubKey)
		if err != nil {
			fmt.Fprintln(os.Stderr, "fox-verify:", err)
			os.Exit(2)
		}
		ledger.VerifySignatures(&rep, anchors, pub)
	} else if len(anchors) > 0 {
		rep.Notes = append(rep.Notes, "anchor signatures were not checked: pass --pubkey to prove the anchors are genuine")
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		fmt.Println(rep.Summary())
	}
	if !rep.Intact {
		os.Exit(1)
	}
}

// readExport parses a `fox ledger export` file (one JSON ledger row per line).
func readExport(path string) ([]ledger.Row, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var rows []ledger.Row
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 64*1024*1024) // a statement can be long
	line := 0
	for sc.Scan() {
		line++
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		r, err := ledger.DecodeRowJSON(b)
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, line, err)
		}
		rows = append(rows, r)
	}
	return rows, sc.Err()
}

// readDatabase reads every ledger row over a plain Postgres connection. Read
// access to bb.schema_ledger (and bb.ledger_ext, if present) is all it needs —
// a connection through the FoxByte gateway with an API key works.
func readDatabase(dsn string) ([]ledger.Row, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connecting: %w", err)
	}
	defer conn.Close(ctx)

	var withExt bool
	if err := conn.QueryRow(ctx, "SELECT to_regclass('bb.ledger_ext') IS NOT NULL").Scan(&withExt); err != nil {
		return nil, fmt.Errorf("reading the ledger: %w", err)
	}
	rs, err := conn.Query(ctx, ledger.RowsQuery(withExt, ""))
	if err != nil {
		return nil, fmt.Errorf("reading the ledger: %w", err)
	}
	defer rs.Close()
	var rows []ledger.Row
	for rs.Next() {
		var line string
		if err := rs.Scan(&line); err != nil {
			return nil, err
		}
		r, err := ledger.DecodeRowJSON([]byte(line))
		if err != nil {
			return nil, err
		}
		rows = append(rows, r)
	}
	return rows, rs.Err()
}
