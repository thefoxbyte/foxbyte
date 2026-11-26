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
//	fox-verify --export main-ledger.jsonl --anchors-s3 s3://acme-anchors/anchors/main \
//	           --s3-endpoint https://s3.eu-west-1.amazonaws.com --s3-region eu-west-1 --s3-access-key AKIA…
//
// With --anchors-s3 it reads the anchors from the bucket they are locked in,
// every version of every one, with read-only keys of the auditor's own: the
// first version of each is the anchor of record, and a delete marker, a later
// version, a missing anchor at the start, or anchoring that stopped while rows
// kept arriving is reported as a problem. Given --anchors as well, it also
// checks the local files against the locked copies.
//
// Exit status: 0 intact, 1 tampered, 2 usage or connection error.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/thefoxbyte/foxbyte/internal/ledger"
	"github.com/thefoxbyte/foxbyte/internal/s3read"
	"github.com/thefoxbyte/foxbyte/internal/version"
)

func main() {
	dsn := flag.String("dsn", os.Getenv("DATABASE_URL"), "Postgres connection string for the branch (default $DATABASE_URL)")
	export := flag.String("export", "", "check a `fox ledger export` JSON-lines file instead of a live database")
	anchorDir := flag.String("anchors", "", "directory holding the branch's anchor files")
	anchorsS3 := flag.String("anchors-s3", "", "the anchors in a bucket: s3://`bucket/[prefix/]anchors/<branch>`; every object version is read")
	s3Endpoint := flag.String("s3-endpoint", "", "the bucket's S3 endpoint (default https://s3.<region>.amazonaws.com)")
	s3Region := flag.String("s3-region", "us-east-1", "the bucket's region")
	s3AccessKey := flag.String("s3-access-key", os.Getenv("AWS_ACCESS_KEY_ID"), "an access key that may read the bucket (default $AWS_ACCESS_KEY_ID); the secret is read from $FOX_VERIFY_S3_SECRET_KEY or $AWS_SECRET_ACCESS_KEY")
	s3PathStyle := flag.Bool("s3-path-style", false, "put the bucket in the path rather than the host name (MinIO and most non-AWS stores)")
	maxAge := flag.Duration("max-anchor-age", 24*time.Hour, "with --anchors-s3: rows left unanchored in the bucket for longer than this are a problem")
	asJSON := flag.Bool("json", false, "print the report as JSON")
	pubKey := flag.String("pubkey", "", "the anchors' public key (fox blackbox anchor-key): every anchor after the first signed one must be signed by it")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: fox-verify (--dsn <postgres-url> | --export <file.jsonl>) (--anchors <dir> | --anchors-s3 s3://… | both) [--pubkey <file>] [--json]")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVersion {
		fmt.Printf("fox-verify %s\n", version.Version)
		return
	}
	if (*anchorDir == "" && *anchorsS3 == "") || (*dsn == "" && *export == "") {
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
	var local []ledger.Anchor
	if *anchorDir != "" {
		if local, err = ledger.LoadAnchors(*anchorDir); err != nil {
			fmt.Fprintln(os.Stderr, "fox-verify:", err)
			os.Exit(2)
		}
	}
	anchors := local
	var bucket bucketResult
	if *anchorsS3 != "" {
		cfg, prefix, err := s3Config(*anchorsS3, *s3Endpoint, *s3Region, *s3AccessKey, *s3PathStyle)
		if err != nil {
			fmt.Fprintln(os.Stderr, "fox-verify:", err)
			os.Exit(2)
		}
		if bucket, err = readBucket(cfg, prefix); err != nil {
			fmt.Fprintln(os.Stderr, "fox-verify: reading the bucket:", err)
			os.Exit(2)
		}
		anchors = bucket.anchors
	}
	if len(anchors) == 0 {
		where := *anchorDir
		if *anchorsS3 != "" {
			where = *anchorsS3
		}
		fmt.Fprintf(os.Stderr, "fox-verify: warning: no anchors in %s — only the hash chain can be checked\n", where)
	}

	rep := ledger.Verify(rows, anchors)
	if *anchorsS3 != "" {
		now := time.Now()
		gaps, gapNotes := ledger.Coverage(rows, anchors, now, *maxAge)
		problems := append(append([]string{}, bucket.problems...), gaps...)
		notes := append([]string{fmt.Sprintf("anchors read from %s: %d anchor(s), from %d object version(s)", *anchorsS3, len(anchors), bucket.versions)}, bucket.notes...)
		notes = append(notes, gapNotes...)
		if *anchorDir != "" {
			p, n := ledger.CompareAnchors(local, anchors, now, *maxAge)
			problems, notes = append(problems, p...), append(notes, n...)
		}
		rep.Problems = append(rep.Problems, problems...)
		rep.Notes = append(rep.Notes, notes...)
		rep.Intact = len(rep.Problems) == 0
	}
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
//
// Recomputing a hash needs every entry's statement, which client roles cannot
// read directly (audit PRIV-3): through the gateway that takes an admin's key
// (db_admin), whose login reads the text through bb.ledger_statement.
func readDatabase(dsn string) ([]ledger.Row, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connecting: %w", err)
	}
	defer conn.Close(ctx)

	var withExt, direct, viaFunc, withSeals bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('bb.ledger_ext') IS NOT NULL,
  has_column_privilege('bb.schema_ledger', 'statement', 'SELECT'),
  to_regprocedure('bb.ledger_statement(bigint)') IS NOT NULL, `+ledger.SealsAvailable).Scan(&withExt, &direct, &viaFunc, &withSeals); err != nil {
		return nil, fmt.Errorf("reading the ledger: %w", err)
	}
	query := ledger.RowsQuerySealed(withExt, withSeals, "")
	if !direct {
		var admin bool
		if viaFunc {
			if err := conn.QueryRow(ctx, "SELECT bb._may_override()").Scan(&admin); err != nil {
				return nil, fmt.Errorf("reading the ledger: %w", err)
			}
		}
		if !admin {
			return nil, errors.New("this login cannot read the Blackbox's statement text, which every hash covers: " +
				"connect as an admin (fox admin grant <email>) or verify an export (fox ledger export)")
		}
		query = ledger.ClientRowsQuerySealed(withExt, withSeals, "")
	}
	rs, err := conn.Query(ctx, query)
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

// s3Config reads s3://bucket/[prefix/]anchors/<branch> and the flags into a
// bucket to read and the prefix to list.
func s3Config(u, endpoint, region, accessKey string, pathStyle bool) (s3read.Config, string, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(u), "s3://")
	if !ok {
		return s3read.Config{}, "", fmt.Errorf("--anchors-s3 must be s3://bucket/[prefix/]anchors/<branch>, not %q", u)
	}
	bucket, prefix, _ := strings.Cut(rest, "/")
	prefix = strings.Trim(prefix, "/")
	if bucket == "" || prefix == "" {
		return s3read.Config{}, "", fmt.Errorf("--anchors-s3 needs a bucket and the branch's anchor path: s3://bucket/[prefix/]anchors/<branch>, not %q", u)
	}
	secret := os.Getenv("FOX_VERIFY_S3_SECRET_KEY")
	if secret == "" {
		secret = os.Getenv("AWS_SECRET_ACCESS_KEY")
	}
	if accessKey == "" || secret == "" {
		return s3read.Config{}, "", errors.New("reading a bucket needs an access key (--s3-access-key or $AWS_ACCESS_KEY_ID) and its secret ($FOX_VERIFY_S3_SECRET_KEY or $AWS_SECRET_ACCESS_KEY)")
	}
	if endpoint == "" {
		endpoint = "https://s3." + region + ".amazonaws.com"
	}
	return s3read.Config{Endpoint: endpoint, Region: region, Bucket: bucket, AccessKey: accessKey, SecretKey: secret, PathStyle: pathStyle}, prefix + "/", nil
}

type bucketResult struct {
	anchors         []ledger.Anchor
	problems, notes []string
	versions        int
}

// readBucket lists every version under prefix, fetches each one and its
// retention, eight at a time, and hands them to ledger.BucketAnchors.
func readBucket(cfg s3read.Config, prefix string) (bucketResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	vs, err := cfg.ListVersions(ctx, prefix)
	if err != nil {
		return bucketResult{}, err
	}
	objs := make([]ledger.BucketObject, len(vs))
	errs := make([]error, len(vs))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, v := range vs {
		objs[i] = ledger.BucketObject{Key: v.Key, VersionID: v.VersionID, LastModified: v.LastModified, DeleteMarker: v.DeleteMarker}
		if v.DeleteMarker || !strings.HasSuffix(v.Key, ".json") {
			continue
		}
		wg.Add(1)
		go func(i int, v s3read.Version) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			body, err := cfg.GetVersion(ctx, v.Key, v.VersionID)
			if err != nil {
				errs[i] = fmt.Errorf("%s (version %s): %w", v.Key, v.VersionID, err)
				return
			}
			objs[i].Body = body
			// The keys may not be allowed to read retention: that is said in
			// the report, not treated as a failure.
			if mode, _, err := cfg.Retention(ctx, v.Key, v.VersionID); err == nil {
				objs[i].Retention, objs[i].RetentionKnown = mode, true
			}
		}(i, v)
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return bucketResult{}, err
	}
	anchors, problems, notes := ledger.BucketAnchors(objs)
	return bucketResult{anchors: anchors, problems: problems, notes: notes, versions: len(vs)}, nil
}
