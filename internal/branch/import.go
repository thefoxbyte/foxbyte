// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Migration into FoxByte. Because FoxByte *is* PostgreSQL, "migrate to
// FoxByte" always means "land the source in a fresh Postgres instance".
//
//   - a Postgres (or Postgres-wire) source → pg_dump | psql, full fidelity
//   - a .sql dump                          → psql
//   - a .csv                               → a table (text columns) via COPY
//   - a .json / .ndjson                    → a table of JSONB documents
//
// The loaders are stream-based, so the same code serves a local file path
// (CLI), stdin (a file streamed from the client machine), and a browser upload.

const pgImportOptions = "PGOPTIONS=-c bb.allow_destructive=on"

type sourceKind int

const (
	srcSQL sourceKind = iota
	srcCSV
	srcJSON
)

// Progress is a sink for migration progress: a human-readable log stream plus an
// optional item-level step callback (e.g. MongoDB collections done/total). Both
// are nil-safe, so callers that don't care can pass a bare &Progress{} or nil.
type Progress struct {
	Log  io.Writer
	Step func(done, total int, label string)
}

func stdoutProgress() *Progress { return &Progress{Log: os.Stdout} }

func (p *Progress) Logf(format string, a ...any) {
	if p != nil && p.Log != nil {
		fmt.Fprintf(p.Log, format, a...)
	}
}

func (p *Progress) step(done, total int, label string) {
	if p != nil && p.Step != nil {
		p.Step(done, total, label)
	}
}

// Import loads a Postgres source (postgres://…) or a local file (.sql/.csv/.json)
// into a new instance named target, returning the resolved instance name. Output
// goes to stdout; use ImportTo to stream progress elsewhere (e.g. the web console).
func Import(source, target string) (string, error) {
	return ImportTo(stdoutProgress(), source, target)
}

// ImportTo is Import with an explicit progress sink.
func ImportTo(p *Progress, source, target string) (string, error) {
	switch {
	case isPostgresDSN(source):
		return importInstance(p, target, defaultTargetName(source), "PostgreSQL source (pg_dump)",
			func(t string) error { return loadPostgres(p, t, source) })
	case hasScheme(source, "mysql", "mariadb"):
		return importInstance(p, target, defaultTargetName(source), "MySQL/MariaDB source (pgloader)",
			func(t string) error { return loadMySQL(p, t, source) })
	case hasScheme(source, "mongodb", "mongodb+srv"):
		return importInstance(p, target, defaultTargetName(source), "MongoDB source (collections → JSONB)",
			func(t string) error { return loadMongo(p, t, source) })
	}
	info, err := os.Stat(source)
	if err != nil || info.IsDir() {
		return "", fmt.Errorf("source must be a postgres:// connection string or a readable .sql/.csv/.json file (got %q)", source)
	}
	kind, err := kindFromExt(filepath.Ext(source))
	if err != nil {
		return "", err
	}
	f, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return ImportReaderTo(p, f, kind, filepath.Base(source), target)
}

// ImportReader loads a stream (a .sql/.csv/.json file's contents, from stdin or a
// browser upload) into a new instance. srcname names the origin, used for the
// default instance name and the target table for CSV/JSON.
func ImportReader(r io.Reader, kind sourceKind, srcname, target string) (string, error) {
	return ImportReaderTo(stdoutProgress(), r, kind, srcname, target)
}

// ImportReaderTo is ImportReader with an explicit progress sink.
func ImportReaderTo(p *Progress, r io.Reader, kind sourceKind, srcname, target string) (string, error) {
	stem := strings.TrimSuffix(srcname, filepath.Ext(srcname))
	// The TABLE keeps the source name verbatim (schema fidelity); the instance name
	// must be filesystem/docker-safe, so it stays sanitized.
	table := stem
	instance := "import-" + sanitizeIdent(stem)
	return importInstance(p, target, instance, describeKind(kind, srcname), func(t string) error {
		switch kind {
		case srcSQL:
			return loadSQL(p, t, r)
		case srcCSV:
			return loadCSV(p, t, r, table)
		case srcJSON:
			return loadJSON(p, t, r, table)
		}
		return fmt.Errorf("unsupported source kind")
	})
}

// importInstance creates the target instance, gives it a clean public schema,
// runs the loader, and prints a summary.
func importInstance(p *Progress, target, defName, desc string, load func(string) error) (string, error) {
	if target == "" {
		target = defName
	}
	p.Logf("Creating instance %q…\n", target)
	if err := Create(target, "main"); err != nil {
		return "", fmt.Errorf("create target instance %q: %w", target, err)
	}
	// Relax the destructive-DDL guardrail for the bulk load — external loaders
	// (pgloader) use their own connections, so PGOPTIONS alone isn't enough. The
	// logging triggers stay on, so the migration is still recorded in the ledger.
	setGuard(target, false)
	defer setGuard(target, true)
	if err := prepareTarget(target); err != nil {
		return target, fmt.Errorf("prepare target: %w", err)
	}
	p.Logf("Importing %s → %q…\n", desc, target)
	if err := load(target); err != nil {
		return target, fmt.Errorf("import failed: %w", err)
	}
	// A finished load that produced no tables is a failure, not a success — the
	// usual cause is the wrong database named in the source. (Loaders with a more
	// specific diagnosis, e.g. loadMySQL, return before reaching here.)
	n := TableCount(target)
	if n == 0 {
		return target, fmt.Errorf("no tables were imported into %q — the source is empty or the wrong database was named (check the connection string or file)", target)
	}
	p.Logf("\n✓ Imported into instance %q — %d table(s) now present.\n", target, n)
	p.Logf("  Connect: postgres://dbadmin:<API_KEY>@localhost:6432/%s\n", target)
	p.Logf("  Browse:  the web console (Console / Ledger), branch = %q\n", target)
	return target, nil
}

// ImportContinuous sets up continuous logical replication from a Postgres source
// into a fresh instance: an initial copy followed by streaming changes, so you can
// cut over with zero downtime. The source must allow logical replication
// (wal_level=logical), and the connecting role must be replication-capable and own
// (or be able to read) the tables.
func ImportContinuous(source, target string) (string, error) {
	return ImportContinuousTo(stdoutProgress(), source, target)
}

// ImportContinuousTo is ImportContinuous with an explicit progress sink.
func ImportContinuousTo(p *Progress, source, target string) (string, error) {
	if !isPostgresDSN(source) {
		return "", fmt.Errorf("--continuous requires a postgres:// source (logical replication)")
	}
	if target == "" {
		target = defaultTargetName(source)
	}
	p.Logf("Creating instance %q…\n", target)
	if err := Create(target, "main"); err != nil {
		return "", fmt.Errorf("create target instance %q: %w", target, err)
	}
	setGuard(target, false)
	defer setGuard(target, true)
	if err := prepareTarget(target); err != nil {
		return target, fmt.Errorf("prepare target: %w", err)
	}
	// Copy the schema (structure only) first: logical replication replicates data,
	// not DDL, so the subscriber needs the tables to exist before it can populate
	// them. --no-publications/--no-subscriptions keep the source's own replication
	// objects out of the target.
	p.Logf("Copying schema (structure only)…\n")
	schemaScript := fmt.Sprintf("set -euo pipefail; pg_dump %s --schema-only --no-owner --no-acl --no-comments "+
		"--no-publications --no-subscriptions | psql -q -U %s -d %s", shellQuote(source), pgUser, pgDatabase)
	if err := run("docker", "exec", "-e", pgImportOptions, container(target), "bash", "-c", schemaScript); err != nil {
		return target, fmt.Errorf("copy schema from source: %w", err)
	}
	// If the schema copy produced no tables, the source is empty or the wrong
	// database was named — fail before setting up an empty subscription.
	if TableCount(target) == 0 {
		return target, fmt.Errorf("the source database has no tables to replicate (check the database name in the connection string)")
	}
	// Best-effort: create a publication covering all tables on the source. If the
	// role lacks privilege or a publication named bb_pub already exists, continue —
	// the subscription below surfaces any real problem.
	p.Logf("Ensuring a publication on the source…\n")
	_ = run("docker", "exec", container(target), "psql", source, "-v", "ON_ERROR_STOP=0",
		"-c", "CREATE PUBLICATION bb_pub FOR ALL TABLES;")
	// Subscribe on the target: initial copy + streaming changes.
	p.Logf("Creating subscription (initial copy, then streaming)…\n")
	sub := fmt.Sprintf("CREATE SUBSCRIPTION bb_sub CONNECTION %s PUBLICATION bb_pub;", sqlQuote(source))
	if err := run("docker", "exec", "-e", pgImportOptions, container(target),
		"psql", "-U", pgUser, "-d", pgDatabase, "-v", "ON_ERROR_STOP=1", "-c", sub); err != nil {
		return target, fmt.Errorf("could not start replication — the source must allow logical replication "+
			"(wal_level=logical), expose a replication-capable role, and be reachable from FoxByte: %w", err)
	}
	p.Logf("\n✓ Continuous replication active into %q.\n", target)
	p.Logf("  The initial copy runs now; subsequent changes stream continuously.\n")
	p.Logf("  Progress:  SELECT * FROM pg_stat_subscription;\n")
	p.Logf("  Cut over once caught up:  fox import-cutover %s\n", target)
	return target, nil
}

// ImportCutover stops the continuous replication started by ImportContinuous,
// leaving the copied data in place so the instance becomes standalone.
func ImportCutover(target string) error { return ImportCutoverTo(stdoutProgress(), target) }

// ImportCutoverTo is ImportCutover with an explicit progress sink (the API passes
// one that discards output).
func ImportCutoverTo(p *Progress, target string) error {
	// Guard the wrong-instance / never-replicated case before finalizing: an
	// instance with no tables means continuous replication landed nothing.
	if TableCount(target) == 0 {
		return fmt.Errorf("instance %q has no tables — continuous replication never landed anything (the source was empty or the wrong database was named); nothing to finalize", target)
	}
	p.Logf("Finalizing %q — stopping replication, keeping data…\n", target)
	if err := run("docker", "exec", container(target), "psql", "-U", pgUser, "-d", pgDatabase,
		"-c", "DROP SUBSCRIPTION IF EXISTS bb_sub;"); err != nil {
		return err
	}
	p.Logf("✓ %q is now a standalone instance (%d tables).\n", target, TableCount(target))
	return nil
}

// TableCount returns the number of user tables in an instance (excludes system
// schemas and the fox ledger schema).
func TableCount(name string) int {
	out, _ := capture("docker", "exec", container(name),
		"psql", "-U", pgUser, "-d", pgDatabase, "-tAc",
		`SELECT count(*) FROM information_schema.tables
		 WHERE table_schema NOT IN ('pg_catalog','information_schema','fox')`)
	n, _ := strconv.Atoi(strings.TrimSpace(out))
	return n
}

// --- source detection ---

func isPostgresDSN(s string) bool {
	return strings.HasPrefix(s, "postgres://") || strings.HasPrefix(s, "postgresql://")
}

func kindFromExt(ext string) (sourceKind, error) {
	switch strings.ToLower(ext) {
	case ".sql":
		return srcSQL, nil
	case ".csv":
		return srcCSV, nil
	case ".json", ".ndjson", ".jsonl":
		return srcJSON, nil
	}
	return 0, fmt.Errorf("unsupported file type %q — supported: .sql, .csv, .json", ext)
}

// ParseKind maps a short kind name ("sql"/"csv"/"json") to a source kind, for
// streamed (stdin / upload) imports where there is no filename to inspect.
func ParseKind(s string) (sourceKind, error) {
	return kindFromExt("." + strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "."))
}

func describeKind(k sourceKind, name string) string {
	switch k {
	case srcSQL:
		return "SQL dump " + name
	case srcCSV:
		return "CSV " + name
	case srcJSON:
		return "JSON " + name + " (→ JSONB)"
	}
	return name
}

func defaultTargetName(dsn string) string {
	db := dsn
	if i := strings.LastIndex(db, "/"); i >= 0 {
		db = db[i+1:]
	}
	if j := strings.IndexAny(db, "?"); j >= 0 {
		db = db[:j]
	}
	if db == "" {
		return "import-db"
	}
	return "import-" + sanitizeIdent(db)
}

// --- loaders (all stream-based) ---

// prepareTarget gives the new instance a clean public schema, independent of
// main's current contents (the fox ledger schema is left intact).
func prepareTarget(target string) error {
	return run("docker", "exec", "-e", pgImportOptions, container(target),
		"psql", "-q", "-U", pgUser, "-d", pgDatabase, "-c",
		"DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;")
}

func loadPostgres(p *Progress, target, dsn string) error {
	p.Logf("  running pg_dump | psql (schema + data)…\n")
	script := fmt.Sprintf("set -euo pipefail; pg_dump %s --no-owner --no-acl --no-comments | psql -q -U %s -d %s",
		shellQuote(dsn), pgUser, pgDatabase)
	// psql exits 0 even when statements fail, so its errors are counted instead.
	c, err := runCollectingErrors(nil, "docker", "exec", "-e", pgImportOptions, container(target), "bash", "-c", script)
	return c.failure(target, err)
}

// loadMySQL migrates a MySQL/MariaDB source using pgloader (schema + data + type
// mapping), run as a throwaway container on the shared network so it can reach
// both the source and the target branch's Postgres.
func loadMySQL(p *Progress, target, dsn string) error {
	// pgloader can't read MySQL 8.x (its caching_sha2_password handshake and its
	// information_schema layout), so route those to a mysqldump-based path whose
	// client speaks the modern protocol. MariaDB and MySQL ≤5.7 stay on pgloader,
	// which maps their indexes/constraints more richly.
	if mysqlNeedsNative(dsn) {
		return loadMySQLNative(p, target, dsn)
	}
	if err := ensurePgloaderImage(p); err != nil {
		return fmt.Errorf("prepare pgloader: %w", err)
	}
	dsn = strings.Replace(dsn, "mariadb://", "mysql://", 1)
	pgTarget := fmt.Sprintf("postgresql://%s:%s@%s:5432/%s", pgUser, pgPass(), container(target), pgDatabase)
	p.Logf("  running pgloader (schema + data + type mapping)…\n")
	// pgloader exits 0 even when it fails outright (a bad connection) or silently
	// loads nothing (e.g. it can't read a MySQL 8.0 source's metadata), so the exit
	// code can't be trusted. Show the operator its log, then treat "no tables
	// landed" as the real success signal.
	out, err := exec.Command("sudo", "docker", "run", "--rm", "--network", network,
		pgloaderImage, "pgloader", dsn, pgTarget).CombinedOutput()
	p.Logf("%s", string(out))
	if err != nil {
		return fmt.Errorf("pgloader: %w", err)
	}
	if TableCount(target) == 0 {
		if strings.Contains(string(out), "Failed to connect") || strings.Contains(string(out), "UNSUPPORTED-AUTHENTICATION") {
			return fmt.Errorf("pgloader could not authenticate to the source (see log above); MySQL 8 needs the server started with mysql_native_password — its default caching_sha2_password handshake is unsupported")
		}
		return fmt.Errorf("pgloader loaded no tables (see log above); the source may be empty or unreadable — or export it to a .sql/.csv/.json file and run `fox import` on that")
	}
	return nil
}

// ensurePgloaderImage builds the local, arch-native pgloader image if it is not
// already present. Idempotent; the build runs only on the first migration.
func ensurePgloaderImage(p *Progress) error {
	if exec.Command("sudo", "docker", "image", "inspect", pgloaderImage).Run() == nil {
		return nil
	}
	p.Logf("  building the pgloader image (first run only)…\n")
	dockerfile := "FROM debian:stable-slim\n" +
		"RUN apt-get update && apt-get install -y --no-install-recommends pgloader ca-certificates && rm -rf /var/lib/apt/lists/*\n"
	cmd := exec.Command("sudo", "docker", "build", "-t", pgloaderImage, "-")
	cmd.Stdin = strings.NewReader(dockerfile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// --- MySQL 8.x native path (mysqldump; the client speaks caching_sha2_password) ---

type myDSN struct{ host, port, user, pass, db string }

func parseMyDSN(dsn string) myDSN {
	u, err := url.Parse(dsn)
	if err != nil {
		return myDSN{}
	}
	c := myDSN{host: u.Hostname(), port: u.Port(), db: strings.TrimPrefix(u.Path, "/")}
	if c.port == "" {
		c.port = "3306"
	}
	if u.User != nil {
		c.user = u.User.Username()
		c.pass, _ = u.User.Password()
	}
	return c
}

// myArgs builds a `docker run … mysql:8 <tool> -h… -u…` argument list.
func myArgs(c myDSN, tool string, extra ...string) []string {
	a := []string{"docker", "run", "--rm", "--network", network, mysqlImage, tool,
		"-h", c.host, "-P", c.port, "-u", c.user}
	if c.pass != "" {
		a = append(a, "-p"+c.pass)
	}
	return append(a, extra...)
}

// mysqlNeedsNative reports whether a source needs the mysqldump path: true only
// for MySQL ≥8. MariaDB and MySQL ≤5.7 (and an unreachable probe) return false so
// pgloader handles them. stdout carries only the version; warnings go to stderr.
func mysqlNeedsNative(dsn string) bool {
	c := parseMyDSN(dsn)
	if c.host == "" {
		return false
	}
	out, err := exec.Command("sudo", myArgs(c, "mysql", "-N", "-B", "-e", "SELECT VERSION()")...).Output()
	if err != nil {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(string(out)))
	if v == "" || strings.Contains(v, "mariadb") {
		return false
	}
	maj := 0
	for _, ch := range v {
		if ch < '0' || ch > '9' {
			break
		}
		maj = maj*10 + int(ch-'0')
	}
	return maj >= 8
}

// loadMySQLNative imports a MySQL 8.x source: it reads the schema from
// information_schema (reliable across versions) and streams data via mysqldump,
// translating MySQL's dialect/escaping for Postgres.
func loadMySQLNative(p *Progress, target, dsn string) error {
	c := parseMyDSN(dsn)
	if c.db == "" {
		return fmt.Errorf("the MySQL connection string must include a database name (…/dbname)")
	}
	p.Logf("  MySQL 8.x source — importing via mysqldump (pgloader can't read this version)…\n")
	tables, err := mysqlTables(c)
	if err != nil {
		return err
	}
	if len(tables) == 0 {
		return fmt.Errorf("no tables found in database %q", c.db)
	}
	p.Logf("  %d table(s): %s\n", len(tables), strings.Join(tables, ", "))

	// 1. Schema — build CREATE TABLE from information_schema.
	var ddl strings.Builder
	for i, t := range tables {
		p.Logf("  table %q…\n", t)
		p.step(i+1, len(tables), "table "+t)
		stmt, err := mysqlCreateTable(c, t)
		if err != nil {
			return fmt.Errorf("read schema of %q: %w", t, err)
		}
		ddl.WriteString(stmt)
	}
	if err := pipeInto(target, strings.NewReader(ddl.String()),
		"psql", "-q", "-U", pgUser, "-d", pgDatabase, "-v", "ON_ERROR_STOP=1"); err != nil {
		return fmt.Errorf("create tables: %w", err)
	}

	// 2. Data — mysqldump (ANSI: double-quoted identifiers, one row per INSERT),
	// loaded with MySQL-style backslash escaping enabled for the session.
	p.Logf("  copying rows…\n")
	data, err := mysqldumpData(c)
	if err != nil {
		return err
	}
	preamble := "SET client_encoding='UTF8';\nSET standard_conforming_strings=off;\nSET backslash_quote=on;\nSET client_min_messages=warning;\n"
	if err := pipeInto(target, strings.NewReader(preamble+data),
		"psql", "-q", "-U", pgUser, "-d", pgDatabase, "-v", "ON_ERROR_STOP=1"); err != nil {
		return fmt.Errorf("load rows: %w", err)
	}
	return nil
}

func mysqlTables(c myDSN) ([]string, error) {
	q := fmt.Sprintf("SELECT table_name FROM information_schema.tables WHERE table_schema=%s AND table_type='BASE TABLE' ORDER BY table_name", sqlQuote(c.db))
	out, err := exec.Command("sudo", myArgs(c, "mysql", "-N", "-B", "-e", q)...).Output()
	if err != nil {
		return nil, fmt.Errorf("could not reach the MySQL source: %w", err)
	}
	var t []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if s := strings.TrimSpace(line); s != "" {
			t = append(t, s)
		}
	}
	return t, nil
}

// mysqlCreateTable renders a Postgres CREATE TABLE for one source table. mysqldump
// emits full-row INSERTs (no column list), so column order here must match the
// source's ordinal_position — and generated columns are skipped in both places.
func mysqlCreateTable(c myDSN, table string) (string, error) {
	q := fmt.Sprintf(`SELECT column_name, data_type, column_type, is_nullable, column_key, extra `+
		`FROM information_schema.columns WHERE table_schema=%s AND table_name=%s ORDER BY ordinal_position`,
		sqlQuote(c.db), sqlQuote(table))
	out, err := exec.Command("sudo", myArgs(c, "mysql", "-N", "-B", "-e", q)...).Output()
	if err != nil {
		return "", err
	}
	var defs, pk []string
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 6 {
			continue
		}
		name, dtype, ctype := f[0], strings.ToLower(f[1]), strings.ToLower(f[2])
		nullable, key, extra := f[3], f[4], strings.ToUpper(f[5])
		// Skip only true generated columns (VIRTUAL/STORED), which mysqldump omits
		// from INSERTs — NOT "DEFAULT_GENERATED", which just marks a column default.
		if strings.Contains(extra, "VIRTUAL GENERATED") || strings.Contains(extra, "STORED GENERATED") {
			continue
		}
		def := pgIdent(name) + " " + mapMySQLType(dtype, ctype)
		if nullable == "NO" {
			def += " NOT NULL"
		}
		defs = append(defs, def)
		if key == "PRI" {
			pk = append(pk, pgIdent(name))
		}
	}
	if len(defs) == 0 {
		return "", fmt.Errorf("no columns")
	}
	body := strings.Join(defs, ", ")
	if len(pk) > 0 {
		body += ", PRIMARY KEY (" + strings.Join(pk, ", ") + ")"
	}
	return fmt.Sprintf("CREATE TABLE %s (%s);\n", pgIdent(table), body), nil
}

// mapMySQLType maps a MySQL column type to a Postgres type. It preserves numeric
// precision and widens for unsigned ranges; text/binary/enum and anything unknown
// fall back to text so a data migration never fails on a length or type mismatch.
func mapMySQLType(dataType, columnType string) string {
	unsigned := strings.Contains(columnType, "unsigned")
	switch dataType {
	case "tinyint":
		return "smallint"
	case "smallint":
		if unsigned {
			return "integer"
		}
		return "smallint"
	case "mediumint", "year":
		return "integer"
	case "int", "integer":
		if unsigned {
			return "bigint"
		}
		return "integer"
	case "bigint":
		if unsigned {
			return "numeric"
		}
		return "bigint"
	case "decimal", "numeric":
		if i := strings.Index(columnType, "("); i >= 0 {
			return "numeric" + columnType[i:strings.Index(columnType, ")")+1]
		}
		return "numeric"
	case "float":
		return "real"
	case "double", "real":
		return "double precision"
	case "bit":
		return "smallint"
	case "date":
		return "date"
	case "datetime", "timestamp":
		return "timestamp"
	case "time":
		return "time"
	case "json":
		return "jsonb"
	default: // char/varchar/text/enum/set/blob/binary/… → text
		return "text"
	}
}

// mysqldumpData returns the source's data as one INSERT statement per row, with
// ANSI-quoted identifiers and MySQL-style value escaping. Non-INSERT lines
// (LOCK/UNLOCK/SET/comments) are dropped; each INSERT is a single physical line.
func mysqldumpData(c myDSN) (string, error) {
	args := []string{"docker", "run", "--rm", "--network", network, mysqlImage, "mysqldump",
		"-h", c.host, "-P", c.port, "-u", c.user}
	if c.pass != "" {
		args = append(args, "-p"+c.pass)
	}
	args = append(args, "--no-create-info", "--compatible=ansi", "--skip-extended-insert",
		"--no-tablespaces", "--skip-comments", "--skip-set-charset", "--default-character-set=utf8mb4", c.db)
	out, err := exec.Command("sudo", args...).Output()
	if err != nil {
		return "", fmt.Errorf("mysqldump failed: %w", err)
	}
	var b strings.Builder
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "INSERT INTO ") {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String(), nil
}

// loadMongo migrates every collection in a MongoDB source into its own JSONB
// table, using the mongo image's shell to enumerate and export documents.
func loadMongo(p *Progress, target, uri string) error {
	cols, err := mongoCollections(uri)
	if err != nil {
		return err
	}
	if len(cols) == 0 {
		return fmt.Errorf("no collections found at the source")
	}
	p.Logf("  %d collection(s): %s\n", len(cols), strings.Join(cols, ", "))
	for i, c := range cols {
		p.Logf("  collection %q → table %q (name preserved)…\n", c, c)
		p.step(i+1, len(cols), "collection "+c)
		if err := mongoImportCollection(p, target, uri, c); err != nil {
			return fmt.Errorf("collection %q: %w", c, err)
		}
	}
	return nil
}

func mongoCollections(uri string) ([]string, error) {
	out, err := exec.Command("sudo", "docker", "run", "--rm", "--network", network, mongoImage,
		"mongosh", uri, "--quiet", "--eval", "db.getCollectionNames().forEach(c=>print(c))").Output()
	if err != nil {
		return nil, fmt.Errorf("could not reach the MongoDB source: %w", err)
	}
	var cols []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l := strings.TrimSpace(line); l != "" && !strings.HasPrefix(l, "Warning") {
			cols = append(cols, l)
		}
	}
	return cols, nil
}

// mongoCleanJS is a mongosh helper that renders a document as PLAIN JSON —
// ObjectId → hex string, Date → ISO string, other BSON types → their string —
// recursively, so no Extended-JSON `$oid`/`$date` wrappers leak into the data
// (top-level or nested).
const mongoCleanJS = `function clean(v){if(v==null)return v;if(v instanceof Date)return v.toISOString();` +
	`if(typeof v!=='object')return v;if(v._bsontype)return v.toString();` +
	`if(Array.isArray(v))return v.map(clean);var o={};for(var k in v)o[k]=clean(v[k]);return o;}`

func mongoImportCollection(p *Progress, target, uri, coll string) error {
	// Stream each document as one plain-JSON line into the JSON loader.
	script := fmt.Sprintf("%s db.getCollection(%s).find().forEach(function(d){print(JSON.stringify(clean(d)))})",
		mongoCleanJS, jsStr(coll))
	cmd := exec.Command("sudo", "docker", "run", "--rm", "--network", network, mongoImage,
		"mongosh", uri, "--quiet", "--eval", script)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	if err := loadJSON(p, target, stdout, coll); err != nil { // preserve the collection name verbatim
		_ = cmd.Wait()
		return err
	}
	return cmd.Wait()
}

// reconcileGuard re-enables the destructive-DDL guardrail, which an import
// temporarily disables (setGuard). A crash mid-import would otherwise leave a
// branch permanently unguarded, so re-enable it whenever the branch (re)starts.
// Idempotent — enabling an already-enabled trigger is a no-op.
func reconcileGuard(name string) { setGuard(name, true) }

// setGuard enables/disables the ledger's destructive-DDL guardrail on an instance.
func setGuard(target string, enabled bool) {
	verb := "DISABLE"
	if enabled {
		verb = "ENABLE"
	}
	_ = run("docker", "exec", container(target), "psql", "-q", "-U", pgUser, "-d", pgDatabase,
		"-c", fmt.Sprintf("ALTER EVENT TRIGGER bb_guard_start %s;", verb))
}

func hasScheme(s string, schemes ...string) bool {
	for _, sc := range schemes {
		if strings.HasPrefix(s, sc+"://") {
			return true
		}
	}
	return false
}

func jsStr(s string) string { b, _ := json.Marshal(s); return string(b) }

func loadSQL(p *Progress, target string, r io.Reader) error {
	p.Logf("  running the .sql dump through psql…\n")
	// The whole dump runs; statements that failed make the import fail afterwards.
	c, err := runCollectingErrors(r, "docker", "exec", "-i", "-e", pgImportOptions, container(target),
		"psql", "-q", "-U", pgUser, "-d", pgDatabase)
	return c.failure(target, err)
}

// psqlErrorsShown caps how many failed statements an import error lists.
const psqlErrorsShown = 20

// psqlErrorCollector is an io.Writer for psql's stderr that keeps its ERROR and
// FATAL lines: how many there were and the first psqlErrorsShown of them.
type psqlErrorCollector struct {
	partial []byte
	count   int
	first   []string
}

func (c *psqlErrorCollector) Write(b []byte) (int, error) {
	c.partial = append(c.partial, b...)
	for {
		s := string(c.partial)
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			break
		}
		c.line(s[:i])
		c.partial = c.partial[i+1:]
	}
	return len(b), nil
}

// flush handles a last line without a newline.
func (c *psqlErrorCollector) flush() {
	if len(c.partial) > 0 {
		c.line(string(c.partial))
		c.partial = nil
	}
}

func (c *psqlErrorCollector) line(l string) {
	if !strings.Contains(l, "ERROR:") && !strings.Contains(l, "FATAL:") {
		return // NOTICE, WARNING, and the LINE/DETAIL/HINT context around an error
	}
	c.count++
	if len(c.first) < psqlErrorsShown {
		c.first = append(c.first, strings.TrimSpace(l))
	}
}

// failure is the import's result: an error listing the failed statements if
// there were any, else the command's own error.
func (c *psqlErrorCollector) failure(target string, runErr error) error {
	if c.count == 0 {
		return runErr
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d statement(s) failed — the rest loaded, and instance %q is kept so you can inspect it:", c.count, target)
	for _, e := range c.first {
		b.WriteString("\n  " + e)
	}
	if c.count > len(c.first) {
		fmt.Fprintf(&b, "\n  … and %d more", c.count-len(c.first))
	}
	return fmt.Errorf("%s", b.String())
}

// runCollectingErrors runs a privileged command like run (output shown), with
// stdin r, and collects the psql errors it printed.
func runCollectingErrors(r io.Reader, name string, args ...string) (*psqlErrorCollector, error) {
	c := &psqlErrorCollector{}
	cmd := exec.Command("sudo", append([]string{name}, args...)...)
	cmd.Stdin = r
	cmd.Stdout = os.Stdout
	cmd.Stderr = io.MultiWriter(os.Stderr, c)
	err := cmd.Run()
	c.flush()
	return c, err
}

func loadCSV(p *Progress, target string, r io.Reader, table string) error {
	br := bufio.NewReader(r)
	headerLine, err := br.ReadString('\n')
	if err != nil && headerLine == "" {
		return fmt.Errorf("empty CSV")
	}
	cols, err := csv.NewReader(strings.NewReader(headerLine)).Read()
	if err != nil || len(cols) == 0 {
		return fmt.Errorf("could not parse CSV header")
	}
	qtable := sqlIdent(table)
	defs := make([]string, len(cols))
	for i, c := range cols {
		defs[i] = fmt.Sprintf("%s text", sqlIdent(c)) // preserve the header names verbatim
	}
	if err := run("docker", "exec", "-e", pgImportOptions, container(target),
		"psql", "-q", "-U", pgUser, "-d", pgDatabase, "-c",
		fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (%s);", qtable, strings.Join(defs, ", "))); err != nil {
		return err
	}
	p.Logf("  loading rows into table %q…\n", table)
	// The header line is already consumed, so COPY the remaining rows (HEADER false).
	return pipeInto(target, br, "psql", "-q", "-U", pgUser, "-d", pgDatabase, "-c",
		fmt.Sprintf(`\copy %s FROM STDIN WITH (FORMAT csv, HEADER false)`, qtable))
}

// loadJSON loads a stream of JSON documents (a JSON array or NDJSON, e.g. from a
// MongoDB collection) into a RELATIONAL table: the documents land in a jsonb
// staging table, then their top-level keys are turned into typed columns
// (scalars → text/numeric/boolean, `_id` unwrapped from {$oid}, nested
// objects/arrays kept as jsonb). Documents that aren't JSON objects fall back to
// a single jsonb column.
func loadJSON(p *Progress, target string, r io.Reader, table string) error {
	stage := table + "__key_stage"
	qstage, qtable := sqlIdent(stage), sqlIdent(table)
	if err := psqlExec(target, fmt.Sprintf(
		`DROP TABLE IF EXISTS %s; CREATE TABLE %s (id bigserial PRIMARY KEY, doc jsonb);`, qstage, qstage)); err != nil {
		return err
	}
	br := bufio.NewReader(r)
	first, err := peekNonSpace(br)
	if err != nil {
		// An empty source (e.g. an empty MongoDB collection) is not an error: leave
		// an empty table behind (a single jsonb column, since there are no keys to
		// infer columns from) and move on.
		p.Logf("  (empty — 0 rows)\n")
		return psqlExec(target, fmt.Sprintf(`DROP TABLE IF EXISTS %s; CREATE TABLE %s (doc jsonb);`, qstage, qtable))
	}
	pr, pw := io.Pipe()
	streamErr := make(chan error, 1)
	go func() {
		defer pw.Close()
		w := bufio.NewWriter(pw)
		fmt.Fprintln(w, "BEGIN;")
		err := streamJSONDocs(br, first, func(raw string) error {
			_, werr := fmt.Fprintf(w, `INSERT INTO %s(doc) VALUES ('%s'::jsonb);`+"\n", qstage, strings.ReplaceAll(raw, "'", "''"))
			return werr
		})
		if err != nil {
			fmt.Fprintln(w, "ROLLBACK;") // an invalid document: nothing from this source is kept
		} else {
			fmt.Fprintln(w, "COMMIT;")
		}
		w.Flush()
		streamErr <- err
	}()
	p.Logf("  loading documents…\n")
	runErr := pipeInto(target, pr, "psql", "-q", "-U", pgUser, "-d", pgDatabase, "-v", "ON_ERROR_STOP=1")
	pr.Close() // if psql stopped early, the writer's next write fails instead of blocking
	sErr := <-streamErr
	if runErr != nil {
		return runErr
	}
	if sErr != nil {
		return sErr
	}
	return relationalizeJSON(p, target, stage, table)
}

// streamJSONDocs reads a JSON array or newline-delimited JSON from br (first is
// its first non-space byte) and passes each document to emit. An invalid document
// is an error naming its position, so a bad file never imports partially.
func streamJSONDocs(br *bufio.Reader, first byte, emit func(string) error) error {
	if first == '[' { // a JSON array
		dec := json.NewDecoder(br)
		if _, err := dec.Token(); err != nil { // consume '['
			return fmt.Errorf("reading the JSON array: %v", err)
		}
		n := 0
		for dec.More() {
			n++
			var m json.RawMessage
			if err := dec.Decode(&m); err != nil {
				return fmt.Errorf("JSON array element %d is not valid JSON: %v", n, err)
			}
			if err := emit(string(m)); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil { // consume ']'
			return fmt.Errorf("the JSON array isn't closed after element %d: %v", n, err)
		}
		return nil
	}
	// newline-delimited JSON (e.g. mongoexport)
	sc := bufio.NewScanner(br)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		if !json.Valid([]byte(raw)) {
			return fmt.Errorf("line %d is not valid JSON", line)
		}
		if err := emit(raw); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("reading line %d: %v", line+1, err)
	}
	return nil
}

// psqlExec runs a (possibly multi-statement) SQL string on an instance. The first
// -c quiets routine NOTICEs (e.g. "table … does not exist, skipping" from a
// defensive DROP IF EXISTS); both -c options share the one psql session.
func psqlExec(target, sql string) error {
	return run("docker", "exec", "-e", pgImportOptions, container(target),
		"psql", "-q", "-U", pgUser, "-d", pgDatabase, "-v", "ON_ERROR_STOP=1",
		"-c", "SET client_min_messages=warning;", "-c", sql)
}

// relationalizeJSON turns the jsonb documents in `stage` into a typed relational
// table `table`: each top-level document key becomes a column, its Postgres type
// inferred from the JSON types seen across the collection.
func relationalizeJSON(p *Progress, target, stage, table string) error {
	qstage, qtable := sqlIdent(stage), sqlIdent(table)
	// Discover top-level keys and the JSON types each takes (chr(9) = a real tab
	// separator, robust to keys containing punctuation). Only object docs have keys.
	q := fmt.Sprintf(`SELECT e.key || chr(9) || coalesce(jsonb_typeof(e.value),'null') `+
		`FROM %s s, LATERAL jsonb_each(s.doc) e WHERE jsonb_typeof(s.doc)='object' GROUP BY 1`, qstage)
	out, err := capture("docker", "exec", container(target),
		"psql", "-U", pgUser, "-d", pgDatabase, "-tAc", q)
	if err != nil {
		return fmt.Errorf("inspect documents: %w", err)
	}
	kinds := map[string]map[string]bool{}
	var keys []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) < 2 {
			continue
		}
		k, t := parts[0], parts[1]
		if kinds[k] == nil {
			kinds[k] = map[string]bool{}
			keys = append(keys, k)
		}
		kinds[k][t] = true
	}
	if len(keys) == 0 {
		// The documents aren't JSON objects — keep them as a single jsonb column.
		p.Logf("  documents are not JSON objects — keeping a single jsonb column\n")
		return psqlExec(target, fmt.Sprintf(`DROP TABLE IF EXISTS %s; ALTER TABLE %s RENAME TO %s;`, qtable, qstage, qtable))
	}
	sort.Strings(keys)
	// Put _id first for readability.
	ordered := keys
	if kinds["_id"] != nil {
		ordered = []string{"_id"}
		for _, k := range keys {
			if k != "_id" {
				ordered = append(ordered, k)
			}
		}
	}
	// Column names are the source keys VERBATIM (quoted, case-preserving) — the
	// migration must not alter the source schema.
	var defs, sel, names []string
	for _, k := range ordered {
		qcol := sqlIdent(k)
		typ, expr := jsonColumn(k, kinds[k])
		defs = append(defs, qcol+" "+typ)
		sel = append(sel, expr+" AS "+qcol)
		names = append(names, k)
	}
	p.Logf("  relationalizing → %d column(s): %s\n", len(names), strings.Join(names, ", "))
	ddl := fmt.Sprintf(`DROP TABLE IF EXISTS %s; CREATE TABLE %s (%s); `+
		`INSERT INTO %s SELECT %s FROM %s WHERE jsonb_typeof(doc)='object'; DROP TABLE %s;`,
		qtable, qtable, strings.Join(defs, ", "), qtable, strings.Join(sel, ", "), qstage, qstage)
	return psqlExec(target, ddl)
}

// jsonColumn maps a document key (given the set of JSON types its values take) to
// a Postgres column type and the SELECT expression that extracts it from `doc`.
func jsonColumn(key string, kinds map[string]bool) (pgType, expr string) {
	kq := strings.ReplaceAll(key, "'", "''")
	if key == "_id" { // MongoDB's id: unwrap {$oid}, else take it as text
		return "text", fmt.Sprintf("coalesce(doc->'%s'->>'$oid', doc->>'%s')", kq, kq)
	}
	var ts []string
	for t := range kinds {
		if t != "null" {
			ts = append(ts, t)
		}
	}
	if len(ts) == 1 {
		switch ts[0] {
		case "string":
			return "text", fmt.Sprintf("doc->>'%s'", kq)
		case "number":
			return "numeric", fmt.Sprintf("(doc->>'%s')::numeric", kq)
		case "boolean":
			return "boolean", fmt.Sprintf("(doc->>'%s')::boolean", kq)
		}
	}
	if len(ts) == 0 { // all null
		return "text", fmt.Sprintf("doc->>'%s'", kq)
	}
	// nested object/array, or mixed types → keep the raw JSON value
	return "jsonb", fmt.Sprintf("doc->'%s'", kq)
}

// pipeInto streams r into a command run inside the target's container.
func pipeInto(target string, r io.Reader, argv ...string) error {
	full := append([]string{"exec", "-i", "-e", pgImportOptions, container(target)}, argv...)
	cmd := exec.Command("sudo", append([]string{"docker"}, full...)...)
	cmd.Stdin = r
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// --- small helpers ---

func peekNonSpace(br *bufio.Reader) (byte, error) {
	for {
		b, err := br.Peek(1)
		if err != nil {
			return 0, err
		}
		switch b[0] {
		case ' ', '\n', '\r', '\t':
			_, _ = br.ReadByte()
		default:
			return b[0], nil
		}
	}
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// sqlQuote renders s as a single-quoted SQL string literal.
func sqlQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// pgIdent renders s as a double-quoted SQL identifier (matching mysqldump's ANSI
// quoting so the generated schema and the dumped INSERTs agree on names).
func pgIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// sqlIdent renders a SOURCE name (a MongoDB key, a collection, a CSV header) as a
// quoted, case-preserving Postgres identifier — the migration must not alter the
// source schema, so unlike sanitizeIdent it keeps the exact case and punctuation,
// enforcing only Postgres's 63-byte identifier limit. (Instance/dataset/container
// names still use sanitizeIdent, which must be filesystem/docker-safe.)
func sqlIdent(s string) string {
	if len(s) > 63 {
		s = s[:63]
	}
	if s == "" {
		s = "col"
	}
	return pgIdent(s)
}

func sanitizeIdent(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	// Trim only trailing underscores (artifacts of sanitizing punctuation); a
	// leading underscore is a valid Postgres identifier and meaningful (e.g. _id).
	out := strings.TrimRight(b.String(), "_")
	if out == "" || (out[0] >= '0' && out[0] <= '9') {
		out = "t_" + out
	}
	if len(out) > 63 {
		out = out[:63]
	}
	return out
}
