// SPDX-License-Identifier: AGPL-3.0-or-later

// Package controlplane serves FoxByte's management REST API (JSON only),
// gated by internal/auth. The web UI is a separate app (see web/).
package controlplane

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/daemon"
	"github.com/thefoxbyte/foxbyte/internal/secrets"
	"github.com/thefoxbyte/foxbyte/internal/tlsutil"
	"github.com/thefoxbyte/foxbyte/web"
)

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)

// ruleIDRe matches a Blackbox policy rule id (bb.policy_rules.rule_id).
var ruleIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// openapiSpec is the canonical API description, served at GET /api/openapi.yaml
// so any client generator can consume it.
//
//go:embed openapi.yaml
var openapiSpec []byte

// Serve starts the control-plane REST API on addr (e.g. ":8080").
func Serve(addr string) error {
	store, err := auth.OpenFromEnv()
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	store.MountPublic(mux) // /auth/* (register, login, logout, me, providers, oauth)

	// The API description, public so client generators can fetch it. More
	// specific than the "/api/" auth gate below, so it wins and stays open.
	mux.HandleFunc("GET /api/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(openapiSpec)
	})

	api := http.NewServeMux()
	registerAPI(api)
	registerPipelines(api, store)                        // /api/pipelines* (ETL)
	registerImpact(api)                                  // /api/branches/{name}/impact, /api/{ledger,blackbox}/diff
	registerPolicy(api, store)                           // /api/branches/{name}/policies* and /admins (Blackbox policy gate)
	registerLedgerV2(api)                                // /api/branches/{name}/ledger/{integrity,checkpoint,export,entries,{id}/branch}
	store.MountKeys(api)                                 // /api/keys (protected via Authn below)
	mux.Handle("/api/", store.Authn(blackboxAlias(api))) // …/blackbox… also reaches …/ledger… routes

	// Blackbox 2.0: anchor new ledger entries outside the database on a schedule.
	branch.StartCheckpointer()

	handler := cors(store.WebOrigin())(logging(mux))

	// TLS when a certificate is available (self-signed on first run, or a real
	// one via FOX_TLS_CERT/KEY), so API keys and session tokens are never
	// sent in cleartext. Falls back to HTTP only if the cert can't be loaded.
	scheme := "https"
	cert, key, tlsErr := tlsutil.EnsureCert()
	if tlsErr != nil {
		scheme = "http"
		log.Printf("control-plane TLS disabled (%v) — serving plain HTTP", tlsErr)
	}

	if ui := web.FS(); ui != nil {
		serveUI(mux, ui)
		log.Printf("web UI served at %s://localhost%s/", scheme, addr)
	}

	log.Printf("control-plane API on %s://localhost%s (auth on; UI origin %s)", scheme, addr, store.WebOrigin())
	if tlsErr != nil {
		return http.ListenAndServe(addr, handler)
	}
	return http.ListenAndServeTLS(addr, cert, key, handler)
}

func registerAPI(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		bs, err := branch.Branches()
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		var nBranch, nAgent int
		mainReady := false
		for _, b := range bs {
			switch {
			case b.Primary:
				mainReady = b.State == "running"
			case b.Agent:
				nAgent++
			default:
				nBranch++
			}
		}
		writeJSON(w, 200, map[string]any{
			"mainReady": mainReady,
			"branches":  nBranch,
			"agents":    nAgent,
			"ha":        branch.HAInfo(),
			"storage":   branch.StorageInfo(),
			"servers": map[string]bool{
				"gateway": daemon.Alive("gateway"),
				"api":     daemon.Alive("api"),
			},
		})
	})

	mux.HandleFunc("GET /api/branches", func(w http.ResponseWriter, r *http.Request) {
		bs, err := branch.Branches()
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		if bs == nil {
			bs = []branch.BranchInfo{}
		}
		writeJSON(w, 200, bs)
	})

	mux.HandleFunc("POST /api/branches", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name string `json:"name"`
			From string `json:"from"` // the branch to copy; default main
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if !nameRe.MatchString(body.Name) {
			writeErr(w, 400, fmt.Errorf("invalid name (use lowercase letters, digits, dashes)"))
			return
		}
		if body.From != "" && !nameRe.MatchString(body.From) {
			writeErr(w, 400, fmt.Errorf("invalid from: %q is not a branch name", body.From))
			return
		}
		if err := branch.Create(body.Name, body.From); err != nil {
			code := 409
			if errors.Is(err, branch.ErrParentNotFound) {
				code = 404
			}
			writeErr(w, code, err)
			return
		}
		from := body.From
		if from == "" {
			from = "main"
		}
		writeJSON(w, 201, map[string]string{"name": body.Name, "from": from, "status": "created"})
	})

	mux.HandleFunc("DELETE /api/branches/{name}", func(w http.ResponseWriter, r *http.Request) {
		if err := branch.Delete(r.PathValue("name")); err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	})

	mux.HandleFunc("POST /api/branches/{name}/suspend", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if name == "main" {
			writeErr(w, 400, fmt.Errorf("refusing to suspend the primary 'main'"))
			return
		}
		if err := branch.Suspend(name); err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, map[string]string{"status": "suspended"})
	})

	mux.HandleFunc("POST /api/branches/{name}/resume", func(w http.ResponseWriter, r *http.Request) {
		if err := branch.Wake(r.PathValue("name")); err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, map[string]string{"status": "resumed"})
	})

	// Run SQL against a branch (powers the web SQL console).
	mux.HandleFunc("POST /api/branches/{name}/query", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		var body struct {
			SQL string `json:"sql"`
			// AllowDestructive applies SET bb.allow_destructive=on to this one
			// query. The guardrail still decides whether it counts.
			AllowDestructive bool `json:"allow_destructive"`
			// AllowRules applies SET bb.policy_allow to this one query: the
			// per-rule override for a Blackbox policy block (BBX01), which
			// allow_destructive does not cover. Also honoured only for admins.
			AllowRules []string `json:"allow_rules"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if strings.TrimSpace(body.SQL) == "" {
			writeErr(w, 400, fmt.Errorf("sql is required"))
			return
		}
		addr, err := branch.EnsureRunning(name)
		if err != nil {
			writeErr(w, 404, err)
			return
		}
		u, _ := auth.UserFrom(r.Context())
		for _, id := range body.AllowRules {
			if !ruleIDRe.MatchString(id) {
				writeErr(w, 400, fmt.Errorf("allow_rules: %q is not a rule id", id))
				return
			}
		}
		writeJSON(w, 200, runQuery(addr, body.SQL, queryAs{Branch: name, Actor: u.Email, AllowDestructive: body.AllowDestructive, AllowRules: body.AllowRules}))
	})

	// Migration: import a source database into a new instance from a connection
	// string. The web wizard accepts a URL source (no arbitrary server file paths
	// from a browser); file imports (.sql/.csv/.json) go through /api/import/file.
	mux.HandleFunc("POST /api/import", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Source     string `json:"source"`
			Target     string `json:"target"`
			Continuous bool   `json:"continuous"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		body.Source = strings.TrimSpace(body.Source)
		send, p, ok := newSSE(w)
		if !ok {
			writeErr(w, 500, fmt.Errorf("streaming is not supported by this server"))
			return
		}
		if !isConnString(body.Source) {
			send("error", map[string]string{"message": "web import needs a connection string (postgres://, mysql://, mariadb://, mongodb://); use the file panel for .sql/.csv/.json"})
			return
		}
		status, target, err := "imported", "", error(nil)
		if body.Continuous {
			status = "replicating"
			target, err = branch.ImportContinuousTo(p, body.Source, strings.TrimSpace(body.Target))
		} else {
			target, err = branch.ImportTo(p, body.Source, strings.TrimSpace(body.Target))
		}
		if err != nil {
			send("error", map[string]string{"message": err.Error()})
			return
		}
		send("done", map[string]any{"status": status, "target": target, "tables": branch.TableCount(target)})
	})

	// Base backups in object storage: what a point-in-time restore can start
	// from. Read-only -- a restore itself is `fox restore --to`, which needs a
	// port on the host and leaves a disposable container behind.
	mux.HandleFunc("GET /api/backups", func(w http.ResponseWriter, r *http.Request) {
		list, err := branch.Backups()
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, list)
	})

	// Continuous imports (logical replication into a branch): where each stands,
	// and the cutover that turns one into a standalone branch.
	mux.HandleFunc("GET /api/replication", func(w http.ResponseWriter, r *http.Request) {
		list, err := branch.Replicating()
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, list)
	})
	mux.HandleFunc("GET /api/branches/{name}/replication", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if _, err := branch.EnsureRunning(name); err != nil {
			writeErr(w, 404, err)
			return
		}
		rep, err := branch.ReplicationStatus(name)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, rep)
	})
	mux.HandleFunc("POST /api/branches/{name}/replication/cutover", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if _, err := branch.EnsureRunning(name); err != nil {
			writeErr(w, 404, err)
			return
		}
		tables, err := branch.CutoverReplication(name)
		if err != nil {
			code := 500
			if errors.Is(err, branch.ErrNotReplicating) {
				code = 409
			}
			writeErr(w, code, err)
			return
		}
		writeJSON(w, 200, map[string]any{"branch": name, "status": "standalone", "tables": tables})
	})

	// Migration via file upload: a .sql/.csv/.json file streamed from the browser
	// into a new instance (kind inferred from the filename). Progress streams as SSE.
	mux.HandleFunc("POST /api/import/file", func(w http.ResponseWriter, r *http.Request) {
		file, hdr, ferr := r.FormFile("file")
		send, p, ok := newSSE(w)
		if !ok {
			writeErr(w, 500, fmt.Errorf("streaming is not supported by this server"))
			return
		}
		if ferr != nil {
			send("error", map[string]string{"message": "a file is required"})
			return
		}
		defer file.Close()
		kind, err := branch.ParseKind(filepath.Ext(hdr.Filename))
		if err != nil {
			send("error", map[string]string{"message": err.Error()})
			return
		}
		target, err := branch.ImportReaderTo(p, file, kind, hdr.Filename, strings.TrimSpace(r.FormValue("target")))
		if err != nil {
			send("error", map[string]string{"message": err.Error()})
			return
		}
		send("done", map[string]any{"status": "imported", "target": target, "tables": branch.TableCount(target)})
	})

	// Blackbox (RECORD layer): the queryable history of DDL changes on a
	// branch, filterable by actor/table/risk/status/kind/time.
	mux.HandleFunc("GET /api/branches/{name}/ledger", func(w http.ResponseWriter, r *http.Request) {
		addr, err := branch.EnsureRunning(r.PathValue("name"))
		if err != nil {
			writeErr(w, 404, err)
			return
		}
		writeJSON(w, 200, runQuery(addr, ledgerSQL(r.URL.Query()), queryAs{}))
	})

	// Tamper-evidence: recompute the ledger's hash chain and report whether it
	// is intact (columns: legacy, chained, broken, first_broken).
	mux.HandleFunc("GET /api/branches/{name}/ledger/verify", func(w http.ResponseWriter, r *http.Request) {
		addr, err := branch.EnsureRunning(r.PathValue("name"))
		if err != nil {
			writeErr(w, 404, err)
			return
		}
		writeJSON(w, 200, runQuery(addr, branch.LedgerVerifySQL, queryAs{}))
	})
}

func sqlEsc(s string) string { return strings.ReplaceAll(s, "'", "''") }

// ledgerSQL builds a filtered, bounded query over bb.schema_ledger. Filter
// values are single-quote-escaped and only ever appear as string literals.
func ledgerSQL(q url.Values) string {
	where := []string{"true"}
	like := func(col, v string) {
		if v = strings.TrimSpace(v); v != "" {
			where = append(where, fmt.Sprintf("%s ILIKE '%%%s%%'", col, sqlEsc(v)))
		}
	}
	eq := func(col, v string) {
		if v = strings.TrimSpace(v); v != "" {
			where = append(where, fmt.Sprintf("%s = '%s'", col, sqlEsc(v)))
		}
	}
	like("actor", q.Get("actor"))
	like("object_identity", q.Get("table"))
	eq("risk", q.Get("risk"))
	eq("status", q.Get("status"))
	eq("actor_kind", q.Get("kind"))
	if v := strings.TrimSpace(q.Get("since")); v != "" {
		where = append(where, fmt.Sprintf("at >= '%s'", sqlEsc(v)))
	}
	if v := strings.TrimSpace(q.Get("until")); v != "" {
		where = append(where, fmt.Sprintf("at <= '%s'", sqlEsc(v)))
	}
	limit := 200
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 && n <= 2000 {
		limit = n
	}
	offset := 0
	if n, err := strconv.Atoi(q.Get("offset")); err == nil && n > 0 {
		offset = n
	}
	// Extra columns are opt-in (with=session), so the default response keeps
	// exactly the columns clients were built against.
	extra := ""
	for _, w := range strings.Split(q.Get("with"), ",") {
		if strings.TrimSpace(w) == "session" {
			extra = ", session"
		}
	}
	return fmt.Sprintf(`SELECT to_char(at,'YYYY-MM-DD HH24:MI:SS') AS at, actor, actor_kind, tool,
		branch, command_tag, object_identity, statement, status, risk%s
		FROM bb.schema_ledger WHERE %s ORDER BY at DESC LIMIT %d OFFSET %d`,
		extra, strings.Join(where, " AND "), limit, offset)
}

// queryAs says whose session a query runs in.
type queryAs struct {
	// Branch and Actor identify the signed-in user. When set, the query logs in
	// as that user's own role, as the Gateway does, so the guardrail knows who is
	// asking and the Blackbox records the real login. Empty for the engine's own
	// reads, which run as the shared client role.
	Branch, Actor string
	// AllowDestructive applies SET bb.allow_destructive=on to this query's
	// session. It is honoured only for superusers and members of db_admin.
	AllowDestructive bool
	// AllowRules applies SET bb.policy_allow (comma-separated rule ids) to this
	// query's session: the override for policy rules, which allow_destructive
	// does not cover. Also honoured only for superusers and db_admin members.
	AllowRules []string
}

// runQuery executes SQL against a branch backend and returns columns/rows (or an
// error message the console can render). Capped and time-bounded.
func runQuery(addr, sql string, as queryAs) map[string]any {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg, err := pgx.ParseConfig(fmt.Sprintf("postgres://%s/%s", addr, branch.Database))
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	// The non-superuser client role, so the web console is bound by the same
	// rules as any other client (RLS, and the append-only ledger).
	cfg.User, cfg.Password = branch.ClientRole, secrets.Load().PGPassword
	if as.Actor != "" && as.Branch != "" {
		// The signed-in user's own role: a member of db_client that acts as
		// db_client, so data access and object ownership are unchanged, but
		// session_user is the user. Every console session used to be db_client,
		// which is never in db_admin — so no one, not even an admin, could
		// override the guardrail from the console.
		if err := branch.EnsureUserRole(as.Branch, as.Actor); err != nil {
			log.Printf("console: per-user role %q on %s: %v (using db_client)", as.Actor, as.Branch, err)
		} else {
			cfg.User = as.Actor
		}
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	defer conn.Close(ctx)

	// Attribute console DDL in the Blackbox to the signed-in user — our own
	// tool should not be the blind spot. The engine's reads skip this.
	if as.Actor != "" {
		if _, err := conn.Exec(ctx,
			"SELECT set_config('bb.actor',$1,false), set_config('bb.actor_kind','human',false), set_config('application_name','console',false)",
			as.Actor); err != nil {
			return map[string]any{"error": err.Error()}
		}
	}
	// Each console run is its own connection, so a SET typed in one run is gone
	// by the next; the override has to travel with the query it is meant for.
	if len(as.AllowRules) > 0 {
		if _, err := conn.Exec(ctx, "SELECT set_config('bb.policy_allow',$1,false)", strings.Join(as.AllowRules, ",")); err != nil {
			return map[string]any{"error": err.Error()}
		}
	}
	if as.AllowDestructive {
		if _, err := conn.Exec(ctx, "SELECT set_config('bb.allow_destructive','on',false)"); err != nil {
			return map[string]any{"error": err.Error()}
		}
	}

	rows, err := conn.Query(ctx, sql)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	defer rows.Close()

	fds := rows.FieldDescriptions()
	cols := make([]string, len(fds))
	for i, f := range fds {
		cols[i] = f.Name
	}
	out := [][]any{}
	for rows.Next() {
		if len(out) >= 1000 {
			break
		}
		vals, err := rows.Values()
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		row := make([]any, len(vals))
		for i, v := range vals {
			row[i] = cell(v, fds[i].DataTypeOID, conn.TypeMap())
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return map[string]any{"error": err.Error()}
	}
	return map[string]any{"columns": cols, "rows": out, "command": rows.CommandTag().String()}
}

// cell renders one result value for the console.
//
// pgx decodes each column into the Go type that fits it, and for several types
// that is a byte array or a struct with no useful JSON form. A uuid decodes to
// [16]byte, so it used to reach the console as "[195,64,152,78,…]" — 16 numbers
// where the user expects c340984e-87bf-4006-a013-72aca6fc7d77. An interval
// became {"Microseconds":7200000000,"Days":1,…}, an inet carried its quotes,
// and bytea was mangled into whatever its bytes looked like as text. For those,
// Postgres's own text form — what psql would print — is both correct and what
// someone reading a table wants, and pgx can produce it for any type it knows
// (pgText). Values that already render well are left exactly as they were.
func cell(v any, oid uint32, m *pgtype.Map) any {
	switch t := v.(type) {
	case nil, bool, string, int16, int32, int64, float32, float64:
		return v
	case time.Time:
		return t.Format(time.RFC3339Nano)
	case [16]byte:
		// uuid.
		if s, ok := pgText(m, oid, v); ok {
			return s
		}
		return fmt.Sprintf("%x", t)
	case []byte:
		// bytea, which Postgres writes as \x0102; string(t) would hand the browser
		// raw bytes. Only for a real bytea column: pgx also returns []byte for a
		// type it has no codec for — a custom enum or domain arrives as the bytes
		// of its text form — and hex would make those unreadable.
		if oid == pgtype.ByteaOID {
			if s, ok := pgText(m, oid, v); ok {
				return s
			}
		}
		return string(t)
	case []any:
		// An array column (pgx decodes every array to []any). Its elements can be
		// any of the above — a uuid[] would otherwise be a list of lists of
		// numbers — so each is rendered on its own, by the element's own type.
		elem := elementOID(m, oid)
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = cell(e, elem, m)
		}
		return jsonText(out)
	case map[string]any:
		// jsonb/json objects: real JSON, readable and copy-pasteable.
		return jsonText(v)
	}
	// pgtype's own types that define a JSON form (numeric, point, …) keep it.
	if _, ok := v.(json.Marshaler); ok {
		return jsonText(v)
	}
	// Everything else — interval, time of day, bits, inet, macaddr, the geometric
	// types, ranges, hstore — as Postgres writes it.
	if s, ok := pgText(m, oid, v); ok {
		return s
	}
	return jsonText(v)
}

// pgText asks pgx for Postgres's text representation of a decoded value. It
// fails (ok false) when the type map has no encoder for that OID, in which case
// the caller keeps whatever it did before.
func pgText(m *pgtype.Map, oid uint32, v any) (string, bool) {
	if m == nil || oid == 0 {
		return "", false
	}
	b, err := m.Encode(oid, pgtype.TextFormatCode, v, nil)
	if err != nil || b == nil {
		return "", false
	}
	return string(b), true
}

// elementOID is the element type of an array type, so array members can be
// rendered by their own type. 0 when oid is not a known array type.
func elementOID(m *pgtype.Map, oid uint32) uint32 {
	if m == nil {
		return 0
	}
	t, ok := m.TypeForOID(oid)
	if !ok {
		return 0
	}
	if ac, ok := t.Codec.(*pgtype.ArrayCodec); ok && ac.ElementType != nil {
		return ac.ElementType.OID
	}
	return 0
}

// jsonText renders a value as JSON, falling back to %v (which is what the
// console showed before there was anything better).
func jsonText(v any) any {
	if b, err := json.Marshal(v); err == nil {
		return string(b)
	}
	return fmt.Sprintf("%v", v)
}

// cors echoes the specific UI origin and allows credentials (cookies), which
// forbids the "*" wildcard.
func cors(origin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", allowOrigin(origin, r.Header.Get("Origin")))
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// allowOrigin echoes the request Origin when it is the configured UI origin or
// any localhost origin (so localhost vs 127.0.0.1 and alternate dev ports all
// work with credentialed CORS); otherwise it falls back to the configured one.
func allowOrigin(configured, reqOrigin string) string {
	if reqOrigin != "" && (reqOrigin == configured || isLocalhostOrigin(reqOrigin)) {
		return reqOrigin
	}
	return configured
}

func isLocalhostOrigin(o string) bool {
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// registerPipelines mounts the ETL pipeline CRUD + run endpoints. All are behind
// Authn and scoped to the calling user.
func registerPipelines(mux *http.ServeMux, store *auth.Store) {
	mux.HandleFunc("GET /api/pipelines", func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFrom(r.Context())
		ps, err := store.ListPipelines(u.ID)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, map[string]any{"pipelines": ps})
	})
	mux.HandleFunc("POST /api/pipelines", func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFrom(r.Context())
		name, spec, err := decodePipelineBody(r)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		p, err := store.CreatePipeline(u.ID, name, spec)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, p)
	})
	mux.HandleFunc("GET /api/pipelines/{id}", func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFrom(r.Context())
		p, ok := store.GetPipeline(r.PathValue("id"), u.ID)
		if !ok {
			writeErr(w, 404, fmt.Errorf("pipeline not found"))
			return
		}
		writeJSON(w, 200, p)
	})
	mux.HandleFunc("PUT /api/pipelines/{id}", func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFrom(r.Context())
		name, spec, err := decodePipelineBody(r)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		if err := store.UpdatePipeline(r.PathValue("id"), u.ID, name, spec); err != nil {
			writeErr(w, 404, err)
			return
		}
		writeJSON(w, 200, map[string]string{"status": "updated"})
	})
	mux.HandleFunc("DELETE /api/pipelines/{id}", func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFrom(r.Context())
		if err := store.DeletePipeline(r.PathValue("id"), u.ID); err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	})
	mux.HandleFunc("GET /api/pipelines/{id}/runs", func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFrom(r.Context())
		runs, err := store.ListRuns(r.PathValue("id"), u.ID)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, map[string]any{"runs": runs})
	})
	// Run a pipeline, streaming its log/progress as SSE (same contract as import).
	mux.HandleFunc("POST /api/pipelines/{id}/run", func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFrom(r.Context())
		pl, ok := store.GetPipeline(r.PathValue("id"), u.ID)
		send, _, sok := newSSE(w)
		if !sok {
			writeErr(w, 500, fmt.Errorf("streaming is not supported by this server"))
			return
		}
		if !ok {
			send("error", map[string]string{"message": "pipeline not found"})
			return
		}
		var spec branch.PipelineSpec
		if err := json.Unmarshal([]byte(pl.Spec), &spec); err != nil {
			send("error", map[string]string{"message": "invalid pipeline spec: " + err.Error()})
			return
		}
		target := pipelineBranch(pl)
		// Stream the log to the client AND capture it for the run record.
		var logBuf strings.Builder
		p := &branch.Progress{
			Log: writeFunc(func(b []byte) (int, error) {
				logBuf.Write(b)
				for _, line := range strings.Split(string(b), "\n") {
					if line != "" {
						send("log", map[string]string{"line": line})
					}
				}
				return len(b), nil
			}),
			Step: func(done, total int, label string) {
				send("progress", map[string]any{"done": done, "total": total, "label": label})
			},
		}
		runID, _ := store.StartRun(pl.ID, u.ID)
		res, err := branch.RunPipeline(p, spec, target)
		if err != nil {
			_ = store.FinishRun(runID, "error", 0, "[]", logBuf.String())
			send("error", map[string]string{"message": err.Error()})
			return
		}
		status := "success"
		if res.Failed {
			status = "failed"
		}
		testsJSON, _ := json.Marshal(res.Tests)
		_ = store.FinishRun(runID, status, res.Tables, string(testsJSON), logBuf.String())
		send("done", map[string]any{
			"status": status, "target": target, "tables": res.Tables,
			"tests": res.Tests, "failed": res.Failed,
		})
	})
}

// decodePipelineBody reads a {name, spec} body and validates the spec.
func decodePipelineBody(r *http.Request) (name, spec string, err error) {
	var body struct {
		Name string          `json:"name"`
		Spec json.RawMessage `json:"spec"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	name = strings.TrimSpace(body.Name)
	if name == "" {
		return "", "", fmt.Errorf("a pipeline name is required")
	}
	if len(body.Spec) == 0 {
		return "", "", fmt.Errorf("a pipeline spec is required")
	}
	var ps branch.PipelineSpec
	if err := json.Unmarshal(body.Spec, &ps); err != nil {
		return "", "", fmt.Errorf("invalid spec: %w", err)
	}
	if strings.TrimSpace(ps.Source) == "" {
		return "", "", fmt.Errorf("the pipeline spec needs a source connection string")
	}
	return name, string(body.Spec), nil
}

// pipelineBranch derives a stable, connectable instance name for a pipeline's runs.
func pipelineBranch(p auth.Pipeline) string {
	var b strings.Builder
	for _, r := range strings.ToLower(p.Name) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	name := strings.Trim(b.String(), "-")
	if name == "" || name[0] < 'a' || name[0] > 'z' {
		name = "pl-" + p.ID
	}
	if len(name) > 40 {
		name = strings.Trim(name[:40], "-")
	}
	return name
}

// serveUI serves the embedded single-page app on "/" (more specific /api/ and
// /auth/ patterns take precedence). Real assets are served from the build; any
// other path falls back to index.html so client-side routes work on refresh.
func serveUI(mux *http.ServeMux, ui fs.FS) {
	fsrv := http.FileServer(http.FS(ui))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p != "" {
			if _, err := fs.Stat(ui, p); err == nil {
				fsrv.ServeHTTP(w, r) // a real asset (JS/CSS/favicon/…)
				return
			}
		}
		b, err := fs.ReadFile(ui, "index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

// writeFunc adapts a function into an io.Writer.
type writeFunc func([]byte) (int, error)

func (f writeFunc) Write(b []byte) (int, error) { return f(b) }

// newSSE turns w into a Server-Sent Events stream and returns a `send(event,data)`
// emitter plus a branch.Progress that streams the engine's log lines (as `log`
// events) and item-level steps (as `progress` events). ok is false if the server
// can't stream (no http.Flusher).
func newSSE(w http.ResponseWriter) (send func(string, any), p *branch.Progress, ok bool) {
	fl, ok := w.(http.Flusher)
	if !ok {
		return nil, nil, false
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no") // don't let a proxy buffer the stream
	w.WriteHeader(http.StatusOK)
	send = func(event string, data any) {
		b, _ := json.Marshal(data)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
		fl.Flush()
	}
	p = &branch.Progress{
		Log: writeFunc(func(b []byte) (int, error) {
			for _, line := range strings.Split(string(b), "\n") {
				if line != "" {
					send("log", map[string]string{"line": line})
				}
			}
			return len(b), nil
		}),
		Step: func(done, total int, label string) {
			send("progress", map[string]any{"done": done, "total": total, "label": label})
		},
	}
	return send, p, true
}

// isConnString reports whether s is a database connection URL the import engine
// understands (as opposed to a file path, which the browser must not send).
func isConnString(s string) bool {
	for _, scheme := range []string{"postgres://", "postgresql://", "mysql://", "mariadb://", "mongodb://", "mongodb+srv://"} {
		if strings.HasPrefix(s, scheme) {
			return true
		}
	}
	return false
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		if r.URL.Path != "/api/status" && r.URL.Path != "/api/branches" {
			log.Printf("%s %s (%s)", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
		}
	})
}
