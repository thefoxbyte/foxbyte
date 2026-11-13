//go:build enterprise && cgo && linux

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/thefoxbyte/foxbyte/enterprise/vault"
)

// The prototype's tools (design, section 18): what the suite measures the
// service with. They are clients of the service, as the engine will be.

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

type clientFlags struct {
	socket, secretFile, actor *string
}

func addClient(fs *flag.FlagSet) clientFlags {
	return clientFlags{
		socket:     fs.String("socket", "/run/fox-vault/vault.sock", "the service's socket"),
		secretFile: fs.String("secret-file", "/etc/fox-vault/secret/secret", "the per-install secret"),
		actor:      fs.String("actor", "prototype", "who the calls are for"),
	}
}

func (f clientFlags) client() (*vault.Client, error) {
	secret, err := readSecret(*f.secretFile)
	if err != nil {
		return nil, err
	}
	return vault.NewClient(*f.socket, secret, *f.actor), nil
}

// gen prints n distinct synthetic Aadhaar numbers: nobody's, but shaped and
// checked like real ones.
func gen(args []string) error {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	n := fs.Int("n", 1000, "how many")
	_ = fs.Parse(args)
	seen := make(map[string]bool, *n)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for len(seen) < *n {
		v, err := vault.SyntheticAadhaar(randBytes)
		if err != nil {
			return err
		}
		if !seen[v] {
			seen[v] = true
			fmt.Fprintln(w, v)
		}
	}
	return nil
}

func status(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	cf := addClient(fs)
	_ = fs.Parse(args)
	c, err := cf.client()
	if err != nil {
		return err
	}
	st, err := c.Status()
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(st)
}

// bench measures calls a second: one value or reference key a call, c calls
// at once. For detokenise it first tokenises the values it then reads back.
func bench(args []string) error {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	cf := addClient(fs)
	op := fs.String("op", "tokenise", "tokenise, find or detokenise")
	n := fs.Int("n", 2000, "calls")
	conc := fs.Int("c", 8, "calls at once")
	seconds := fs.Int("seconds", 0, "detokenise: keep reading the n values back for this long instead")
	refsOut := fs.String("refs-out", "", "write the reference keys made, one a line")
	_ = fs.Parse(args)
	c, err := cf.client()
	if err != nil {
		return err
	}
	values := make([]string, 0, *n)
	seen := map[string]bool{}
	for len(values) < *n {
		v, err := vault.SyntheticAadhaar(randBytes)
		if err != nil {
			return err
		}
		if !seen[v] {
			seen[v] = true
			values = append(values, v)
		}
	}
	var refs []string
	if *op != "tokenise" {
		// Put them in first, in big calls, untimed.
		for i := 0; i < len(values); i += 1000 {
			j := min(i+1000, len(values))
			resp, _, err := c.Call("tokenise", vault.Request{Kind: "aadhaar", Values: values[i:j]})
			if err != nil {
				return err
			}
			refs = append(refs, resp.Refs...)
		}
	}
	// A signal ends the run early and still prints what was measured, so the
	// suite can read readers it ran in the background.
	var stop atomic.Bool
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; stop.Store(true) }()
	var lat []time.Duration
	var lmu sync.Mutex
	var errs atomic.Int64
	var done atomic.Int64
	var next atomic.Int64
	deadline := time.Time{}
	if *seconds > 0 {
		deadline = time.Now().Add(time.Duration(*seconds) * time.Second)
	}
	start := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < *conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if stop.Load() {
					return
				}
				if deadline.IsZero() && i >= len(values) {
					return
				}
				if !deadline.IsZero() && time.Now().After(deadline) {
					return
				}
				i %= len(values)
				t := time.Now()
				var resp *vault.Response
				var err error
				switch *op {
				case "tokenise":
					resp, _, err = c.Call("tokenise", vault.Request{Kind: "aadhaar", Values: values[i : i+1]})
					if err == nil && resp.Results[0] != vault.ResultDone {
						err = fmt.Errorf("%s", resp.Results[0])
					}
					if err == nil && *refsOut != "" {
						lmu.Lock()
						refs = append(refs, resp.Refs[0])
						lmu.Unlock()
					}
				case "find":
					resp, _, err = c.Call("find", vault.Request{Kind: "aadhaar", Values: values[i : i+1]})
					if err == nil && resp.Refs[0] != refs[i] {
						err = fmt.Errorf("found %q, want %q", resp.Refs[0], refs[i])
					}
				case "detokenise":
					resp, _, err = c.Call("detokenise", vault.Request{Kind: "aadhaar", Refs: refs[i : i+1], Purpose: "prototype benchmark"})
					if err == nil && resp.Values[0] != values[i] {
						err = fmt.Errorf("read back %q (%s)", "…"+lastN(resp.Values[0], 4), resp.Results[0])
					}
				default:
					err = fmt.Errorf("no op %q", *op)
				}
				d := time.Since(t)
				if err != nil {
					if errs.Add(1) <= 3 {
						fmt.Fprintln(os.Stderr, "bench:", err)
					}
				}
				done.Add(1)
				lmu.Lock()
				lat = append(lat, d)
				lmu.Unlock()
			}
		}()
	}
	wg.Wait()
	el := time.Since(start)
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	pct := func(p float64) float64 {
		if len(lat) == 0 {
			return 0
		}
		return float64(lat[int(float64(len(lat)-1)*p)].Microseconds()) / 1000
	}
	fmt.Printf("BENCH op=%s calls=%d c=%d seconds=%.1f calls_per_s=%.0f p50_ms=%.2f p99_ms=%.2f errors=%d\n",
		*op, done.Load(), *conc, el.Seconds(), float64(done.Load())/el.Seconds(), pct(0.5), pct(0.99), errs.Load())
	if *refsOut != "" {
		if err := os.WriteFile(*refsOut, []byte(strings.Join(refs, "\n")+"\n"), 0o600); err != nil {
			return err
		}
	}
	if errs.Load() > 0 {
		return fmt.Errorf("%d calls failed", errs.Load())
	}
	return nil
}

func lastN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// migrate moves a column's values into the vault, on a branch (design,
// section 15): each distinct value is tokenised, then the rows are rewritten
// in batches by key, then the column is read again for any value of the kind
// left.
func migrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	cf := addClient(fs)
	dsn := fs.String("dsn", "", "the branch's database")
	table := fs.String("table", "", "the table")
	column := fs.String("column", "", "the column holding the values")
	keyCol := fs.String("key", "id", "the table's integer primary key")
	kindName := fs.String("kind", "aadhaar", "the values' kind")
	format := fs.String("format", vault.FormatOpaque, "the reference keys' format")
	batch := fs.Int("batch", 1000, "values a tokenise call")
	ubatch := fs.Int("update-batch", 10000, "rows an update")
	_ = fs.Parse(args)
	kind, ok := vault.KindOf(*kindName)
	if !ok {
		return fmt.Errorf("no kind %q", *kindName)
	}
	c, err := cf.client()
	if err != nil {
		return err
	}
	ctx := context.Background()
	db, err := pgx.Connect(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close(ctx)
	t, col, key := pgx.Identifier{*table}.Sanitize(), pgx.Identifier{*column}.Sanitize(), pgx.Identifier{*keyCol}.Sanitize()

	t0 := time.Now()
	rows, err := db.Query(ctx, fmt.Sprintf(`SELECT DISTINCT %s FROM %s WHERE %s IS NOT NULL`, col, t, col))
	if err != nil {
		return err
	}
	var values []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		values = append(values, v)
	}
	rows.Close()
	tRead := time.Since(t0)

	t1 := time.Now()
	mapping := make([][]any, 0, len(values))
	refused := 0
	for i := 0; i < len(values); i += *batch {
		j := min(i+*batch, len(values))
		resp, _, err := c.Call("tokenise", vault.Request{Kind: kind.Name, Values: values[i:j], Format: *format})
		if err != nil {
			return err
		}
		for k, res := range resp.Results {
			if res == vault.ResultDone {
				mapping = append(mapping, []any{values[i+k], resp.Refs[k]})
			} else {
				refused++
			}
		}
	}
	tTok := time.Since(t1)

	// The map of value to reference key is unlogged, so it is never in the
	// WAL, and dropped at the end: the values were in the table already.
	t2 := time.Now()
	if _, err := db.Exec(ctx, `DROP TABLE IF EXISTS fox_vault_map; CREATE UNLOGGED TABLE fox_vault_map (value text PRIMARY KEY, ref text NOT NULL)`); err != nil {
		return err
	}
	if _, err := db.CopyFrom(ctx, pgx.Identifier{"fox_vault_map"}, []string{"value", "ref"}, pgx.CopyFromRows(mapping)); err != nil {
		return err
	}
	var lo, hi int64
	if err := db.QueryRow(ctx, fmt.Sprintf(`SELECT coalesce(min(%s), 0), coalesce(max(%s), -1) FROM %s`, key, key, t)).Scan(&lo, &hi); err != nil {
		return err
	}
	var maxBatch time.Duration
	updated := int64(0)
	for from := lo; from <= hi; from += int64(*ubatch) {
		bt := time.Now()
		tag, err := db.Exec(ctx, fmt.Sprintf(`UPDATE %s AS t SET %s = m.ref FROM fox_vault_map m
			WHERE t.%s = m.value AND t.%s >= $1 AND t.%s < $2`, t, col, col, key, key), from, from+int64(*ubatch))
		if err != nil {
			return err
		}
		updated += tag.RowsAffected()
		maxBatch = max(maxBatch, time.Since(bt))
	}
	if _, err := db.Exec(ctx, `DROP TABLE fox_vault_map`); err != nil {
		return err
	}
	tUpd := time.Since(t2)

	left := 0
	rows, err = db.Query(ctx, fmt.Sprintf(`SELECT %s FROM %s WHERE %s IS NOT NULL`, col, t, col))
	if err != nil {
		return err
	}
	notRef := 0
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		if _, err := kind.Accept(v); err == nil {
			left++
		}
		if !kind.IsRef(v) {
			notRef++
		}
	}
	rows.Close()
	fmt.Printf("MIGRATE distinct=%d refused=%d read_s=%.1f tokenise_s=%.1f values_per_s=%.0f rows_updated=%d update_s=%.1f max_update_batch_ms=%d left=%d not_ref=%d\n",
		len(values), refused, tRead.Seconds(), tTok.Seconds(), float64(len(values))/tTok.Seconds(), updated, tUpd.Seconds(), maxBatch.Milliseconds(), left, notRef)
	return nil
}

// callCmd makes one call and prints the answer as JSON, for the suite's checks:
// fox-vault call tokenise|find|detokenise|delete|rotate --kind k [--format f]
// [--purpose p] value-or-ref...
func callCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("call: which call?")
	}
	path := args[0]
	fs := flag.NewFlagSet("call", flag.ExitOnError)
	cf := addClient(fs)
	kind := fs.String("kind", "aadhaar", "the kind")
	format := fs.String("format", "", "tokenise: opaque or legacy")
	purpose := fs.String("purpose", "", "detokenise: why")
	_ = fs.Parse(args[1:])
	c, err := cf.client()
	if err != nil {
		return err
	}
	req := vault.Request{Kind: *kind, Format: *format, Purpose: *purpose}
	switch path {
	case "tokenise", "find":
		req.Values = fs.Args()
	default:
		req.Refs = fs.Args()
	}
	resp, code, err := c.Call(path, req)
	if resp == nil {
		resp = &vault.Response{}
	}
	out, _ := json.Marshal(struct {
		Code int `json:"code"`
		*vault.Response
	}{code, resp})
	fmt.Println(string(out))
	if err != nil && code == 0 {
		return err
	}
	return nil
}
