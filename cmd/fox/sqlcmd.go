// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/controlplane"
	"github.com/thefoxbyte/foxbyte/internal/resultfmt"
)

// sqlCmd is `fox sql`: run SQL on a branch and print the result, as a table to
// read or in a format to paste somewhere else (point 1.1):
//
//	fox sql [--branch <b>] "<sql>"                       a table to read
//	fox sql --format csv|tsv|markdown|json|insert …      to paste elsewhere
//	        [--no-header] [--raw] [--table <t>]
//	fox sql --format xlsx "<sql>" > result.xlsx          an Excel workbook (1.2)
//	echo "SELECT 1" | fox sql -                          SQL from stdin
//
// It runs as the console does, as the shared client role (bound by row-level
// security, the guardrails and the append-only Blackbox), and the Blackbox
// records the person at this machine as the actor. At most 1,000 rows per
// statement, as in the console.
func sqlCmd(args []string) {
	b := optValue(args, "--branch")
	if b == "" {
		b = "main"
	}
	format := optValue(args, "--format")
	if format == "" {
		format = "table"
	}
	sql := strings.Join(positionals(args, "--branch", "--format", "--table"), " ")
	if sql == "" || sql == "-" {
		in, err := io.ReadAll(os.Stdin)
		must(err)
		sql = string(in)
	}
	if strings.TrimSpace(sql) == "" {
		fmt.Printf("usage: %s sql [--branch <b>] [--format table|csv|tsv|markdown|json|insert|xlsx] [--no-header] [--raw] [--table <t>] \"<sql>\" | -\n", brand.CLI)
		os.Exit(2)
	}
	// A workbook is binary: written to a terminal it is noise that can leave
	// the terminal in a strange state.
	if format == "xlsx" && isTerminal(os.Stdout) {
		fmt.Fprintf(os.Stderr, "%s sql --format xlsx writes a workbook: send it to a file, e.g. > result.xlsx\n", brand.CLI)
		os.Exit(2)
	}
	start := time.Now()
	out, err := controlplane.RunSQL(b, sql, cliActor())
	must(err)
	rows, failed := out.Outcome()
	if hs := historyStore(); hs != nil {
		controlplane.RecordCLIQuery(hs, cliActor(), b, sql, "query", start, rows, failed)
		hs.Close()
	}
	os.Exit(printSQL(os.Stdout, os.Stderr, out, format, sqlOpts(args)))
}

// sqlOpts reads the format flags: CSV and TSV get a header and formula
// escaping unless told otherwise.
func sqlOpts(args []string) resultfmt.Options {
	return resultfmt.Options{
		Header: !hasFlag(args, "--no-header"),
		Safe:   !hasFlag(args, "--raw"),
		Table:  optValue(args, "--table"),
	}
}

// printSQL writes what running SQL gave and returns the exit status: 0 when
// every statement ran, 1 when one failed, 2 for a format it cannot write.
func printSQL(w, ew io.Writer, out controlplane.SQLOutput, format string, o resultfmt.Options) int {
	failed := false
	report := func(msg, detail, hint string) {
		fmt.Fprintln(ew, "ERROR:", msg)
		if detail != "" {
			fmt.Fprintln(ew, "DETAIL:", detail)
		}
		if hint != "" {
			fmt.Fprintln(ew, "HINT:", hint)
		}
		failed = true
	}
	capped := func(r controlplane.SQLResult) {
		if len(r.Rows) >= controlplane.RowCap {
			fmt.Fprintf(ew, "(the first %d rows)\n", controlplane.RowCap)
		}
	}

	if format == "table" {
		for i, r := range out.Results {
			if len(out.Results) > 1 {
				if i > 0 {
					fmt.Fprintln(w)
				}
				fmt.Fprintf(w, "-- statement %d: %s\n", i+1, r.Command)
			}
			if r.Error != "" {
				report(r.Error, r.Detail, r.Hint)
				continue
			}
			if len(r.Columns) == 0 {
				fmt.Fprintln(w, r.Command)
				continue
			}
			tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, strings.Join(r.Columns, "\t"))
			for _, row := range r.Rows {
				cells := make([]string, len(row))
				for j, v := range row {
					cells[j] = tableCell(v)
				}
				fmt.Fprintln(tw, strings.Join(cells, "\t"))
			}
			_ = tw.Flush()
			fmt.Fprintf(w, "(%d row%s)\n", len(r.Rows), plural(len(r.Rows)))
			capped(r)
		}
	} else {
		// One result to paste: the last statement that returned rows.
		var pick *controlplane.SQLResult
		for i := range out.Results {
			r := &out.Results[i]
			if r.Error != "" {
				report(r.Error, r.Detail, r.Hint)
			} else if len(r.Columns) > 0 {
				pick = r
			}
		}
		if pick != nil && !failed && format == "xlsx" {
			b, err := resultfmt.XLSX(pick.Columns, pick.Rows)
			if err != nil {
				fmt.Fprintln(ew, "fox sql:", err)
				return 2
			}
			_, _ = w.Write(b)
			capped(*pick)
		} else if pick != nil && !failed {
			o.Format = format
			s, err := resultfmt.Format(pick.Columns, pick.Rows, o)
			if err != nil {
				fmt.Fprintln(ew, "fox sql:", err)
				return 2
			}
			fmt.Fprint(w, s)
			capped(*pick)
		} else if pick == nil && !failed && out.Error == "" {
			fmt.Fprintln(ew, "the SQL returned no rows to format")
		}
	}
	if out.Error != "" {
		report(out.Error, out.Detail, out.Hint)
	}
	if out.Note != "" {
		fmt.Fprintln(ew, out.Note)
	}
	if failed {
		return 1
	}
	return 0
}

// tableCell is a value as the console's grid shows it, on one line.
func tableCell(v any) string {
	if v == nil {
		return "NULL"
	}
	s, err := resultfmt.Format([]string{"v"}, [][]any{{v}}, resultfmt.Options{Format: "tsv"})
	if err != nil {
		return fmt.Sprint(v)
	}
	s = strings.TrimSuffix(s, "\n")
	if strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) {
		s = strings.ReplaceAll(s[1:len(s)-1], `""`, `"`)
	}
	return strings.NewReplacer("\t", " ", "\r\n", "↵", "\n", "↵", "\r", "↵").Replace(s)
}

// positionals are the arguments that are neither flags nor a flag's value.
func positionals(args []string, valueFlags ...string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a != "-" && strings.HasPrefix(a, "-") {
			for _, f := range valueFlags {
				if a == f {
					i++
					break
				}
			}
			continue
		}
		out = append(out, a)
	}
	return out
}

// isTerminal reports whether f is a terminal rather than a file or a pipe.
func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
