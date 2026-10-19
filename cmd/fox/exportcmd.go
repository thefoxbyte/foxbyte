// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/controlplane"
	"github.com/thefoxbyte/foxbyte/internal/resultfmt"
)

// resultExportCmd is `fox export`: every row a query returns, written as it arrives
// (point 1.3). `fox sql` stops at 1,000 rows, as the console does; this does
// not stop.
//
//	fox export [--branch <b>] [--format csv|tsv|json|xlsx] [--no-header] [--raw]
//	           "<sql>" | -   > file
//
// The file is stdout, redirected: on macOS and Windows this runs in the VM, and
// stdout is what reaches this computer unchanged, where a path would name a
// file in the VM.
//
// Read only, one statement, as the shared client role labelled for the
// Blackbox, and recorded in the security log (data.export) with a fingerprint
// of the query. Ctrl-C stops it and the query with it.
func resultExportCmd(args []string) {
	b := optValue(args, "--branch")
	if b == "" {
		b = "main"
	}
	format := optValue(args, "--format")
	if format == "" {
		format = "csv"
	}
	sql := strings.Join(positionals(args, "--branch", "--format"), " ")
	if sql == "" || sql == "-" {
		in, err := io.ReadAll(os.Stdin)
		must(err)
		sql = string(in)
	}
	if strings.TrimSpace(sql) == "" {
		fmt.Printf("usage: %s export [--branch <b>] [--format csv|tsv|json|xlsx] [--no-header] [--raw] \"<sql>\" | -  > file\n", brand.CLI)
		os.Exit(2)
	}
	var out io.Writer = os.Stdout
	if format == "xlsx" && isTerminal(os.Stdout) {
		fmt.Fprintf(os.Stderr, "%s export --format xlsx writes a workbook: send it to a file (> result.xlsx)\n", brand.CLI)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	o := controlplane.ExportOptions{Format: format, Header: !hasFlag(args, "--no-header"), Safe: !hasFlag(args, "--raw")}
	start := time.Now()
	n, err := controlplane.ExportSQL(ctx, out, b, sql, cliActor(), o)
	if s := openStore(); s != nil {
		s.Audit(auth.EvDataExport, cliActor(), b, "", controlplane.ExportDetail(b, sql, format, n, err))
		kept := err
		if errors.Is(err, resultfmt.ErrExcelFull) {
			kept = nil
		}
		controlplane.RecordCLIQuery(s, cliActor(), b, sql, "export", start, n, kept)
	}
	switch {
	case errors.Is(err, resultfmt.ErrExcelFull):
		fmt.Fprintf(os.Stderr, "%d rows exported; %v\n", n, err)
	case err != nil:
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		if n > 0 {
			fmt.Fprintf(os.Stderr, "(stopped after %d rows: the file is incomplete)\n", n)
		}
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "%d row%s exported\n", n, plural(int(n)))
	}
}
