// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"

	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// Reading a Blackbox as a stream.
//
// The integrity check, the diff and a change request each read whole ledgers.
// They used to collect psql's output, split it into lines and decode every
// line into a row before looking at any of it: three copies of the ledger at
// once, which at a million entries is gigabytes for one request. Here each line
// is decoded as it arrives and handed on, and what the caller keeps is up to
// the caller: the integrity check keeps a few hashes (ledger.Verifier), the
// diff and a change request keep the entries after the fork.
//
// The answers and the errors are the ones the old reads gave. A psql that
// fails part-way is an error, never a short ledger that reads as valid: the
// rows already handed on are the caller's to throw away, and every caller does.
// A decoding error is reported only if psql itself succeeded, as before, since
// a line cut off by a failing psql is not the problem worth reporting.

// ledgerPsql builds the psql command that ledgerLines has always run. A
// variable so a test can stand in for docker.
var ledgerPsql = func(name, sql string) (*exec.Cmd, context.Context, context.CancelFunc) {
	return sudoCmd(execQuick, "docker", "exec", "--env-file", pgEnvFile(), container(name),
		"psql", "-U", pgUser, "-d", pgDatabase, "-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1", "-c", sql)
}

// ledgerStream runs sql and hands each non-empty output line, trimmed, to
// visit as it arrives. The slice is only valid during the call.
//
// A container stopped behind the state cache is woken and the query run again,
// as ledgerLines does, but only if nothing was handed on yet: a second run
// would hand the same rows on twice.
func ledgerStream(name, sql string, visit func(line []byte) error) error {
	delivered := false
	var first error
	return retryIfStopped(name, func() error {
		if delivered {
			return first
		}
		first = ledgerStreamOnce(name, sql, func(l []byte) error {
			delivered = true
			return visit(l)
		})
		return first
	})
}

func ledgerStreamOnce(name, sql string, visit func([]byte) error) error {
	cmd, ctx, cancel := ledgerPsql(name, sql)
	defer cancel()
	procErr, visitErr := streamLines(cmd, visit)
	if procErr != nil {
		return execErr(ctx, execQuick, "docker exec psql", withStderr(procErr))
	}
	return visitErr
}

// streamLines runs cmd and feeds its stdout to visit line by line. It reads to
// the end even after visit fails, so the command's own outcome is known, and
// reports that outcome separately: procErr is what cmd.Output would have
// returned (with stderr kept for the message), visitErr the first error visit
// gave.
func streamLines(cmd *exec.Cmd, visit func([]byte) error) (procErr, visitErr error) {
	var stderr boundedBuffer
	if cmd.Stderr == nil {
		cmd.Stderr = &stderr
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err, nil
	}
	if err := cmd.Start(); err != nil {
		return err, nil
	}
	br := bufio.NewReaderSize(out, 64<<10)
	var readErr error
	for {
		line, err := br.ReadBytes('\n')
		if visitErr == nil {
			if l := bytes.TrimSpace(line); len(l) > 0 {
				visitErr = visit(l)
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				readErr = err
			}
			break
		}
	}
	if err := cmd.Wait(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.Stderr == nil {
			ee.Stderr = stderr.Bytes()
		}
		return err, nil
	}
	if readErr != nil {
		return readErr, nil
	}
	return nil, visitErr
}

// boundedBuffer keeps the start of what a command writes to stderr: enough for
// withStderr's one line, never an unbounded copy of a chatty failure.
type boundedBuffer struct{ b bytes.Buffer }

const stderrKept = 32 << 10

func (w *boundedBuffer) Write(p []byte) (int, error) {
	if room := stderrKept - w.b.Len(); room > 0 {
		if len(p) > room {
			w.b.Write(p[:room])
		} else {
			w.b.Write(p)
		}
	}
	return len(p), nil
}

func (w *boundedBuffer) Bytes() []byte { return w.b.Bytes() }

// streamLedgerRows decodes ledger rows (ledger.RowsQuery) as psql prints them
// and hands each to visit, in id order. Lines that are not a JSON document are
// skipped, as loadLedgerRows always did.
func streamLedgerRows(name string, withExt bool, where string, visit func(ledger.Row) error) error {
	return ledgerStream(name, ledger.RowsQuery(withExt, where), func(l []byte) error {
		if l[0] != '{' {
			return nil
		}
		r, err := ledger.DecodeRowJSON(l)
		if err != nil {
			return err
		}
		return visit(r)
	})
}

// loadLedgerRows reads matching ledger rows into memory, for the callers that
// need them all: one copy, decoded as it arrives, rather than three.
func loadLedgerRows(name string, withExt bool, where string) ([]ledger.Row, error) {
	rows := []ledger.Row{}
	err := streamLedgerRows(name, withExt, where, func(r ledger.Row) error {
		rows = append(rows, r)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// LedgerFork receives two Blackbox histories compared side by side. Fork is
// called once, when the histories part: common is how many entries they share
// (same id, same recomputed hash) and last is the last shared one, nil when
// they share none. OnlyA and OnlyB are then called for each entry after the
// fork on that side, in id order on each side. All three are called from one
// goroutine, and any may be nil.
type LedgerFork struct {
	Fork  func(common int, last *ledger.Row)
	OnlyA func(ledger.Row)
	OnlyB func(ledger.Row)
}

func (v LedgerFork) fork(n int, last *ledger.Row) {
	if v.Fork != nil {
		v.Fork(n, last)
	}
}

func (v LedgerFork) onlyA(r ledger.Row) {
	if v.OnlyA != nil {
		v.OnlyA(r)
	}
}

func (v LedgerFork) onlyB(r ledger.Row) {
	if v.OnlyB != nil {
		v.OnlyB(r)
	}
}

// WalkLedgerFork reads two branches' Blackboxes at the same time and reports
// where they part and what each has after it (see LedgerFork). This is
// commonPrefix without holding either ledger: the shared history, usually
// nearly all of both, is compared row by row and dropped. Both branches must be
// running. An error names the branch whose read failed, the first branch's
// first, and whatever was reported before it is to be thrown away.
func WalkLedgerFork(a, b string, v LedgerFork) error {
	if a == b {
		// One history compared with itself is all shared.
		n, last := 0, ledger.Row{}
		if err := streamLedgerRows(a, false, "", func(r ledger.Row) error {
			n, last = n+1, r
			return nil
		}); err != nil {
			return fmt.Errorf("reading %q's Blackbox: %w", a, err)
		}
		if n == 0 {
			v.fork(0, nil)
		} else {
			v.fork(n, &last)
		}
		return nil
	}
	ca, cb := make(chan ledger.Row, 256), make(chan ledger.Row, 256)
	var ea, eb error
	go func() {
		defer close(ca)
		ea = streamLedgerRows(a, false, "", func(r ledger.Row) error { ca <- r; return nil })
	}()
	go func() {
		defer close(cb)
		eb = streamLedgerRows(b, false, "", func(r ledger.Row) error { cb <- r; return nil })
	}()
	walkFork(ca, cb, v)
	if ea != nil {
		return fmt.Errorf("reading %q's Blackbox: %w", a, ea)
	}
	if eb != nil {
		return fmt.Errorf("reading %q's Blackbox: %w", b, eb)
	}
	return nil
}

// WalkRowsFork is WalkLedgerFork over histories already in memory.
func WalkRowsFork(a, b []ledger.Row, v LedgerFork) {
	ca, cb := make(chan ledger.Row, len(a)), make(chan ledger.Row, len(b))
	for _, r := range a {
		ca <- r
	}
	for _, r := range b {
		cb <- r
	}
	close(ca)
	close(cb)
	walkFork(ca, cb, v)
}

// walkFork compares two id-ordered row streams and drains both to the end.
// After the fork both are read as rows arrive, not one after the other, so a
// long tail on one side does not hold the other's psql waiting on a full pipe
// against its deadline.
func walkFork(ca, cb <-chan ledger.Row, v LedgerFork) {
	ra, oka := <-ca
	rb, okb := <-cb
	n, last := 0, ledger.Row{}
	for oka && okb && ra.ID == rb.ID && ledger.RowHash(ra) == ledger.RowHash(rb) {
		n, last = n+1, ra
		ra, oka = <-ca
		rb, okb = <-cb
	}
	if n == 0 {
		v.fork(0, nil)
	} else {
		v.fork(n, &last)
	}
	if oka {
		v.onlyA(ra)
	} else {
		ca = nil
	}
	if okb {
		v.onlyB(rb)
	} else {
		cb = nil
	}
	for ca != nil || cb != nil {
		select {
		case r, ok := <-ca:
			if !ok {
				ca = nil
				continue
			}
			v.onlyA(r)
		case r, ok := <-cb:
			if !ok {
				cb = nil
				continue
			}
			v.onlyB(r)
		}
	}
}
