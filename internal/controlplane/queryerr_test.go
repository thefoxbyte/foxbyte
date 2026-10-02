package controlplane

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// Postgres says where a syntax error is; the console cannot point at the line
// unless that survives the trip. Detail and hint come with it because Postgres's
// hint is often the whole answer.
func TestQueryErrCarriesWherePostgresSaysItIs(t *testing.T) {
	pg := &pgconn.PgError{
		Severity: "ERROR", Code: "42601",
		Message:  `syntax error at or near "FORM"`,
		Position: 42, Hint: "Perhaps you meant SELECT … FROM.", Detail: "near token FORM",
	}
	got := queryErr(pg)
	if got["position"] != int32(42) {
		t.Errorf("position = %v, want 42", got["position"])
	}
	if got["hint"] != "Perhaps you meant SELECT … FROM." {
		t.Errorf("hint = %v", got["hint"])
	}
	if got["detail"] != "near token FORM" {
		t.Errorf("detail = %v", got["detail"])
	}

	// A position of zero means Postgres did not locate it; sending 0 would have
	// the console point at character zero, which is a lie about line 1.
	got = queryErr(&pgconn.PgError{Message: "deadlock detected", Code: "40P01"})
	if _, ok := got["position"]; ok {
		t.Error("a zero position should be left out, not sent as 0")
	}

	// Anything that is not a Postgres error still renders.
	got = queryErr(errors.New("connection refused"))
	if got["error"] != "connection refused" {
		t.Errorf("plain error = %v", got["error"])
	}
	if _, ok := got["position"]; ok {
		t.Error("a plain error has no position")
	}
}
