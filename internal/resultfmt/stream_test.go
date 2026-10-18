// SPDX-License-Identifier: AGPL-3.0-or-later

package resultfmt

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
)

// An export written a row at a time is, row for row, exactly what the copy
// and on-screen formats write: the same shared cases, through NewWriter.
func TestStreamMatchesFormat(t *testing.T) {
	b, err := os.ReadFile("../../web/src/copyformat.vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []vector
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, v := range vs {
		if v.Format != "csv" && v.Format != "tsv" && v.Format != "json" {
			continue // Markdown and INSERTs are for pasting, not for files
		}
		n++
		var buf bytes.Buffer
		w, err := NewWriter(&buf, v.Columns, Options{Format: v.Format, Header: v.Header, Safe: v.Safe})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range v.Rows {
			if err := w.Row(r); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if buf.String() != v.Want {
			t.Errorf("%s\n got %q\nwant %q", v.Name, buf.String(), v.Want)
		}
	}
	if n < 8 {
		t.Fatalf("only %d cases", n)
	}
}

// The streamed workbook's sheet is the same as the whole one's.
func TestStreamXLSXMatches(t *testing.T) {
	cols := []string{"id", "name", "ok"}
	rows := [][]any{{int64(1), "Ada & <Co>", true}, {2.5, nil, false}}
	var buf bytes.Buffer
	w, err := NewWriter(&buf, cols, Options{Format: "xlsx"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		_ = w.Row(r)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	z, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range z.File {
		if f.Name == "xl/worksheets/sheet1.xml" {
			r, _ := f.Open()
			got, _ := io.ReadAll(r)
			if string(got) != SheetXML(cols, rows) {
				t.Errorf("streamed sheet differs:\n%s", got)
			}
			return
		}
	}
	t.Error("no sheet in the streamed workbook")
}

// A workbook stops at what Excel can open, and still closes into a file that
// opens.
func TestStreamXLSXStopsAtExcelsLimit(t *testing.T) {
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, []string{"n"}, Options{Format: "xlsx"})
	x := w.(*xlsxWriter)
	x.n = excelMaxRows - 1 // as if nearly full
	if err := w.Row([]any{int64(1)}); err != nil {
		t.Fatalf("the last row that fits: %v", err)
	}
	if err := w.Row([]any{int64(2)}); !errors.Is(err, ErrExcelFull) {
		t.Fatalf("one past the limit: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len())); err != nil {
		t.Errorf("a full workbook does not open: %v", err)
	}
}

func TestStreamUnknownFormat(t *testing.T) {
	if _, err := NewWriter(io.Discard, nil, Options{Format: "insert"}); err == nil {
		t.Error("INSERTs are not an export format")
	}
}
