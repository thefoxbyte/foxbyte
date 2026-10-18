// SPDX-License-Identifier: AGPL-3.0-or-later

package resultfmt

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Writing a result as it arrives, a row at a time, for exporting a whole
// result (point 1.3): `fox export` and POST /api/branches/{name}/export. Memory
// stays the same whatever the size. Row for row the output is exactly what
// Format and XLSX write for the same rows, which TestStreamMatchesFormat holds
// them to, so an export of the first rows is a copy of them.

// RowWriter writes one result as its rows arrive.
type RowWriter interface {
	Row(vals []any) error
	// Close finishes the file. It must be called once the rows are done.
	Close() error
}

// ErrExcelFull means a workbook already holds as many rows as Excel opens
// (1,048,576 with the header); the rest were not written.
var ErrExcelFull = errors.New("Excel holds at most 1,048,576 rows: the rest were not written")

const excelMaxRows = 1048576

// NewWriter starts writing cols in the chosen format to w: csv, tsv, json or
// xlsx.
func NewWriter(w io.Writer, cols []string, o Options) (RowWriter, error) {
	bw := bufio.NewWriterSize(w, 64<<10)
	switch o.Format {
	case "csv", "tsv":
		sep := ','
		if o.Format == "tsv" {
			sep = '\t'
		}
		d := &delimWriter{w: bw, sep: sep, o: o}
		if o.Header {
			vals := make([]any, len(cols))
			for i, c := range cols {
				vals[i] = c
			}
			if _, err := bw.WriteString(delimitedLine(vals, sep, false)); err != nil {
				return nil, err
			}
		}
		return d, nil
	case "json":
		return &jsonWriter{w: bw, keys: keys(cols)}, nil
	case "xlsx":
		return newXLSXWriter(bw, cols)
	}
	return nil, fmt.Errorf("unknown export format %q (one of csv, tsv, json, xlsx)", o.Format)
}

type delimWriter struct {
	w   *bufio.Writer
	sep rune
	o   Options
}

func (d *delimWriter) Row(vals []any) error {
	_, err := d.w.WriteString(delimitedLine(vals, d.sep, d.o.Safe))
	return err
}
func (d *delimWriter) Close() error { return d.w.Flush() }

type jsonWriter struct {
	w    *bufio.Writer
	keys []string
	n    int
}

func (j *jsonWriter) Row(vals []any) error {
	if j.n == 0 {
		j.w.WriteString("[\n")
	} else {
		j.w.WriteString(",\n")
	}
	j.n++
	s, err := jsonObject(j.keys, vals)
	if err != nil {
		return err
	}
	_, err = j.w.WriteString(s)
	return err
}

func (j *jsonWriter) Close() error {
	if j.n == 0 {
		j.w.WriteString("[]\n")
	} else {
		j.w.WriteString("\n]\n")
	}
	return j.w.Flush()
}

type xlsxWriter struct {
	out   *bufio.Writer
	z     *zip.Writer
	sheet io.Writer
	n     int // rows written, the header included
	full  bool
}

func newXLSXWriter(out *bufio.Writer, cols []string) (*xlsxWriter, error) {
	z := zip.NewWriter(out)
	for _, f := range staticParts() {
		w, err := z.CreateHeader(&zip.FileHeader{Name: f.name, Method: zip.Deflate, Modified: xlsxStamp})
		if err != nil {
			return nil, err
		}
		if _, err := io.WriteString(w, f.body); err != nil {
			return nil, err
		}
	}
	sheet, err := z.CreateHeader(&zip.FileHeader{Name: "xl/worksheets/sheet1.xml", Method: zip.Deflate, Modified: xlsxStamp})
	if err != nil {
		return nil, err
	}
	x := &xlsxWriter{out: out, z: z, sheet: sheet}
	io.WriteString(sheet, sheetHead)
	head := make([]any, len(cols))
	for i, c := range cols {
		head[i] = c
	}
	return x, x.Row(head)
}

func (x *xlsxWriter) Row(vals []any) error {
	if x.n >= excelMaxRows {
		x.full = true
		return ErrExcelFull
	}
	x.n++
	_, err := io.WriteString(x.sheet, sheetRow(x.n, vals))
	return err
}

func (x *xlsxWriter) Close() error {
	io.WriteString(x.sheet, sheetTail)
	if err := x.z.Close(); err != nil {
		return err
	}
	return x.out.Flush()
}

// sheetRow is one worksheet row, numbered from 1.
func sheetRow(n int, vals []any) string {
	var b strings.Builder
	b.WriteString(`<row r="` + strconv.Itoa(n) + `">`)
	for i, v := range vals {
		writeCell(&b, colName(i)+strconv.Itoa(n), v)
	}
	b.WriteString(`</row>`)
	return b.String()
}

// jsonObject is one row as the JSON format writes it: indented, keys in
// column order.
func jsonObject(ks []string, vals []any) (string, error) {
	var b strings.Builder
	b.WriteString("  {\n")
	for i, v := range vals {
		k, err := json.Marshal(ks[i])
		if err != nil {
			return "", err
		}
		var val []byte
		if isNumber(v) {
			s, _ := text(v)
			val = []byte(s)
		} else if val, err = marshal(v); err != nil {
			return "", err
		}
		b.WriteString("    " + string(k) + ": " + string(val))
		if i < len(vals)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString("  }")
	return b.String(), nil
}
