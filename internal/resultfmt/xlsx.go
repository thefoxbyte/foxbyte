// SPDX-License-Identifier: AGPL-3.0-or-later

package resultfmt

import (
	"archive/zip"
	"bytes"
	"strings"
	"time"
)

// An Excel workbook of a result (point 1.2): `fox sql --format xlsx`, and the
// console's Export menu (web/src/xlsx.ts), which builds the same worksheet. The
// two are held to one worksheet by web/src/xlsx.vectors.json.
//
// A .xlsx file is a zip of a few XML files, so this needs nothing beyond the
// standard library. Each value is written as what it is, a number as a number,
// true/false as a boolean, text as text (an inline string), so a spreadsheet
// never reads a value as a formula and there is nothing to escape. NULL is an
// empty cell. Text longer than Excel allows in a cell (32,767 characters) is
// cut there, or the workbook would not open.

const maxCellText = 32767

// colName is a column's letters: 0 → A, 25 → Z, 26 → AA.
func colName(i int) string {
	s := ""
	for i++; i > 0; i = (i - 1) / 26 {
		s = string(rune('A'+(i-1)%26)) + s
	}
	return s
}

// xmlText escapes text for XML, and drops the control characters XML 1.0
// cannot hold at all (all but tab, line feed and carriage return).
func xmlText(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '&':
			b.WriteString("&amp;")
		case r == '<':
			b.WriteString("&lt;")
		case r == '>':
			b.WriteString("&gt;")
		case r == '"':
			b.WriteString("&quot;")
		case r < 0x20 && r != '\t' && r != '\n' && r != '\r', r == 0xFFFE, r == 0xFFFF:
			// not representable in XML 1.0
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// truncateRunes cuts s to n characters (UTF-16 units are what Excel counts, but
// a rune count never exceeds that, so this stays inside the limit).
func truncateRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	i := 0
	for j := range s {
		if i == n {
			return s[:j]
		}
		i++
	}
	return s
}

const (
	sheetHead = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n" +
		`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`
	sheetTail = `</sheetData></worksheet>`
)

// writeCell writes one cell: a number as a number, true/false as a boolean,
// text as an inline string, and nothing for NULL.
func writeCell(b *strings.Builder, ref string, v any) {
	switch t := v.(type) {
	case nil:
		return
	case bool:
		x := "0"
		if t {
			x = "1"
		}
		b.WriteString(`<c r="` + ref + `" t="b"><v>` + x + `</v></c>`)
		return
	}
	s, _ := text(v)
	if isNumber(v) {
		b.WriteString(`<c r="` + ref + `"><v>` + s + `</v></c>`)
		return
	}
	b.WriteString(`<c r="` + ref + `" t="inlineStr"><is><t xml:space="preserve">` + xmlText(truncateRunes(s, maxCellText)) + `</t></is></c>`)
}

// SheetXML is the worksheet: the column names as the first row, then a row per
// result row.
func SheetXML(cols []string, rows [][]any) string {
	var b strings.Builder
	b.WriteString(sheetHead)
	head := make([]any, len(cols))
	for i, c := range cols {
		head[i] = c
	}
	b.WriteString(sheetRow(1, head))
	for i, r := range rows {
		b.WriteString(sheetRow(i+2, r))
	}
	b.WriteString(sheetTail)
	return b.String()
}

// The parts every workbook has, whatever its data.
const (
	xlsxContentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>`
	xlsxRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`
	xlsxWorkbook = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Result" sheetId="1" r:id="rId1"/></sheets></workbook>`
	xlsxWorkbookRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>`
)

// xlsxStamp is every part's time, fixed so the same result makes the same file.
var xlsxStamp = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

type part struct{ name, body string }

func staticParts() []part {
	return []part{
		{"[Content_Types].xml", xlsxContentTypes},
		{"_rels/.rels", xlsxRels},
		{"xl/workbook.xml", xlsxWorkbook},
		{"xl/_rels/workbook.xml.rels", xlsxWorkbookRels},
	}
}

// XLSX is a workbook of one sheet, "Result", holding cols and rows.
func XLSX(cols []string, rows [][]any) ([]byte, error) {
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for _, f := range append(staticParts(), part{"xl/worksheets/sheet1.xml", SheetXML(cols, rows)}) {
		w, err := z.CreateHeader(&zip.FileHeader{Name: f.name, Method: zip.Deflate, Modified: xlsxStamp})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(f.body)); err != nil {
			return nil, err
		}
	}
	if err := z.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
