//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package pii

import (
	"fmt"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// Automatic marks for the audit log (F6 Gate 1, step 6): a table holding
// personal data a reviewer confirmed has its writes audited. What a mark is,
// and why it only ever adds, is in internal/branch/auditauto.go.

func init() { branch.SetPIIAuditMarker(markTable, markAll) }

// auditTool is what the Blackbox records as having made the grant.
const auditTool = "personal data"

// markTable marks one table's writes unless they are audited already, and
// says whether it did.
func markTable(name, schema, table, actor string) (bool, error) {
	marks, err := branch.AuditMarks(name)
	if err != nil {
		return false, err
	}
	for _, m := range marks {
		if m.Schema == schema && m.Name == table && m.Writes {
			return false, nil
		}
	}
	if err := branch.MarkAuditedWrites(name, schema, table, actor, auditTool); err != nil {
		return false, err
	}
	return true, nil
}

// markAll marks every table with confirmed personal data whose writes are not
// audited, and returns those it marked. One that cannot be marked does not
// stop the others; every failure is said at the end.
func markAll(name, actor string) ([]string, error) {
	unmarked, err := branch.PersonalTablesUnmarked(name)
	if err != nil {
		return nil, err
	}
	var marked, failed []string
	for _, t := range unmarked {
		schema, table, _ := strings.Cut(t, ".")
		if err := branch.MarkAuditedWrites(name, schema, table, actor, auditTool); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", t, err))
			continue
		}
		marked = append(marked, t)
	}
	if len(failed) > 0 {
		return marked, fmt.Errorf("not marked: %s", strings.Join(failed, "; "))
	}
	return marked, nil
}
