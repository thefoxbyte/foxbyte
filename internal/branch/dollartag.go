// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"strings"
)

// DollarTag returns a dollar-quote tag ($base$, or $base1$, $base2$, …) that
// does not occur in body, so the body cannot end its own quoting.
//
// It is for bodies holding what bodyLiteral cannot rewrite: identifiers. A
// table or column name may legally contain '$', and anyone who can create a
// table chooses one, so a fixed tag could be closed by a name when the engine
// later builds SQL around that table as the superuser. With no collision the
// tag is exactly $base$.
func DollarTag(base, body string) string {
	tag := "$" + base + "$"
	for i := 1; strings.Contains(body, tag); i++ {
		tag = fmt.Sprintf("$%s%d$", base, i)
	}
	return tag
}
