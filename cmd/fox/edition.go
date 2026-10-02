// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"

	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// requireFeature stops a command that needs a paid feature this build cannot
// serve, and says which of the two reasons applies. A Standard binary does not
// contain the code; an Enterprise binary does but has no licence covering it.
// Telling them apart matters: one is a download, the other is a purchase.
func requireFeature(f edition.Feature) {
	if edition.Has(f) {
		return
	}
	fmt.Fprintf(os.Stderr, "error: %s is part of %s Enterprise, and this is the %s edition.\n",
		edition.Describe(f), brand.Product, edition.Name())
	if edition.Enterprise {
		fmt.Fprintf(os.Stderr, "\nThis build can run it, but no licence covers %q.\n"+
			"Activate one with: %s license activate <file>\n", f, brand.CLI)
	} else {
		fmt.Fprintf(os.Stderr, "\nInstall the Enterprise edition to use it, then activate a licence:\n"+
			"  %s license activate <file>\n", brand.CLI)
	}
	os.Exit(1)
}

// editionLine is what `fox version` and `fox check` print. A user reporting a
// problem should never have to guess which edition they are running, and the
// licence state is the other half of that answer.
func editionLine() string {
	switch {
	case !edition.Enterprise:
		return "standard edition"
	case len(edition.Available()) == 0:
		return "enterprise edition, no licence active"
	default:
		return fmt.Sprintf("enterprise edition, %d features licensed", len(edition.Available()))
	}
}
