// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"

	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
	"github.com/thefoxbyte/foxbyte/internal/version"
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

// versionLine is what `fox version` prints.
//
// In the Standard edition the version is the last whitespace-separated field,
// and the only thing after the command name. That is not a style choice.
//
// `fox update` checks the engine it has staged by running `version` on it and
// parsing what comes back — and the binary doing that parsing is the one
// already installed, not the one being installed. Every release up to and
// including v1.0 read the last field, so when the editions split added
// "(standard edition)" the last field became "edition)", and those installs
// refused every update with "the new engine doesn't run here" after
// downloading a binary that ran perfectly well. Fixing the parser could not
// fix them: the fix ships in the new binary, which is not the one deciding.
//
// So the line has to stay readable by the oldest parser in the field, for as
// long as any of those installs exist. Enterprise may say more after the
// version: no Enterprise build predates the parser fix, and `fox update` keeps
// a machine in its own edition, so no old parser ever sees that suffix. Which
// edition a Standard install is remains a question `fox check` answers, in a
// row of its own.
func versionLine() string {
	return versionLineFor(edition.Enterprise, version.Version, editionLine())
}

// versionLineFor is the pure half, so either build can test both editions'
// output — the alternative is a test that only checks the edition it was
// compiled as, which is how this went wrong in the first place.
func versionLineFor(enterprise bool, ver, ed string) string {
	if !enterprise {
		return fmt.Sprintf("%s %s", brand.CLI, ver)
	}
	return fmt.Sprintf("%s %s (%s)", brand.CLI, ver, ed)
}
