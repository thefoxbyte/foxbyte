// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"fmt"

	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// Where a paid feature is refused, in the package that does the work.
//
// The gate sits on the function that performs the action, not only at the CLI
// and the REST route. Those are the two callers today; the scheduler is a
// third, and the next one has to be remembered. Putting it here means it
// cannot be forgotten, and the edges keep their own check only so the message
// can name the feature and the way out instead of surfacing as a failure.
//
// The line the editions draw, in one sentence: **doing is paid, reading is
// free.** Writing an anchor, authoring a policy rule, running an impact
// analysis, applying a promotion, exporting a bundle and running a pipeline are
// Enterprise. Listing, checking and verifying what is already there are not —
// an install that used a feature before upgrading keeps everything it produced
// and can still read it, and the record of what happened is never the thing a
// licence switches off.

// ErrNotLicensed matches every refusal below, so a caller can ask "was this the
// licence?" without naming the feature.
var ErrNotLicensed = errors.New("this is an Enterprise feature")

// notLicensed is the refusal for one feature. A value type, so the per-feature
// sentinels below compare equal under errors.Is.
type notLicensed struct{ feature edition.Feature }

func (e notLicensed) Error() string {
	// Not "<feature> is an Enterprise feature": several of the names are plural,
	// and the agreement reads wrong. This phrasing works for all of them.
	return fmt.Sprintf("this install is not licensed for %s", edition.Describe(e.feature))
}

// Is lets errors.Is(err, ErrNotLicensed) match any of them.
func (e notLicensed) Is(target error) bool { return target == ErrNotLicensed }

// The refusals, one per gated feature. Named rather than built on the fly so a
// caller and a test can name the one they mean.
var (
	ErrAnchorsNotLicensed   = notLicensed{edition.Anchors}
	ErrPolicyNotLicensed    = notLicensed{edition.Policy}
	ErrImpactNotLicensed    = notLicensed{edition.Impact}
	ErrPromotionNotLicensed = notLicensed{edition.Promotion}
	ErrExportNotLicensed    = notLicensed{edition.Export}
	ErrPipelinesNotLicensed = notLicensed{edition.Pipelines}
)

// requireFeature is the one-line guard the gated functions start with.
func requireFeature(f edition.Feature) error {
	if edition.Has(f) {
		return nil
	}
	return notLicensed{f}
}
