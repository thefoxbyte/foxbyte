// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"fmt"

	"github.com/thefoxbyte/foxbyte/internal/brand"
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

// UpgradeHint is "run: fox blackbox upgrade <branch>" when that would help, and
// empty when it would not.
//
// `fox blackbox upgrade` applies the current Blackbox definition to a branch —
// but what "current" contains depends on the edition, because the paid schema
// objects live in enterprise/schema and a Standard build has none of them. So
// on an install that cannot have a feature, pointing at the upgrade sends
// someone after a command that will not install the thing they are missing.
//
// That is worse than saying nothing: a licensed boundary then reads as a broken
// install, and the next step they take is a support ticket. One function, so
// every message that wants to suggest the upgrade asks the same question first.
func UpgradeHint(name string, f edition.Feature) string {
	if !edition.Has(f) {
		return ""
	}
	return fmt.Sprintf("run: %s blackbox upgrade %s", brand.CLI, name)
}
