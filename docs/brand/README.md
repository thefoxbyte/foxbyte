# Brand assets

**To change the logo:** replace the four files in `source/`, set the colours in
[`brand.json`](../../brand.json)'s `logo` block to match, run `make brand`.
That is the whole procedure. Nothing below is cut by hand.

`make brand-check` — which CI runs, and which `TestGeneratedFilesAreInStep`
also covers — fails if any derived file is stale. Forgetting to regenerate is a
red build rather than a favicon left a version behind the mark beside it, which
is how the last two logo changes went.

## The source

| File | What it is |
| --- | --- |
| `source/mark-dark.png` | the mark as drawn for a dark page (white and orange) |
| `source/mark-light.png` | the mark as drawn for a light page (navy and orange) |
| `source/lockup-dark.png` | mark and wordmark, for a dark page |
| `source/lockup-light.png` | mark and wordmark, for a light page |

These are the artwork exactly as supplied, background and all, converted to PNG
only so the generator can read them with the standard library. **Do not trim or
key them by hand** — the generator does both, and doing it twice is how edges
get crunchy.

## What is derived from them

| File | Size | Used by |
| --- | --- | --- |
| `web/public/mark-dark.png` | 128 | the app, on a dark theme |
| `web/public/mark-light.png` | 128 | the app, on a light theme |
| `web/public/favicon.png` | 48 | the browser tab |
| `web/public/apple-touch-icon.png` | 180 | iOS |
| `docs/brand/foxbyte-mark.png` | 512 | the mark on its own |
| `docs/brand/foxbyte-mark-light.png` | 512 | the same, for a light page |
| `docs/brand/foxbyte-logo.png` | 720 | the README, light |
| `docs/brand/foxbyte-logo-dark.png` | 720 | the README, dark |
| `web/src/brand.gen.css` | — | the two colours, as CSS custom properties |

The sizes live in `internal/brand/gen/logo.go` rather than in `brand.json`,
because they follow from where the image is shown and not from the artwork: the
app never draws the mark above 30px, a tab icon is a tab icon, iOS asks for 180.
New artwork does not change any of them.

## Two things the generator does that are worth knowing

**It keys the background out.** The corner pixel is taken as the background and
pixels near it become transparent, with a feathered edge so nothing comes out
jagged. Every derived asset is therefore transparent and sits on any page.
`key_tolerance` and `key_feather` in `brand.json` are the knobs: raise the first
if new artwork leaves a fringe, the second if its edges look hard.

The favicon and the touch icon are the exceptions — they get an opaque plate of
`logo.plate`, because iOS ignores a touch icon's alpha and composites on black,
and a browser tab may be either colour.

**The mark ships in two inks and CSS chooses.** The cool half is white on a dark
page and navy on a light one, so one file cannot serve both. Both are shipped
and `[data-theme]` picks, which means the right one is painted on the first
frame rather than after a script runs. The wordmark's accented letter follows
the same rule, which is why `brand.json` carries `accent_cool_on_dark` and
`accent_cool_on_light` rather than one colour — a single one disappeared into
the dark theme.

The product's *name* is not here: it comes from [`brand.json`](../../brand.json).
See [docs/branding.md](../branding.md).
