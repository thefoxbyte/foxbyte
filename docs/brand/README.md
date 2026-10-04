# Brand assets

The logo is artwork, not something this repository generates. Until 4 October
2026 it was: `logo.html` drew a fox head from the same two angles as the branch
graph, and two Chrome screenshots of that page were the README's logos. The
mark is now a supplied orange-to-blue cube, so the page and its render commands
are gone and these files are the originals.

| File | What it is | Where it is used |
| --- | --- | --- |
| `foxbyte-mark.png` | the mark on its own, 512px, **transparent** | the master for every icon below |
| `foxbyte-logo.png` | mark and wordmark, for a light background | the README's default |
| `foxbyte-logo-dark.png` | the same lockup for a dark background | GitHub serves it to dark-mode readers |
| `foxbyte-wordmark.png` | the wordmark alone, for a light background | — |
| `foxbyte-wordmark-dark.png` | the wordmark alone, for a dark background | — |

**Only the mark is transparent.** Every lockup has its background baked in, and
the dark ones were tried both ways before being left alone: keying a flat colour
leaves a halo, because that background is a gradient rather than one colour, and
taking alpha from luminance — which works for bright artwork on true black —
lifts the backdrop into a visible grey haze here, because it is `#020d20` rather
than black. So the lockups ship as supplied, which is why they come as a
light/dark pair and the mark does not need to.

On GitHub the light lockup's `#fefefe` is invisible against the page. The dark
one's backdrop is darker and bluer than GitHub's `#0d1117`, so it reads as a
deliberate plate behind the logo rather than as nothing at all. New artwork with
a transparent lockup would remove that; it is the only thing missing here.

The app's copies are derived from `foxbyte-mark.png` and live in `web/public/`:

| File | Size | Why that size |
| --- | --- | --- |
| `mark.png` | 128px | the app never draws it above 30px; 128 covers a 3x display |
| `favicon.png` | 48px | the browser tab |
| `apple-touch-icon.png` | 180px | on the brand's dark ground, because iOS ignores a touch icon's alpha and composites it on black |

To regenerate them after new artwork, resize `foxbyte-mark.png` to those three
sizes. They are a straight scale of one square image: the supplied mark is
trimmed to its own bounds and padded to a square first, so nothing shifts
between sizes.

The two colours sampled from the mark are ember `#ff7f02` and blue `#006bff`.
They are in `web/src/styles.css` as `--mark-a` and `--mark-b`, kept apart from
`--grad-a`/`--grad-b`, which are the product's accent and tint every button and
focus ring — adopting the mark's blue across those is a palette decision rather
than a logo one, and has not been taken.

The product's *name* is not here: it comes from [`brand.json`](../../brand.json).
See [docs/branding.md](../branding.md).
