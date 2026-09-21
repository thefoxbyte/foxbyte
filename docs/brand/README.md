# Brand assets

| File | What it is |
| --- | --- |
| `logo.html` | the source of the two logos below — the mark, the wordmark and the tagline |
| `foxbyte-logo.png` | the logo for a light background (the README's default) |
| `foxbyte-logo-dark.png` | the same logo for a dark background (GitHub serves it to dark-mode readers) |

The mark's geometry lives in [`web/src/components/brand.tsx`](../../web/src/components/brand.tsx)
and is repeated here and in `web/public/favicon.svg`, because neither a PNG nor
a favicon can read the CSS variables the app draws it from. The two colours are
the brand's literals: ember `#ff7a2f` → fox amber `#ffc24a`.

To re-render after a change (any Chrome or Chromium):

```
chrome="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
"$chrome" --headless=new --force-device-scale-factor=2 --window-size=420,140 \
  --default-background-color=00000000 --virtual-time-budget=9000 \
  --screenshot=docs/brand/foxbyte-logo.png      "file://$PWD/docs/brand/logo.html"
"$chrome" --headless=new --force-device-scale-factor=2 --window-size=420,140 \
  --default-background-color=00000000 --virtual-time-budget=9000 \
  --screenshot=docs/brand/foxbyte-logo-dark.png "file://$PWD/docs/brand/logo.html?theme=dark"
```

The page loads its fonts from Google Fonts, so render it with a network
connection or the wordmark falls back to the system sans.

The product's *name* is not here: it comes from [`brand.json`](../../brand.json).
See [docs/branding.md](../branding.md).
