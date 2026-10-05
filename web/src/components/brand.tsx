import { useState } from 'react'
import { getTheme, toggleTheme } from '../theme'
import { BRAND } from '../brand'

// Wordmark renders the product name, derived from brand.json rather than
// written into the markup: the product has been renamed twice, and a name
// spread across tags is exactly what a rename misses.
//
// One letter can be picked out in the mark's colours — the letter before the
// second capital, the x in FoxByte. That followed the logo that drew its own x
// in a gradient; the current one does not, so brand.json turns it off and this
// renders the plain name. The switch is there rather than the code deleted
// because the next logo may want it back, and finding the rule again would be
// the expensive part.
export function Wordmark() {
  const m = BRAND.wordmarkAccent ? /^(.*?)(.)([A-Z].*)$/.exec(BRAND.product) : null
  // One element around the whole name: the brand row is a flex box, and two
  // bare children would be spaced by its gap — "Fox Byte".
  return (
    <span className="wm">
      {m ? <>{m[1]}<span className="wm-accent">{m[2]}</span>{m[3]}</> : BRAND.product}
    </span>
  )
}

// The mark, in whichever ink the page can show it.
//
// The artwork is two-tone and the cool half changes with the background: white
// beside the orange on a dark page, navy on a light one. One file cannot do
// both — a white mark disappears on paper — so both are shipped and CSS picks,
// which also means the switch costs nothing at runtime and cannot flash the
// wrong one before a script runs.
//
// Both files are generated: cmd/brandgen derives every size from the artwork in
// docs/brand/source, and `make brand-check` fails if any of them is stale. The
// sizes are not written here for the same reason.
export function Mark({ size = 26 }: { size?: number }) {
  return (
    <span className="mark" style={{ width: size, height: size }} role="img" aria-label={BRAND.product}>
      <img className="mark-dark" src="/mark-dark.png" width={size} height={size} alt="" draggable={false} />
      <img className="mark-light" src="/mark-light.png" width={size} height={size} alt="" draggable={false} />
    </span>
  )
}

// The round light/dark toggle used in the public navbar.
export function ThemeToggle() {
  const [theme, setTheme] = useState(getTheme())
  return (
    <button className="theme-toggle" title="Toggle theme" onClick={() => setTheme(toggleTheme())}>
      {theme === 'dark' ? '☀' : '☾'}
    </button>
  )
}
