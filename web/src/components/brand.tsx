import { useState } from 'react'
import { getTheme, toggleTheme } from '../theme'
import { BRAND } from '../brand'

// Wordmark renders the product name with one letter picked out in the mark's
// gradient — the letter immediately before the second capital, which in
// FoxByte is the x the logo itself colours. Derived from the name rather than
// written into the markup: the product has been renamed twice, and a name
// spread across tags is exactly what a rename misses.
export function Wordmark() {
  const m = /^(.*?)(.)([A-Z].*)$/.exec(BRAND.product)
  // One element around the whole name: the brand row is a flex box, and two
  // bare children would be spaced by its gap — "Fox Byte".
  return (
    <span className="wm">
      {m ? <>{m[1]}<span className="wm-accent">{m[2]}</span>{m[3]}</> : BRAND.product}
    </span>
  )
}

// The mark is the logo as supplied — artwork, not geometry this file draws.
// It replaced a fox head built from two angles of the branch graph, which was
// an SVG filled from CSS variables so it followed the theme. The new mark
// cannot: it is a fixed orange-to-blue cube. That is the trade, and it is the
// right way round — the logo is the logo on either theme, and the one asset
// with real transparency is this one, so it sits on any background without a
// plate behind it.
//
// 128px of artwork for something drawn at most at 30: that covers a 3x display
// and still costs 19K. It carries the product name rather than being marked
// decorative, because the sidebar collapses to the mark alone and the name has
// to survive that.
export function Mark({ size = 26 }: { size?: number }) {
  return (
    <img
      className="mark" src="/mark.png" width={size} height={size}
      alt={BRAND.product} draggable={false}
    />
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
