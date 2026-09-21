import { useState } from 'react'
import { getTheme, toggleTheme } from '../theme'
import { BRAND } from '../brand'

// Wordmark renders the product name with its last capitalised part picked out
// in the brand gradient (Fox|Byte). Split here rather than written into the
// markup: the product has been renamed twice, and a name spread across tags is
// exactly what a rename misses.
export function Wordmark() {
  const m = /^(.*[a-z])([A-Z].*)$/.exec(BRAND.product)
  // One element around the whole name: the brand row is a flex box, and two
  // bare children would be spaced by its gap — "Fox Byte".
  return (
    <span className="wm">
      {m ? <>{m[1]}<span className="wm-accent">{m[2]}</span></> : BRAND.product}
    </span>
  )
}

// The mark: a fox head, built from the same two angles as the branch graph —
// two ears rising, a muzzle tapering down. It is geometry rather than drawing,
// so it survives being 20px tall in a sidebar.
//
// The gradient is declared in CSS custom properties, not hexes, so the mark
// follows the theme; the old one stayed dark-mode purple on a white page. The
// id is per-instance: two marks on one page with the same gradient id would
// have the second quietly reuse the first.
let markSeq = 0

export function Mark({ size = 26 }: { size?: number }) {
  const id = `fox-mark-${++markSeq}`
  return (
    <svg
      className="mark" width={size} height={size} viewBox="0 0 32 32"
      fill="none" role="img" aria-label={BRAND.product}
    >
      <defs>
        <linearGradient id={id} x1="4" y1="2" x2="28" y2="30" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="var(--grad-a)" />
          <stop offset="1" stopColor="var(--grad-b)" />
        </linearGradient>
      </defs>
      {/* ears */}
      <path d="M5.2 3.4 13 7.4 8.6 14.2 4.4 8.2Z" fill={`url(#${id})`} />
      <path d="M26.8 3.4 19 7.4l4.4 6.8 4.2-6Z" fill={`url(#${id})`} />
      {/* head: wide at the ears, tapering to the muzzle */}
      <path
        d="M16 6.6c4.6 0 8.4 2.4 9.8 6.4 1 2.9.3 6.2-1.9 9.1-1.9 2.5-4.6 4.4-7.9 5.6-3.3-1.2-6-3.1-7.9-5.6-2.2-2.9-2.9-6.2-1.9-9.1 1.4-4 5.2-6.4 9.8-6.4Z"
        fill={`url(#${id})`}
      />
      {/* eyes and muzzle, punched out so the mark reads at small sizes */}
      <path d="M11.4 15.1c1.3 0 2.2.9 2.2 2s-.9 1.7-2.2 1.7-2.3-.6-2.3-1.7.9-2 2.3-2Z" fill="var(--bg)" />
      <path d="M20.6 15.1c1.4 0 2.3.9 2.3 2s-1 1.7-2.3 1.7-2.2-.6-2.2-1.7.9-2 2.2-2Z" fill="var(--bg)" />
      <path d="M16 21.4c1.6 0 2.7.7 2.7 1.6 0 1.1-1.2 2.3-2.7 3.1-1.5-.8-2.7-2-2.7-3.1 0-.9 1.1-1.6 2.7-1.6Z" fill="var(--bg)" opacity=".92" />
    </svg>
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
