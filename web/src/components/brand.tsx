import { useState } from 'react'
import { getTheme, toggleTheme } from '../theme'
import { BRAND } from '../brand'

// Wordmark renders the product name with its last capitalised part picked out
// in the brand gradient (Fox|Byte). Split here rather than written into the
// markup: the product has been renamed twice, and a name spread across tags is
// exactly what a rename misses.
export function Wordmark() {
  const m = /^(.*[a-z])([A-Z].*)$/.exec(BRAND.product)
  return m ? <>{m[1]}<span>{m[2]}</span></> : <>{BRAND.product}</>
}

// The mark: a branch splitting in two.
export function Mark({ size = 26 }: { size?: number }) {
  return (
    <svg className="mark" width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden>
      <defs>
        <linearGradient id="vg" x1="0" y1="24" x2="24" y2="0">
          <stop offset="0" stopColor="#8b6dff" />
          <stop offset="1" stopColor="#34d6f0" />
        </linearGradient>
      </defs>
      <path d="M12 22V13" stroke="url(#vg)" strokeWidth="2.4" strokeLinecap="round" />
      <path d="M12 13C12 9.5 7 9.5 7 5.5" stroke="url(#vg)" strokeWidth="2.4" strokeLinecap="round" />
      <path d="M12 13C12 9.5 17 9.5 17 5.5" stroke="url(#vg)" strokeWidth="2.4" strokeLinecap="round" />
      <circle cx="12" cy="22" r="2.1" fill="url(#vg)" />
      <circle cx="7" cy="4.6" r="2.4" fill="url(#vg)" />
      <circle cx="17" cy="4.6" r="2.4" fill="url(#vg)" />
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
