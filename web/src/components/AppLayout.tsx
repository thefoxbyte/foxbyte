import { useEffect, useState, type ComponentType } from 'react'
import { Link, Outlet, useLocation } from 'react-router-dom'
import { logout as apiLogout } from '../api'
import { useAuth } from '../auth-context'
import { getTheme, toggleTheme } from '../theme'
import { Mark, Wordmark } from './brand'
import { BRAND } from '../brand'
import * as I from './icons'

type NavItem = {
  to: string
  label: string
  icon: ComponentType<I.IconProps>
  also?: string[] // other paths that belong to this page (e.g. an old address)
}
type NavSection = { label: string; items: NavItem[] }

// The signed-in app's navigation. A new page is one entry here: it appears in
// the sidebar under its section instead of crowding a single top bar.
export const APP_NAV: NavSection[] = [
  { label: 'Overview', items: [{ to: '/dashboard', label: 'Dashboard', icon: I.IconDashboard }] },
  {
    label: 'Data',
    items: [
      { to: '/console', label: 'Console', icon: I.IconConsole },
      { to: '/import', label: 'Import', icon: I.IconImport },
      { to: '/pipelines', label: 'Pipelines', icon: I.IconPipelines },
    ],
  },
  {
    label: 'Blackbox',
    items: [
      { to: '/blackbox', label: 'Changes', icon: I.IconBlackbox, also: ['/ledger'] },
      { to: '/integrity', label: 'Integrity', icon: I.IconIntegrity },
      { to: '/policies', label: 'Policies', icon: I.IconPolicies },
    ],
  },
  { label: 'Account', items: [{ to: '/keys', label: 'API keys', icon: I.IconKey }] },
  {
    label: 'Help',
    items: [
      { to: '/guide', label: 'Guide', icon: I.IconGuide },
      { to: '/docs', label: 'Docs', icon: I.IconDocs },
    ],
  },
]

function matches(path: string, base: string) {
  return path === base || path.startsWith(base + '/')
}

function isActive(item: NavItem, path: string) {
  return matches(path, item.to) || (item.also ?? []).some(a => matches(path, a))
}

function currentPage(path: string) {
  for (const section of APP_NAV) {
    for (const item of section.items) {
      if (isActive(item, path)) return { section: section.label, label: item.label }
    }
  }
  return null
}

// The collapsed/expanded choice is a per-browser convenience; storage may be
// unavailable (private windows), in which case the sidebar starts expanded.
const COLLAPSED_KEY = 'bb.sidebar.collapsed'
function readCollapsed() {
  try { return localStorage.getItem(COLLAPSED_KEY) === '1' } catch { return false }
}
function writeCollapsed(value: boolean) {
  try { localStorage.setItem(COLLAPSED_KEY, value ? '1' : '0') } catch { /* not persisted */ }
}

// AppLayout is the signed-in shell: a sidebar with the app's sections, a slim top
// bar with where you are, and the page. On narrow screens the sidebar becomes a
// drawer opened from the top bar.
export default function AppLayout() {
  const { user, setUser } = useAuth()
  const { pathname } = useLocation()
  const [collapsed, setCollapsed] = useState(readCollapsed)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [theme, setTheme] = useState(getTheme())

  useEffect(() => { setDrawerOpen(false) }, [pathname])
  useEffect(() => {
    if (!drawerOpen) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setDrawerOpen(false) }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [drawerOpen])

  const toggleCollapsed = () => setCollapsed(c => { writeCollapsed(!c); return !c })
  const logout = async () => {
    await apiLogout().catch(() => {})
    setUser(null)
    location.assign('/login')
  }
  const page = currentPage(pathname)
  const tip = (label: string) => (collapsed ? label : undefined)

  return (
    <div className={'app-shell' + (collapsed ? ' collapsed' : '')}>
      <aside id="app-sidebar" className={'sidebar' + (drawerOpen ? ' open' : '')} aria-label="Main navigation">
        <div className="sb-head">
          <Link to="/dashboard" className="brand" title={BRAND.product}>
            <Mark size={24} />
            <b className="sb-text"><Wordmark /></b>
          </Link>
          <button className="icon-btn sb-close" aria-label="Close menu" onClick={() => setDrawerOpen(false)}>
            <I.IconClose />
          </button>
        </div>

        <nav className="sb-nav">
          {APP_NAV.map(section => (
            <div className="sb-section" key={section.label}>
              <div className="sb-label">{section.label}</div>
              {section.items.map(item => {
                const active = isActive(item, pathname)
                const ItemIcon = item.icon
                return (
                  <Link key={item.to} to={item.to} className={'sb-link' + (active ? ' active' : '')}
                    aria-current={active ? 'page' : undefined} title={tip(item.label)}>
                    <ItemIcon className="sb-icon" />
                    <span className="sb-text">{item.label}</span>
                  </Link>
                )
              })}
            </div>
          ))}
        </nav>

        <div className="sb-foot">
          <a className="sb-link" href={BRAND.repoUrl} target="_blank" rel="noreferrer" title={tip('GitHub')}>
            <I.IconExternal className="sb-icon" />
            <span className="sb-text">GitHub</span>
          </a>
          <button className="sb-link" onClick={() => setTheme(toggleTheme())}
            title={tip(theme === 'dark' ? 'Light mode' : 'Dark mode')}>
            {theme === 'dark' ? <I.IconSun className="sb-icon" /> : <I.IconMoon className="sb-icon" />}
            <span className="sb-text">{theme === 'dark' ? 'Light mode' : 'Dark mode'}</span>
          </button>
          <div className="sb-user" title={user?.email}>
            <span className="sb-avatar" aria-hidden>{(user?.email || '?').slice(0, 1).toUpperCase()}</span>
            <span className="sb-text sb-email">{user?.email}</span>
          </div>
          <button className="sb-link" onClick={logout} title={tip('Log out')}>
            <I.IconLogout className="sb-icon" />
            <span className="sb-text">Log out</span>
          </button>
          <button className="sb-link sb-collapse" onClick={toggleCollapsed}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'} title={tip('Expand sidebar')}>
            {collapsed ? <I.IconExpand className="sb-icon" /> : <I.IconCollapse className="sb-icon" />}
            <span className="sb-text">Collapse</span>
          </button>
        </div>
      </aside>

      {drawerOpen && <div className="sb-overlay" onClick={() => setDrawerOpen(false)} />}

      <div className="app-main">
        <header className="app-topbar">
          <button className="icon-btn sb-menu" aria-label="Open menu" aria-controls="app-sidebar"
            aria-expanded={drawerOpen} onClick={() => setDrawerOpen(true)}>
            <I.IconMenu />
          </button>
          {page && (
            <div className="crumbs">
              <span className="muted">{page.section}</span>
              <span className="sep" aria-hidden>/</span>
              <span>{page.label}</span>
            </div>
          )}
        </header>
        <main className="app-content"><Outlet /></main>
      </div>
    </div>
  )
}
