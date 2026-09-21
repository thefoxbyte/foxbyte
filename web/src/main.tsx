import React from 'react'
import { createRoot } from 'react-dom/client'
import { createBrowserRouter, RouterProvider, NavLink, Outlet, Link, Navigate } from 'react-router-dom'
import './styles.css'
import { AuthProvider, useAuth } from './auth-context'
import AppLayout from './components/AppLayout'
import { Mark, ThemeToggle, Wordmark } from './components/brand'
import { BRAND } from './brand'

import Landing from './pages/Landing'
import Docs from './pages/Docs'
import Guide from './pages/Guide'
import Ledger from './pages/Ledger'
import Integrity from './pages/Integrity'
import Policies from './pages/Policies'
import Import from './pages/Import'
import Pipelines from './pages/Pipelines'
import PipelineEditor from './pages/PipelineEditor'
import { ConfirmProvider } from './confirm'
import Dashboard from './pages/Dashboard'
import Console from './pages/Console'
import Login from './pages/Login'
import ApiKeys from './pages/ApiKeys'

// The page title follows the brand, so a rename does not leave the old name
// in the browser tab (index.html carries it too, for the first paint).
document.title = `${BRAND.product} — ${BRAND.tagline}`

function Loading() {
  return <div className="container muted">Loading…</div>
}

// PublicLayout: the marketing pages (Home, Log in), and Guide/Docs for visitors
// who aren't signed in. The app's own pages live in AppLayout's sidebar.
function PublicLayout() {
  const { user } = useAuth()
  return (
    <>
      <header className="nav">
        <Link to="/" className="brand"><Mark /> <Wordmark /></Link>
        <div className="links">
          <NavLink to="/" end>Home</NavLink>
          <NavLink to="/guide">Guide</NavLink>
          <NavLink to="/docs">Docs</NavLink>
        </div>
        <div className="right">
          <a href={BRAND.repoUrl} target="_blank" rel="noreferrer" className="muted" style={{ fontSize: 13 }}>GitHub ↗</a>
          {user
            ? <Link to="/dashboard" className="btn ghost" style={{ padding: '6px 12px' }}>Open dashboard →</Link>
            : <NavLink to="/login" className="btn ghost" style={{ padding: '6px 12px' }}>Log in</NavLink>}
          <ThemeToggle />
        </div>
      </header>
      <main className="container"><Outlet /></main>
      <footer className="container" style={{ paddingTop: 0, paddingBottom: 0 }}>
        <div className="footer">
          <Link to="/" className="brand"><Mark size={20} /> <Wordmark /></Link>
          <span className="muted">Serverless Postgres · branches · time-travel · agent DBs</span>
          <span style={{ marginLeft: 'auto' }} className="muted">Open source — AGPL-3.0 core · Apache-2.0 clients</span>
        </div>
      </footer>
    </>
  )
}

// The app's pages: signed in, inside the sidebar layout; otherwise to Log in.
function SignedInLayout() {
  const { user, loading } = useAuth()
  if (loading) return <Loading />
  if (!user) return <Navigate to="/login" replace />
  return <AppLayout />
}

// Guide and Docs help both visitors and users: inside the app when signed in.
function HelpLayout() {
  const { user, loading } = useAuth()
  if (loading) return <Loading />
  return user ? <AppLayout /> : <PublicLayout />
}

// Every address is unchanged; only which layout wraps each page differs.
const router = createBrowserRouter([
  {
    path: '/',
    element: <PublicLayout />,
    children: [
      { index: true, element: <Landing /> },
      { path: 'login', element: <Login /> },
    ],
  },
  {
    element: <HelpLayout />,
    children: [
      { path: 'guide', element: <Guide /> },
      { path: 'docs', element: <Docs /> },
    ],
  },
  {
    element: <SignedInLayout />,
    children: [
      { path: 'dashboard', element: <Dashboard /> },
      { path: 'blackbox', element: <Ledger /> },
      { path: 'ledger', element: <Ledger /> }, // the page's original address
      { path: 'integrity', element: <Integrity /> },
      { path: 'policies', element: <Policies /> },
      { path: 'import', element: <Import /> },
      { path: 'pipelines', element: <Pipelines /> },
      { path: 'pipelines/:id', element: <PipelineEditor /> },
      { path: 'console', element: <Console /> },
      { path: 'keys', element: <ApiKeys /> },
    ],
  },
])

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AuthProvider>
      <ConfirmProvider>
        <RouterProvider router={router} />
      </ConfirmProvider>
    </AuthProvider>
  </React.StrictMode>,
)
