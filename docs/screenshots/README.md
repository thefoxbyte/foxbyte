# Web console screenshots

These images are referenced by the top-level `README.md`.

| File | Page | How to reach it |
| --- | --- | --- |
| `landing.png` | the public landing page | `/`, signed out |
| `dashboard.png` | Ops dashboard | after login (default landing) |
| `ledger.png` | Blackbox | **Changes** in the sidebar |
| `console.png` | SQL console | **Console** in the sidebar |

All four were captured 4 October 2026 on the new logo and palette: dark theme,
1512 logical pixels wide at a device pixel ratio of 2, so ~3024px files, which
is what looks right on GitHub.

The data is sample data, not a real install: a fresh install has one empty
branch, which makes a dull picture. The pages are served from `web/dist` with a
canned control plane behind them — a script that answers `/auth/me`,
`/api/status`, `/api/branches`, `/api/backups`, the branch admins endpoint, the
Blackbox's entries and verify endpoints, and the query endpoint with literals, and falls back to `index.html` so the app's
own routing works.

The console is driven rather than merely loaded, because it is only worth a
picture with a query run in it. That rules out a plain
`--screenshot --virtual-time-budget`, which takes its shot before any timer of
ours has fired: the capture uses Playwright (already a dev dependency, launched
with `channel: 'chrome'` so it needs no extra browser download) to set the theme
before first paint, fill the editor, press **Run** and wait for the first result
cell.

To recapture from a real install instead, start the stack (`fox start`), open
**https://localhost:8080**, sign in, and screenshot each page at those exact
names — PNG, ~1400px wide or more.
