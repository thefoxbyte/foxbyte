# Web console screenshots

These images are referenced by the top-level `README.md`.

| File | Page | How to reach it |
| --- | --- | --- |
| `dashboard.png` | Ops dashboard | after login (default landing) |
| `ledger.png` | Blackbox | **Changes** in the sidebar |
| `console.png` | SQL console | **Console** in the sidebar |

Captured 21 Sep 2026 against the FoxByte theme, in the dark theme, at 1512
logical pixels wide with a device pixel ratio of 2 (so ~3024px files, which is
what looks right on GitHub). The data in them is sample data, not a real
install: the pages were served by the dev server with a canned control plane
behind it, because screenshots of a fresh install show one empty branch.

To recapture from a real install, start the stack (`fox start`), open
**https://localhost:8080**, sign in, and screenshot each page at those exact
names — PNG, ~1400px wide or more.
