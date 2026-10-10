# Web console screenshots

These images are referenced by the top-level `README.md`.

| File | Page | How to reach it |
| --- | --- | --- |
| `landing.png` | the public landing page | `/`, signed out |
| `dashboard.png` | Ops dashboard | after login (default landing) |
| `ledger.png` | Blackbox | **Changes** in the sidebar |
| `console.png` | SQL console | **Console** in the sidebar |
| `realtime.png` | Realtime | **Realtime** in the sidebar |

## Retaking them

```
make screenshots
```

All five, from one harness, in about twenty seconds. Commit whatever changed.

That command is the point of this directory's history. The previous retake was
done by hand and the method was written down here without being shipped, so
`ledger.png` was left behind on 21 September showing the old fox-head mark and
the orange accent — this file said so, and it stayed that way for three weeks,
because retaking one picture meant rebuilding the harness first. A picture of
the product is documentation, and documentation that is expensive to regenerate
goes stale.

## How it works

`scripts/screenshots.mjs` serves `web/dist` with a canned control plane behind
it and drives Chrome through Playwright, which is already a dev dependency of
`web/` (`channel: 'chrome'`, so no extra browser download).

The data is invented, not a real install: a fresh install has one empty branch,
which makes a dull and unrepresentative picture. The canned answers are chosen
to show what each page is *for* — a Blackbox with an agent's change beside a
person's, one blocked and one flagged; a realtime table list with one of each
rung of the ladder, including the one change that has an ongoing cost.

Two pages are driven rather than merely loaded. The console is only worth a
picture with a query run in it, so the harness fills the editor, presses **Run**
and waits for a result cell. That rules out a plain `--screenshot
--virtual-time-budget`, which takes its shot before any timer of ours has fired.

The theme is set before first paint, or the shot catches the light theme behind
a dark one.

All of them: dark theme, 1512 logical pixels wide at a device pixel ratio of 2,
so ~3024px files, which is what looks right on GitHub.

## If a page changes shape

The harness answers the console's endpoints with literals, so a renamed field
shows up as an empty column rather than an error. Both of those have happened:
the Blackbox reads `command_tag` and `object_identity`, and its status pill is
keyed on the *uppercase* value — a first draft used `kind`/`object` and
lowercase statuses, which rendered an empty CHANGE column and colourless
badges. **Look at the PNGs before committing them.**

## From a real install instead

Start the stack (`fox start`), open **https://localhost:8080**, sign in, and
screenshot each page at those exact names — PNG, ~1400px wide or more. Worth
doing if you want real data in the picture; the harness is for keeping them
current.
