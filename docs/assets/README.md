<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Recording the README demo

The README reserves `docs/assets/demo.gif` for a short recording of a branch
being created. The file is not in the repository until someone records it.
The tape is [`demo.tape`](demo.tape). Nothing in CI runs it: a GIF of a live
engine does not belong on every pull request.

You need a running FoxByte (`fox start` on Linux, or the installer on macOS
and Windows) and `fox` on `PATH`. The tape creates a branch named `demo`,
runs one `CREATE TABLE`, shows the Blackbox, and deletes the branch. The
statement is recorded on `demo`. Deleting `demo` drops that branch. `main`
is not changed.

## vhs

[vhs](https://github.com/charmbracelet/vhs) records a terminal to a GIF from
a tape file. Install it, then from the repository root:

```bash
vhs docs/assets/demo.tape
```

That writes `docs/assets/demo.gif`. Commit the GIF and uncomment the image
in the README (the HTML comment marked `DEMO GIF PLACEHOLDER`). Watch the
GIF before you commit it: a tape that types faster than the engine answers
will show a half-drawn prompt.

`Output` in the tape is `docs/assets/demo.gif`, relative to the working
directory. Run `vhs` from the repository root.

## asciinema, then agg

If you would rather record a real session than a scripted tape:

```bash
asciinema rec --command "fox branch create demo && fox blackbox demo && fox branch delete demo" docs/assets/demo.cast
agg --font-size 18 docs/assets/demo.cast docs/assets/demo.gif
```

[agg](https://github.com/asciinema/agg) renders the cast to a GIF. Delete
`docs/assets/demo.cast` afterwards unless you mean to keep the source. The
same README placeholder applies.

Do not put API keys, the setup token, or `~/.fox/secrets.json` in the
recording. `fox branch create` prints a connection string with `<API_KEY>`
still to fill in, which is safe. A `psql` line with a real key is not.
