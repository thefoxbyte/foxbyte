# get.thefoxbyte.com

The address people install from:

```sh
curl -fsSL https://get.thefoxbyte.com/install.sh | sh
```

```powershell
irm https://get.thefoxbyte.com/install.ps1 | iex
```

This folder is the whole site: a Vercel project with no build and no files of
its own. Today `vercel.json` rewrites `/install.sh` and `/install.ps1` to the
copies on GitHub's `main` branch, so the domain serves exactly what is merged.
`/` sends a browser to the README's install section.

**Planned switch (finding SUP-3).** The installer carries the pinned release
keys, so serving it from `main` makes those keys only as safe as the newest
merged commit. From the next release on, release.yml uploads `install.sh` and
`install.ps1` as release assets, listed in the signed `SHA256SUMS`. Once a
release that carries them is the latest one, change `vercelFile` in
`internal/brand/gen/gen.go` to redirect both paths to
`https://github.com/thefoxbyte/foxbyte/releases/latest/download/<script>`
(`curl -L` and `irm` both follow redirects), run `make brand`, and update
`TestInstallHostServesTheInstallers`. Switching earlier would make the
one-liner answer 404, because v2.2.1 and older releases have no installer
assets.

`vercel.json` is generated from `brand.json` (`install_host`, `repo`) by
`make brand`. Do not edit it by hand.

## What it protects

Whoever controls this domain's DNS, or the Vercel project behind it, can serve
a script that people run as root. The binaries it installs are still checked
against the release's signed `SHA256SUMS`, but the script itself is trusted as
served. Keep two-factor sign-in on the registrar and on Vercel.

Release assets can be replaced by anything holding `contents: write` on the
repository, so keep the default workflow token read-only and the signing secrets
in the `release` environment (README, "Release signing"). The installers are
listed in the signed `SHA256SUMS`, so a copy can be checked against it.

The old `raw.githubusercontent.com` URL on `main` keeps working, so existing
instructions do not break, but it serves `main`. The Windows installer's
resume-after-reboot fetches the installer of the release being installed from
GitHub directly.

## Setting it up (once)

1. In Vercel, add a project from this repository with **Root Directory**
   `deploy/get`, framework preset **Other**, and no build command.
2. In the project's **Domains**, add `get.thefoxbyte.com`.
3. At GoDaddy (the DNS host for `thefoxbyte.com`), add the record Vercel
   shows, usually `CNAME get -> cname.vercel-dns.com`.
4. Check it:

   ```sh
   curl -fsSL https://get.thefoxbyte.com/install.sh | head -3
   ```
