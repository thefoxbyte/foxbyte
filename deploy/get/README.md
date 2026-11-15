# get.thefoxbyte.com

The address people install from:

```sh
curl -fsSL https://get.thefoxbyte.com/install.sh | sh
```

```powershell
irm https://get.thefoxbyte.com/install.ps1 | iex
```

This folder is the whole site: a Vercel project with no build and no files of
its own. `vercel.json` redirects `/install.sh` and `/install.ps1` to the copies
published with the latest release
(`https://github.com/thefoxbyte/foxbyte/releases/latest/download/install.sh`),
which release.yml uploads and lists in the signed `SHA256SUMS`. `/` sends a
browser to the README's install section.

Why a release and not `main` (finding SUP-3): the installer is what carries the
pinned release keys, so serving it from `main` made those keys only as safe as
the newest merged commit. A release's copy is the one its tag was built and
signed from, and a prerelease (a release still being verified) is never
"latest". A static Vercel config cannot name "the latest tag" itself, so it
redirects to GitHub's latest-release download, which redirects again to the
file; `curl -L` and `irm` both follow. The installer then resolves "latest" to
a tag of its own and installs everything from that one release.

`vercel.json` is generated from `brand.json` (`install_host`, `repo`) by
`make brand`. Do not edit it by hand.

The first deploy of this redirect needs the installers on the current latest
release, which predates them: `gh release upload <tag> deploy/install.sh
deploy/install.ps1`. Every release after that carries its own.

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
