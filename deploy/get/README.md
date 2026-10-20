# get.thefoxbyte.com

The address people install from:

```sh
curl -fsSL https://get.thefoxbyte.com/install.sh | sh
```

```powershell
irm https://get.thefoxbyte.com/install.ps1 | iex
```

This folder is the whole site: a Vercel project with no build and no files of
its own. `vercel.json` rewrites `/install.sh` and `/install.ps1` to the copies
on GitHub's `main` branch, so the domain always serves exactly what is merged.
It is a rewrite, not a redirect: the script comes back on the first request,
whatever the client. `/` sends a browser to the README's install section.

`vercel.json` is generated from `brand.json` (`install_host`, `repo`) by
`make brand`. Do not edit it by hand.

## What it protects

Whoever controls this domain's DNS, or the Vercel project behind it, can serve
a script that people run as root. The binaries it installs are still checked
against the release's signed `SHA256SUMS`, but the script itself is trusted as
served. Keep two-factor sign-in on the registrar and on Vercel.

The old `raw.githubusercontent.com` URL keeps working, so existing instructions
do not break. The Windows installer's resume-after-reboot still fetches from
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
