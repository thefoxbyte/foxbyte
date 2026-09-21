# FoxByte on Windows

FoxByte's engine is Linux-only (ZFS + Docker + Postgres). On Windows it runs inside a dedicated
**WSL2** distro — the direct analog of the Lima VM used on macOS. The native `fox.exe` launcher
forwards every engine command into that distro, so day to day you just type `fox …`.

## Prerequisites

- **Windows 10 (21H2+) or Windows 11**
- **Virtualization** enabled in the BIOS/UEFI

That's it. You do **not** need to install WSL yourself, and you do **not** need Ubuntu or any other
Linux distribution — FoxByte installs WSL if it's missing and brings its own dedicated distro.

## Install

One command, **in PowerShell** — not Command Prompt. `irm` and `iex` are PowerShell commands (`irm`
is the alias for `Invoke-RestMethod`); in cmd.exe you get `irm is not recognized`.

```powershell
irm https://raw.githubusercontent.com/thefoxbyte/foxbyte/main/deploy/install.ps1 | iex
```

It does the whole job:

1. installs the WSL components if absent (asking for admin once, **without** installing a Linux
   distribution) — if Windows needs a restart to finish, it says so and resumes automatically after;
2. downloads `fox.exe` into `%LOCALAPPDATA%\Programs\foxbyte` and adds it to your PATH — including
   the current window, so `fox` works immediately;
3. runs `fox setup`, which imports the dedicated `fox` distro, installs Docker, downloads and
   installs the OpenZFS module matching **your** WSL kernel, verifies `modprobe zfs` actually works,
   and brings the stack up.

Output is a short progress list; the full detail goes to
`%LOCALAPPDATA%\Programs\foxbyte\install.log`, which is named in any error.

If PowerShell blocks the script (`running scripts is disabled on this system`), allow it for this
session first, then re-run the install:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

To install without running setup, or without the admin prompt, set `FOX_NO_SETUP=1` or
`FOX_NO_ELEVATE=1` before running the command.

After that, use FoxByte exactly as on macOS/Linux — `fox branch create`, `fox import`, `fox status`,
etc. Services are reachable from Windows on `localhost` (gateway `:6432`, control API `:8080`, agent
API `:8088`, MinIO console `:9001`) via WSL2 localhost-forwarding.

## Your other WSL distros are not touched

The stock WSL2 kernel ships **no ZFS module**, and ZFS is what powers FoxByte's instant
copy-on-write branches. FoxByte does **not** solve that by replacing your kernel.

WSL mounts its module tree as an overlay — the stock modules are a read-only lower layer, and the
upper layer lives on each distro's own disk. You can see it in any distro:

```
$ grep lib/modules /proc/mounts
none /usr/lib/modules/6.6.87.2-microsoft-standard-WSL2 overlay rw,lowerdir=/modules,
     upperdir=/lib/modules/6.6.87.2-microsoft-standard-WSL2/rw/upper,...
```

So `fox setup` writes `zfs.ko` into the **`fox` distro's** upper layer and runs `depmod`. Your
`%UserProfile%\.wslconfig` is never modified, no `kernel=` or `kernelModules=` line is added, and
Docker Desktop, Rancher Desktop, and your other distros keep running the stock kernel untouched.

The trade-off is that the modules are tied to one exact kernel version. `fox setup` reads `uname -r`
and looks for the bundle built for it by name, so a WSL kernel bump produces a clear "no ZFS bundle
for this WSL kernel" message rather than a module that silently refuses to load.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `irm is not recognized` / `iex is not recognized` | You're in Command Prompt. Open **PowerShell** and run the install command there. |
| `The term '# ' is not recognized` at line 1 | A cached copy of an older `install.ps1` that had a UTF-8 BOM. The current installer is pure ASCII with no BOM, which is the only form that works both piped to `iex` and run as a file. Re-run to fetch the fixed copy. |
| `running scripts is disabled on this system` | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then re-run the install. |
| `The request was aborted: The connection was closed unexpectedly` | Windows PowerShell 5.1 didn't negotiate TLS 1.2. The installer now sets it itself; if you hit this running an older copy, re-run the current one-liner. |
| `fox is not recognized` after install | The installer adds it to the current window's PATH as well as persisting it, so this should not happen. In a window opened *before* installing: `$env:Path += ";$env:LOCALAPPDATA\Programs\foxbyte"`. |
| The install stops asking you to restart | Enabling the WSL components needs a reboot. Restart; the installer resumes on its own. If it doesn't, run the one-liner again. |
| `no ZFS module bundle published for this WSL kernel` | This release has no module built for your kernel (`wsl -e uname -r`). See *Supported WSL kernels* below — a maintainer can add yours in about an hour. Do **not** `wsl --update`: that moves the kernel further ahead, not closer. |
| `WSL is present but not healthy` | Enable virtualization in the BIOS and the *Virtual Machine Platform* feature; `wsl --update`. |
| `ZFS is not usable in the "fox" distro` | The staged modules were built for a different kernel. Check `wsl -d fox -- uname -r` against the bundle filename in `%LOCALAPPDATA%\Programs\foxbyte`. |
| `systemd did not finish booting` | `wsl --terminate fox`, then re-run `fox setup`. |
| `the FoxByte ZFS pool device is not ready` | Deliberate stop: the pool could not be imported, and FoxByte will not run the engine in case it recreates the pool over your data. Run `wsl --terminate fox` and retry; if it persists, see `journalctl -u dbpool-storage.service` inside the distro. |
| `pool I/O is currently suspended` | The pool lost its backing device. `wsl --terminate fox` and re-run `fox setup`; the pool is re-imported at boot. |
| `wsl` commands hang and `wsl --shutdown` never returns | A suspended ZFS pool can wedge the WSL VM. In an **Administrator** PowerShell: `Restart-Service WSLService -Force` (a reboot also clears it). |

## Uninstall

```powershell
wsl --unregister fox                           # remove the distro + its data
wsl --shutdown                                   # release its loop device
Remove-Item -Recurse "$env:LOCALAPPDATA\Programs\foxbyte"
Remove-Item -Recurse "$env:LOCALAPPDATA\foxbyte"
```

Nothing else to undo — FoxByte made no machine-wide WSL changes.

> **The `wsl --shutdown` matters if you plan to reinstall.** Unregistering a
> distro does not release the loop device its ZFS pool was using: that binding
> belongs to the WSL virtual machine, which all distros share, and it survives
> until the VM restarts. A reinstall in the same VM lifetime would otherwise find
> a device pointing at the deleted pool image. `fox setup` detects this and stops
> with instructions rather than proceeding, but a `wsl --shutdown` avoids it.

## Supported WSL kernels (maintainers)

ZFS modules only load against the exact kernel they were built for, so a release
must ship a bundle per kernel its users run. Microsoft ships new WSL kernels
regularly and `wsl --update` moves people onto them, so this list needs
maintaining — a user on an uncovered kernel gets a clear
*"no ZFS module bundle published for this WSL kernel"* and cannot install.

The list lives in the `modules` matrix in
[`.github/workflows/wsl-distro.yml`](../.github/workflows/wsl-distro.yml). Each
entry is a `microsoft/WSL2-Linux-Kernel` tag; the expected `uname -r` is derived
from it, and the build fails loudly if they disagree. One entry is marked
`primary` — its ZFS userland is baked into the distro image. The userland is
identical across kernels (same `ZFS_TAG`), so only one entry needs it.

Everything else in the image is kernel-independent, which is why adding a kernel
costs one ~2 MB bundle rather than another 740 MB image.

**To cover a new kernel on an existing release**, run the **wsl-zfs** workflow
manually with the kernel tag and the release tag. It builds just that bundle
(~1 hour), attaches it, and updates `SHA256SUMS` — no full rebuild. Add the
kernel to the matrix as well, so future releases keep covering it.

## Building the ZFS bundle (maintainers)

The ZFS artifact is produced on a Linux builder / CI (a WSL2 Ubuntu distro works), not on the user's
machine:

```bash
make wsl-zfs
```

This builds the Microsoft WSL2 kernel tree purely as a **compile target** (OpenZFS needs a configured
tree with `Module.symvers`), builds OpenZFS against it, and packages the modules plus matching
userland as `dist/foxbyte-zfs-<kernelrelease>.tar.gz`. The kernel image itself is not shipped.

Pin `KERNEL_TAG` in `deploy/wsl-zfs/build.sh` to the tag matching the kernel WSL ships, and
`EXPECT_RELEASE` to that kernel's `uname -r`; the build **fails loudly** on a mismatch, because
modules built for the wrong kernel are the single most likely way this breaks. Bump `KERNEL_TAG` and
`ZFS_TAG` together and re-run the end-to-end Windows test after any bump.

> **Gotcha:** the build exports an empty `LOCALVERSION`. `scripts/setlocalversion` appends `+` to
> the release whenever that variable is unset and the tree isn't a cleanly-tagged checkout — which
> a `git clone --depth 1` always looks like, because `git describe --exact-match` can't resolve the
> tag in a shallow clone. Without it you get `…-microsoft-standard-WSL2+`, whose vermagic will not
> load on the real `…-microsoft-standard-WSL2` kernel. (An empty `.scmversion` does *not* fix this.)
> The `EXPECT_RELEASE` assertion is what catches it, so do not weaken it into a warning.
