# Windows Port — Status

This branch (`feat/windows-support`) adds native Windows support to FoxByte. On Windows the engine
runs in a dedicated **WSL2** distro named `foxbyte` — the direct analog of the Lima VM used on
macOS — and `bb.exe` forwards every engine command into it, marking forwarded processes with
`FOX_IN_GUEST=1` so the in-distro `fox` runs the engine in-process.

Read `docs/windows-setup.md` (the user-facing guide) first.

## Architecture: no custom kernel, no machine-wide changes

The engine needs ZFS for copy-on-write branching, and the stock WSL2 kernel ships no `zfs` module.
An earlier revision of this port solved that by building a ZFS-enabled WSL2 kernel and pointing
`%UserProfile%\.wslconfig` at it. **That is no longer how it works, and the kernel is not built or
shipped.**

WSL mounts its module tree as an overlay: the stock module set is a read-only lower layer, and the
writable upper layer lives on each distro's own disk.

```
$ grep lib/modules /proc/mounts
none /usr/lib/modules/6.6.87.2-microsoft-standard-WSL2 overlay rw,lowerdir=/modules,
     upperdir=/lib/modules/6.6.87.2-microsoft-standard-WSL2/rw/upper,...
```

Writes there persist across `wsl --terminate` and are private to the distro. So `fox setup` drops
`zfs.ko` into the `foxbyte` distro's own module tree and runs `depmod`. Consequences:

- `.wslconfig` is never written. No `kernel=`, no `kernelModules=`.
- Docker Desktop, Rancher Desktop, and every other distro are untouched — this is true by
  construction, not by testing.
- The shipped artifact is a ~30 MB tarball, not a kernel image or a modules VHDX.
- The modules are tied to one exact kernel release, which is the one real constraint. See below.

## The vermagic contract

Modules only load against the kernel they were built for. Two guards:

1. `deploy/wsl-zfs/build.sh` asserts `make -s kernelrelease` equals `EXPECT_RELEASE` and fails the
   build otherwise. This assertion has already earned its keep: the first build produced
   `6.6.87.2-microsoft-standard-WSL2+`, whose modules would not have loaded. `setlocalversion`
   appends `+` when `LOCALVERSION` is unset and the tree isn't cleanly tagged — and a
   `clone --depth 1` always looks untagged, since `git describe --exact-match` can't resolve the tag
   in a shallow clone. The build exports an empty `LOCALVERSION` to suppress it; an empty
   `.scmversion` does not work. Do not downgrade the assertion to a warning.
2. The artifact is named for that release (`foxbyte-zfs-<rel>.tar.gz`), and both `fox setup`
   (`zfsBundleName` in `internal/host/host_wsl.go`) and `install.ps1` (`Get-ZfsBundleName`) look it
   up by `uname -r`. A WSL kernel bump therefore surfaces as a missing file with an actionable
   message, not as a module that silently refuses to load.

`verifyZFS` runs on **every** `fox setup`, not just the first, because a WSL update can move the
kernel under an already-provisioned distro.

## Key files

- `internal/host/host_windows.go` — the WSL2 orchestration (import, provision, ZFS install, verify).
- `internal/host/host_wsl.go` (+ `_test.go`) — pure helpers, unit-tested on any OS (TC1.*).
- `deploy/wsl-zfs/build.sh` — the ZFS bundle build; `make wsl-zfs`.
- `deploy/install.ps1` — installer; `deploy/install.Tests.ps1` — Pester.
- `.github/workflows/wsl-zfs.yml` — builds and attaches the bundle on a tag.

## WSL2 behaviours this port had to work around

Each of these was found by running the thing, and each has a fix in
`host_windows.go`. They are listed because they are non-obvious and will look
like new bugs if someone changes that file without knowing them.

**A file vdev cannot back a pool.** `zpool create` on a plain file fails on the
WSL2 kernel with `cannot create 'foxbyte': no such pool or dataset`; the same
file behind a loop device works. Setup attaches the pool image to a loop device
and points the engine at it with `FOX_ZPOOL_DEVICE`.

**Loop device numbers are global and contended.** Every WSL2 distro shares one
kernel, so `/dev/loop*` is a single namespace — Docker Desktop and Rancher
Desktop take devices from it. A hardcoded number fails with `EBUSY`. Worse, a
distro that is unregistered while its pool is attached leaves the binding behind
for as long as the VM lives, still advertising the same
`/var/lib/dbpool-zpool.img` path. Matching by path therefore adopts a device
backed by a deleted filesystem, and the pool faults and suspends on first write.
`zpool-up.sh` matches on the backing **inode**, detaches such corpses, and
publishes the live device as the stable symlink `/dev/foxbyte-pool`.

**Never detach a loop device that a pool is using.** It suspends pool I/O, and a
suspended pool can wedge the whole WSL VM — `wsl --shutdown` then hangs and only
`Restart-Service WSLService` (elevated) or a reboot clears it. `zpool-up.sh`
therefore refuses to continue when it finds the pool `SUSPENDED`, telling the
user to terminate the distro: a fresh boot drops every binding and import, after
which normalisation runs clean.

**Import from our device, never a scan of `/dev`.** `zpool import -d /dev` reads
every device, including a stale binding left by an unregistered distro, and the
old pool's label is still on it. ZFS then imports onto a device whose backing
file no longer exists, which faults on the first write and suspends the pool.
The import is scoped to `/dev/foxbyte-pool`. This one is subtle and cost
several debugging cycles — do not widen it back to `-d /dev`.

**WSL leaves `/` mount propagation private.** A normal systemd boot makes it
`rshared`. Sandboxed systemd services (`ProtectSystem=strict`, e.g.
`systemd-timedated`) clone the mount tree at start-up, so they hold a read-only
copy of every branch dataset that existed then. With private mounts, ZFS's
unmount cannot propagate into those namespaces, the copy pins the dataset, and
`fox branch delete` fails with `dataset is busy` for any branch that existed at
boot. Setup makes the pool's mounts `rshared`, restoring normal Linux behaviour.
Note the direction: making them *more* private makes this worse.

**The Windows PATH is injected into distros.** On a machine with Docker Desktop,
`command -v docker` inside a fresh distro resolves to `docker.exe` and the distro
looks provisioned when it has no Docker at all. The distro sets
`appendWindowsPath=false`, and the probe looks for `/usr/bin/dockerd`.

**`wsl.exe -d <distro> -- cmd` does not wait for boot.** It starts a stopped
distro and runs immediately, long before systemd has started Docker. Since WSL
stops idle distros, the first command after an idle timeout would fail with
"cannot reach the Docker daemon". `forwardStdin` waits for systemd on a cold
start — the macOS path gets this free from `limactl start`.

## Two engine gaps the launcher works around

The engine is not modified (`internal/branch`, `internal/proxy`, … run unchanged in WSL2). Two of its
assumptions don't hold for an installed Windows user, and setup compensates:

- **Image build context.** `ensureImage()` finds `docker/postgres` relative to the working
  directory, which finds nothing for someone who installed `fox` rather than cloning the repo.
  `stageImageContext` copies the context into the distro and the forwarded environment sets
  `FOX_IMAGE_CONTEXT` (an env var the engine already reads).
- **Pool import.** The engine never runs `zpool import`; `ensurePool` falls through to
  `zpool create -f`, which on an un-imported existing pool would destroy it. WSL stops idle distros,
  so this is reached routinely on Windows. `foxbyte-zpool.service` imports the pool at every boot
  (ZFS's own `zfs-import-cache.service` cannot: a loop-backed pool writes no `/etc/zfs/zpool.cache`,
  so its `ConditionPathExists` never holds). If that unit cannot import a pool the image already
  contains, it fails deliberately and `checkZpoolUnit` refuses to run the engine — that refusal is
  the only thing standing between an unimportable pool and `zpool create -f` overwriting it.
  **Test a stop/restart cycle whenever this area changes.**
- **First-start readiness.** The engine connects as soon as the Postgres socket appears, but the
  container entrypoint's temporary server is still running initdb, so psql gets
  `database "foxbyte" does not exist`. initdb on a fresh ZFS pool is slow enough to lose that race
  every time here, so `setupWindows` retries `start` once. Fixing the readiness check in the engine
  would let that retry be deleted.

## Guardrails

- **Do not change the engine.** If something's wrong, it's almost certainly in `host_windows.go` or
  the ZFS bundle.
- Keep side-effecting `wsl.exe` calls thin; put logic in pure helpers in `host_wsl.go` and unit-test
  it — that's why TC1.* run without a Windows host.
- `zfsBundleName` (Go) and `Get-ZfsBundleName` (PowerShell) must agree; both are unit-tested.
- Verify `go test ./internal/host` passes natively on Windows too.
