#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Build OpenZFS kernel modules + matching userland for the *stock* WSL2 kernel.
#
# FoxByte needs ZFS for copy-on-write branching and the WSL2 kernel ships no
# zfs module. It does not, however, need a custom kernel: WSL mounts its module
# tree as an overlay whose lower layer is the stock module set and whose upper
# layer lives on the distro's own disk (see /proc/mounts inside any distro):
#
#   none /usr/lib/modules/<rel> overlay lowerdir=/modules,upperdir=/lib/modules/<rel>/rw/upper,...
#
# So `fox setup` just drops zfs.ko/spl.ko into the fox distro's own module
# overlay and runs depmod. Nothing outside that distro is touched — no custom
# kernel, no .wslconfig edit, no effect on Docker Desktop / Rancher Desktop.
#
# A kernel tree is still built here, but only as a *compile target*: OpenZFS
# needs a configured tree with Module.symvers to build against. The kernel image
# itself is not shipped.
#
# Output:
#   dist/foxbyte-zfs-<kernelrelease>.tar.gz   modules under lib/modules/<rel>/extra
#                                               + userland under usr/local
#   dist/foxbyte-zfs.release                  the kernel release string
#
# Runs on a Linux builder or CI (including a WSL2 Ubuntu distro on the target
# machine). It is NOT run on the user's machine — install.ps1 downloads the
# artifact from the release.
#
# KERNEL_TAG MUST match the kernel WSL actually runs (`uname -r` inside WSL).
# A mismatched vermagic makes `modprobe zfs` fail — that is the single most
# likely breakage, so the build asserts it below. Bump both pins together and
# re-run the end-to-end Windows test.
KERNEL_TAG="${KERNEL_TAG:-linux-msft-wsl-6.6.87.2}"      # microsoft/WSL2-Linux-Kernel tag
ZFS_TAG="${ZFS_TAG:-zfs-2.3.9}"                          # openzfs/zfs tag
EXPECT_RELEASE="${EXPECT_RELEASE:-6.6.87.2-microsoft-standard-WSL2}"
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="$here/../../dist"
work="${WORK:-$(mktemp -d)}"
stage="$work/stage"
mkdir -p "$out" "$stage"

echo "==> deps (Debian/Ubuntu builder)"
sudo apt-get update -y
sudo apt-get install -y build-essential flex bison libssl-dev libelf-dev bc \
  python3 cpio pahole dwarves git autoconf automake libtool uuid-dev \
  zlib1g-dev libblkid-dev libudev-dev libaio-dev libattr1-dev libcurl4-openssl-dev \
  libtirpc-dev python3-dev python3-setuptools python3-cffi python3-packaging tar

echo "==> fetch kernel ($KERNEL_TAG) + zfs ($ZFS_TAG)"
git clone --depth 1 -b "$KERNEL_TAG" https://github.com/microsoft/WSL2-Linux-Kernel "$work/kernel"
git clone --depth 1 -b "$ZFS_TAG"    https://github.com/openzfs/zfs             "$work/zfs"

echo "==> configure + build the kernel with the Microsoft WSL config"
# Full build, not just modules_prepare: OpenZFS needs Module.symvers, which only
# a complete build produces.
cd "$work/kernel"
# Exporting LOCALVERSION (even empty) stops scripts/setlocalversion appending
# "+" to the release. It appends that whenever the env var is unset and the tree
# isn't a cleanly-tagged checkout — which a `clone --depth 1` always looks like,
# since `git describe --exact-match` cannot resolve the tag in a shallow clone.
# Without this the build yields "…-WSL2+", whose vermagic does not match the
# running "…-WSL2" kernel, and the modules refuse to load.
export LOCALVERSION=
cp Microsoft/config-wsl .config
make olddefconfig
make -j"$(nproc)"
KREL="$(make -s kernelrelease)"

# The vermagic contract. If this trips, the pinned KERNEL_TAG no longer matches
# the kernel WSL ships; find the tag for `uname -r` and bump KERNEL_TAG.
if [ "$KREL" != "$EXPECT_RELEASE" ]; then
	echo "error: kernel release mismatch" >&2
	echo "  built:    $KREL" >&2
	echo "  expected: $EXPECT_RELEASE  (from EXPECT_RELEASE)" >&2
	echo "  modules built here would fail to load on the target WSL kernel." >&2
	exit 1
fi
echo "    kernel release: $KREL"

echo "==> build OpenZFS against the kernel ($KREL)"
cd "$work/zfs"
./autogen.sh
# /usr/local keeps our userland clear of the distro's dpkg-managed /usr, so the
# shipped binaries and libs can never be half-upgraded by apt. systemd units are
# installed too: the pool lives on a file vdev and must be re-imported when the
# distro restarts (WSL stops idle distros), and the engine never imports it
# itself — it would otherwise fall through to `zpool create -f`.
./configure \
	--prefix=/usr/local \
	--with-linux="$work/kernel" \
	--with-linux-obj="$work/kernel" \
	--with-systemdunitdir=/usr/local/lib/systemd/system \
	--with-udevdir=/usr/local/lib/udev
make -j"$(nproc)"
make DESTDIR="$stage" INSTALL_MOD_PATH="$stage" install

echo "==> package"
# Drop libtool archives and build-tree symlinks.
find "$stage" -name '*.la' -delete
rm -f "$stage/lib/modules/$KREL/build" "$stage/lib/modules/$KREL/source"

# Split the output in two, because only half of it depends on the kernel:
#
#   modules  (zfs.ko, spl.ko)  -- tied to one exact kernel by vermagic
#   userland (zpool, zfs, libs, systemd units) -- tied only to the ZFS version
#
# The userland is baked into the prebuilt distro image, so a user downloads it
# once; only the modules are fetched per kernel. Keeping them apart is what makes
# a WSL kernel bump a 2 MB re-fetch instead of an 80 MB one. Both halves come
# from this single build, so they cannot drift in version.
#
# Stripping matters more than it sounds: zfs.ko is 89 MB built and 9 MB stripped,
# almost entirely DWARF debug info that is useless on a user's machine. The
# compressed module bundle goes from 28 MB to 2.3 MB. vermagic and modinfo
# survive --strip-debug, which is what modprobe actually checks.
strip --strip-debug "$stage/lib/modules/$KREL/extra"/*.ko
modules_dir="$work/modules"
find "$modules_dir" -mindepth 1 -delete 2>/dev/null || true
mkdir -p "$modules_dir/lib/modules/$KREL"
cp -a "$stage/lib/modules/$KREL/extra" "$modules_dir/lib/modules/$KREL/extra"

modules_tar="$out/foxbyte-zfs-modules-$KREL.tar.gz"
tar -C "$modules_dir" -czf "$modules_tar" .

# Userland is everything except the modules.
userland_dir="$work/userland"
find "$userland_dir" -mindepth 1 -delete 2>/dev/null || true
mkdir -p "$userland_dir"
cp -a "$stage/." "$userland_dir/"
rm -rf "$userland_dir/lib/modules"
userland_tar="$out/foxbyte-zfs-userland.tar.gz"
tar -C "$userland_dir" -czf "$userland_tar" .

printf '%s\n' "$KREL" > "$out/foxbyte-zfs.release"

echo
echo "zfs modules (per kernel): $modules_tar"
echo "zfs userland (shared):    $userland_tar"
echo "kernel release:           $out/foxbyte-zfs.release ($KREL)"
echo
echo "The userland is baked into the distro image by deploy/wsl-distro/build.sh."
echo "Only the modules tarball is a per-kernel release asset."
