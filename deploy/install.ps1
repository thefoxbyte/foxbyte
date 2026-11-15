# SPDX-License-Identifier: Apache-2.0
#
# FoxByte Windows installer: one command, from a machine with nothing on it to
# a running database. Installs WSL if absent (no Linux distribution required),
# installs the fox launcher, and runs `fox setup`.
#
# Usage (PowerShell):
#   irm https://get.thefoxbyte.com/install.ps1 | iex
#
# This file must stay free of a UTF-8 BOM: `irm | iex` pipes the BOM into the
# parser, which then reports `The term '# ' is not recognized` on line 1.
#
# Every FoxByte download is checked against the release's SHA256SUMS before it
# is kept -- these files run as root inside the distro. Anything that cannot be
# verified stops the install (FOX_NO_VERIFY=1 deliberately skips the check).
#
# Env overrides: FOX_VERSION (default "latest"), FOX_REPO, FOX_PREFIX,
# FOX_EDITION ("standard" or "enterprise"; default standard),
# FOX_NO_SETUP (skip `fox setup`), FOX_NO_ELEVATE (never prompt for admin),
# FOX_NO_VERIFY (skip checksum verification), FOX_ALLOW_UNSIGNED (install a
# release whose signature cannot be checked; checksums are still checked).
#
# The Enterprise edition (paid) is a different binary from the same release and
# needs a licence to unlock its features:
#   $env:FOX_EDITION = 'enterprise'; irm .../install.ps1 | iex

$ErrorActionPreference = 'Stop'

# Windows PowerShell 5.1 does not negotiate TLS 1.2 by default, and GitHub
# requires it -- without this, downloads fail with "the connection was closed
# unexpectedly" partway through.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

# generated from brand.json -- do not edit by hand, run `make brand`
$Product = "FoxByte"
$Cli = "fox"
$Slug = "foxbyte"
$EnvPrefix = "FOX_"
$StateDir = ".fox"
$DefaultRepo = "thefoxbyte/foxbyte"
$InstallUrl = "https://get.thefoxbyte.com/install.ps1"
# end generated

$Repo    = if ($env:FOX_REPO)    { $env:FOX_REPO }    else { $DefaultRepo }
$Version = if ($env:FOX_VERSION) { $env:FOX_VERSION } else { 'latest' }
$Prefix  = if ($env:FOX_PREFIX)  { $env:FOX_PREFIX }  else { "$env:LOCALAPPDATA\Programs\$Slug" }

# Which edition to fetch. The asset names carry it; the installed command is
# `fox.exe` either way, so nothing downstream has to know which one is here.
# The launcher and the engine inside the WSL distro must match, or the launcher
# would offer commands the engine does not have.
$Edition = if ($env:FOX_EDITION) { $env:FOX_EDITION } else { 'standard' }
switch ($Edition) {
    'standard'   { $BinName = $Cli }
    'enterprise' { $BinName = "$Cli-enterprise" }
    default { throw "unknown FOX_EDITION '$Edition' (expected 'standard' or 'enterprise')" }
}
$HostAsset   = "$BinName-windows-amd64.exe"
$EngineAsset = "$BinName-linux-amd64"

# The P-256 release key's public half: base64 of the 65-byte uncompressed
# point (0x04, X, Y). Releases sign SHA256SUMS with it as well as with Ed25519,
# because Windows PowerShell and .NET can check ECDSA P-256 and cannot check
# Ed25519 (finding SUP-5). Written by `go run ./cmd/releasesign generate-p256
# --write`, with fox's and install.sh's copies.
#
# Empty until the maintainer makes that key (README, "Verifying a release").
# While it is empty this installer checks checksums only, and says so; once it
# is set, a release whose signature does not check is refused (unless
# FOX_ALLOW_UNSIGNED=1).
$ReleaseP256PublicKey = ''

# The first release whose signed SHA256SUMS names its own version (finding
# SUP-4). Keep in step with internal/update/select.go and install.sh.
$FirstVersionedRelease = '2.3.0'

# Ubuntu publishes WSL rootfs tarballs directly; pulling from upstream keeps our
# own release small and avoids redistributing Ubuntu. Note the path: only
# /wsl/releases/<series>/current/ carries the tarballs -- /wsl/<series>/current/
# holds manifests alone.
$RootfsBase = 'https://cloud-images.ubuntu.com/wsl/releases/noble/current'
$RootfsName = 'ubuntu-noble-wsl-amd64-wsl.rootfs.tar.gz'
$RootfsUrl  = if ($env:FOX_ROOTFS_URL) { $env:FOX_ROOTFS_URL } else { "$RootfsBase/$RootfsName" }

$script:Step = 0
$script:Steps = 5

function Write-Step([string]$Message) {
    $script:Step++
    Write-Host ("  [{0}/{1}] {2}" -f $script:Step, $script:Steps, $Message)
}

# Resolve-Arch maps the OS architecture to our release-asset arch token.
function Resolve-Arch {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { 'amd64' }
        'ARM64' { 'arm64' }
        default { 'amd64' }
    }
}

# Get-FoxAsset builds the download URL for a named release asset.
function Get-FoxAsset([string]$Name) {
    if ($Version -eq 'latest') {
        "https://github.com/$Repo/releases/latest/download/$Name"
    } else {
        "https://github.com/$Repo/releases/download/$Version/$Name"
    }
}

# Test-Admin reports whether this process is elevated.
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Test-WslReady reports whether WSL is installed and healthy enough to import a
# distro. `wsl --status` fails when the platform is present but not enabled.
function Test-WslReady {
    if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { return $false }
    try {
        & wsl.exe --status *> $null
        return ($LASTEXITCODE -eq 0)
    } catch { return $false }
}

# Test-RebootPending reports whether Windows is waiting on a restart. Enabling
# the WSL optional components sets this on a machine that had them off.
function Test-RebootPending {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )
    foreach ($k in $keys) { if (Test-Path $k) { return $true } }
    return $false
}

# Get-ResumeCommand is what runs after the reboot: the installer of a release,
# never main (findings SUP-3 and SUP-8). This one carries the pinned release
# key, and main is only whatever was merged last; it also used to mean the
# resumed install could be a different installer, of a different release,
# from the one the person started. So it resumes the same release (and
# edition), with the installer published with that release -- or, for a
# release from before installers were published with it, the latest
# release's installer, still pinned to the same release.
function Get-ResumeCommand {
    $tag = $script:Version
    $url = "https://github.com/$Repo/releases/latest/download/install.ps1"
    $pin = ''
    if ($tag -and $tag -ne 'latest' -and $tag -match '^[A-Za-z0-9._-]+$') {
        $pin = "`$env:FOX_VERSION='$tag'; "
        $c = Compare-FoxVersion $tag $FirstVersionedRelease
        if ($null -ne $c -and $c -ge 0) {
            $url = "https://github.com/$Repo/releases/download/$tag/install.ps1"
        }
    }
    return "$pin`$env:FOX_EDITION='$Edition'; irm $url | iex"
}

# Register-Resume arranges for this installer to run again after a reboot, so a
# machine that needed WSL enabled finishes on its own. It is a convenience, never
# the only path: re-running the one-liner by hand always works.
function Register-Resume {
    # RunOnce fires early at logon, typically before networking is up, so the
    # resumed command waits for the download host to answer before starting.
    # Without the wait it fails immediately on `irm` and the user sees only a
    # stray error window -- which is what happened on the first real machine
    # this was tried on.
    #
    # It fetches from GitHub directly, not from $InstallUrl: nobody reads this
    # command, and at logon it is one fewer service that has to be up.
    $cmd = "for (`$i=0; `$i -lt 60; `$i++) { " +
           "if (Test-Connection -ComputerName github.com -Count 1 -Quiet) { break }; " +
           "Start-Sleep -Seconds 5 }; " + (Get-ResumeCommand)
    $run = "powershell -NoExit -NoProfile -ExecutionPolicy Bypass -Command `"$cmd`""
    try {
        New-ItemProperty -Force -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' `
            -Name 'FoxByteInstall' -Value $run -PropertyType String | Out-Null
        return $true
    } catch { return $false }
}

# Install-Wsl enables WSL without a Linux distribution.
#
# --no-distribution matters: FoxByte imports its own dedicated distro, so an
# Ubuntu install is a pure waste of the user's time and disk. Requires admin, so
# this re-launches elevated and waits.
function Install-Wsl {
    if ($env:FOX_NO_ELEVATE) {
        throw "WSL is not installed. Run this in an Administrator PowerShell, then re-run the installer:`n" +
              "    wsl --install --no-distribution"
    }
    Write-Host "  FoxByte needs WSL. Windows will ask for permission to install it."
    $wslArgs = @('--install', '--no-distribution')
    if (Test-Admin) {
        & wsl.exe --install --no-distribution 2>&1 | Out-String | Write-Verbose
    } else {
        $p = Start-Process -FilePath 'wsl.exe' -ArgumentList $wslArgs -Verb RunAs -Wait -PassThru
        if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) {
            throw "installing WSL failed (exit $($p.ExitCode)). Run 'wsl --install --no-distribution' in an Administrator PowerShell."
        }
    }
    try { & wsl.exe --update *> $null } catch { }
}

# Bounded waits for every download.
#
# Invoke-WebRequest has no timeout by default, so a network fault that lets a
# connection stall rather than refusing it leaves the installer waiting with
# nothing on screen. That is the hang install.sh had, reported from a real
# machine on 3 Oct 2026; this is the same fix on the other installer.
#
# Which parameter to use differs between the two PowerShells, and choosing
# wrong would cut the 460MB distro image short on a slow link:
#
#   Windows PowerShell  -TimeoutSec bounds the request, NOT the reading of the
#                       response body, so a long download is unaffected.
#   PowerShell 7.0-7.3  -TimeoutSec became the whole operation, body included.
#                       Nothing bounds the connect alone, so nothing is set --
#                       waiting beats truncating a download that is working.
#   PowerShell 7.4+     -ConnectionTimeoutSec restored the old meaning.
#
# Detected by asking for the parameter rather than by version number, so a
# backport lands correctly without this having to know about it.
$script:WebTimeout = @{}
if ($PSVersionTable.PSVersion.Major -lt 6) {
    $script:WebTimeout = @{ TimeoutSec = 30 }
} elseif ((Get-Command Invoke-WebRequest).Parameters.ContainsKey('ConnectionTimeoutSec')) {
    $script:WebTimeout = @{ ConnectionTimeoutSec = 30 }
}

function Get-File([string]$Url, [string]$Dest, [bool]$Required = $true) {
    $timeout = $script:WebTimeout
    # Three attempts. With the timeout above, a stalled connection gives up
    # instead of hanging, and a transient fault is usually gone by the second.
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            # Progress rendering dominates the runtime of a large download in
            # Windows PowerShell; suppressing it is worth several minutes on the
            # rootfs.
            $prev = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
            try { Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Dest @timeout }
            finally { $ProgressPreference = $prev }
            return $true
        } catch {
            if ($attempt -lt 3) {
                Write-Warning "download attempt $attempt of 3 failed: $Url"
                Start-Sleep -Seconds 2
                continue
            }
            if ($Required) { throw "download failed after 3 attempts: $Url`n$($_.Exception.Message)" }
            Write-Warning "optional asset not in this release yet: $Url"
            return $false
        }
    }
}

# Get-UpstreamChecksum returns the expected SHA256 for $Name from a publisher's
# SHA256SUMS listing, or $null if the listing can't be fetched or doesn't name
# the file. Callers decide what an unknown checksum means.
function Get-UpstreamChecksum([string]$SumsUrl, [string]$Name) {
    try {
        $timeout = $script:WebTimeout
        $body = (Invoke-WebRequest -UseBasicParsing -Uri $SumsUrl @timeout).Content
    } catch {
        Write-Warning "could not fetch $SumsUrl"
        return $null
    }
    # Windows PowerShell hands back a byte[] when the response isn't typed as
    # text; PowerShell 7 hands back a string. Normalize before splitting.
    $sums = if ($body -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($body) } else { [string]$body }
    # Lines look like: "<sha256>  *ubuntu-...rootfs.tar.gz" (or two spaces).
    foreach ($line in ($sums -split "`n")) {
        if ($line -match '^([0-9a-fA-F]{64})\s+\*?(.+?)\s*$' -and $Matches[2] -eq $Name) {
            return $Matches[1].ToLower()
        }
    }
    Write-Warning "$Name not listed in SHA256SUMS"
    return $null
}

# Test-UpstreamChecksum reports whether a staged file still matches the
# publisher's listing. An unverifiable file is not reusable, so anything other
# than a positive match is $false.
function Test-UpstreamChecksum([string]$Path, [string]$SumsUrl, [string]$Name) {
    $want = Get-UpstreamChecksum $SumsUrl $Name
    if (-not $want) { return $false }
    return (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLower() -eq $want
}

# Assert-UpstreamChecksum verifies a download against the publisher's listing.
# Ubuntu's rootfs is a ~340 MB third-party download that becomes the root
# filesystem of a distro, so it is worth checking. A listing we cannot reach is
# a warning, not a failure -- the download itself already came over TLS.
function Assert-UpstreamChecksum([string]$Path, [string]$SumsUrl, [string]$Name) {
    $want = Get-UpstreamChecksum $SumsUrl $Name
    if (-not $want) {
        Write-Warning "skipping checksum verification for $Name"
        return
    }
    $got = (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLower()
    if ($got -ne $want) {
        Remove-Item $Path -Force -ErrorAction SilentlyContinue
        throw "checksum mismatch for $Name`n  expected $want`n  got      $got"
    }
}

# --- FoxByte's own releases ----------------------------------------------
# Every release publishes SHA256SUMS beside its assets. It travels over the same
# TLS connection as the files, so it proves integrity (a complete, unaltered
# download), not authorship. The files below are executed as root inside the
# distro, so an unverifiable one is not installed. FOX_NO_VERIFY=1 skips the
# check deliberately.
#
# Authorship (audit v2 G22, finding SUP-5): SHA256SUMS is signed. The Ed25519
# signature (SHA256SUMS.sig) is out of reach here -- PowerShell and .NET have no
# Ed25519 -- so this installer checks the P-256 one, SHA256SUMS.p256.sig,
# against $ReleaseP256PublicKey above. fox.exe checks Ed25519 on every
# `fox update`, and `gh attestation verify fox-windows-amd64.exe --repo
# thefoxbyte/foxbyte` proves where a download came from.
#
# The distro image is built by its own workflow, on its own schedule, so its
# checksum is in SHA256SUMS.distro, signed on its own. Releases made before that
# file existed list the image in SHA256SUMS, which is why both are looked at for
# it, and only for it.
$script:FoxSums = $null
$script:FoxDistroSums = $null

# Get-FoxBytes downloads a small file as the exact bytes served: a signature is
# over bytes, and turning them into a string and back could change them.
function Get-FoxBytes([string]$Url) {
    $timeout = $script:WebTimeout
    $r = Invoke-WebRequest -UseBasicParsing -Uri $Url @timeout
    return ,($r.RawContentStream.ToArray())
}

# Compare-FoxVersion returns -1, 0 or 1, ordered as fox orders versions (a
# pre-release sorts before its release), or $null if either is not a version.
function Compare-FoxVersion([string]$A, [string]$B) {
    $parsed = @()
    foreach ($s in $A, $B) {
        if ($s -notmatch '^[vV]?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-(.+))?$') { return $null }
        $parsed += ,@([int64]$Matches[1], [int64]("0" + $Matches[2]), [int64]("0" + $Matches[3]), [string]$Matches[4])
    }
    $x = $parsed[0]; $y = $parsed[1]
    for ($i = 0; $i -lt 3; $i++) {
        if ($x[$i] -ne $y[$i]) { if ($x[$i] -lt $y[$i]) { return -1 } else { return 1 } }
    }
    if ($x[3] -ceq $y[3]) { return 0 }
    if (-not $x[3]) { return 1 }
    if (-not $y[3]) { return -1 }
    if ([string]::CompareOrdinal($x[3], $y[3]) -lt 0) { return -1 }
    return 1
}

# Get-FoxSignedVersion returns the version a listing names in its version line
# ("<64 zeros>  VERSION=<tag>", written by scripts/release-checksums.sh), or ''
# for a release made before the line existed. It is a checksum line so that
# installers already released, which look files up by name, pass over it.
function Get-FoxSignedVersion([string]$Listing) {
    $found = @()
    foreach ($line in ($Listing -split "`n")) {
        if ($line -match '^0{64}\s+\*?VERSION=([^\s]+)\s*$') {
            if ($found -notcontains $Matches[1]) { $found += $Matches[1] }
        }
    }
    if ($found.Count -gt 1) { throw "SHA256SUMS of $Version names more than one version -- nothing was installed." }
    if ($found.Count -eq 1) { return $found[0] }
    return ''
}

# Assert-FoxVersion holds the version a listing names to the tag being
# installed (finding SUP-4): the tag is not signed, so an old release put up
# again under a newer tag would otherwise install. From $FirstVersionedRelease
# on, every release names its version, so one that does not is refused; older
# ones never did, and stay installable by naming them with FOX_VERSION.
function Assert-FoxVersion([string]$Listing, [string]$Tag) {
    $signed = Get-FoxSignedVersion $Listing
    if (-not $Tag -or $Tag -eq 'latest') { return }
    if ($signed) {
        if ((Compare-FoxVersion $signed $Tag) -ne 0) {
            throw "SHA256SUMS of $Tag is signed for $signed -- it is a different release, published under the $Tag tag. Nothing was installed."
        }
        return
    }
    if ((Compare-FoxVersion $Tag $FirstVersionedRelease) -ne -1) {
        throw "SHA256SUMS of $Tag does not say which version it is, and every release from v$FirstVersionedRelease on does. It may be an older release published again under a newer tag. Nothing was installed."
    }
}

# ConvertFrom-DerSignature turns an ASN.1 DER ECDSA signature, which is what
# `openssl dgst -sign` and Go write, into the 64-byte r||s form .NET checks.
# $null for anything that is not a well-formed P-256 signature.
function ConvertFrom-DerSignature([byte[]]$Der) {
    if ($null -eq $Der -or $Der.Length -lt 8 -or $Der.Length -gt 72 -or $Der[0] -ne 0x30) { return $null }
    if ($Der[1] -ne $Der.Length - 2) { return $null }
    $out = New-Object byte[] 64
    $i = 2
    foreach ($k in 0, 1) {
        if ($i + 2 -gt $Der.Length -or $Der[$i] -ne 0x02) { return $null }
        $n = [int]$Der[$i + 1]
        $i += 2
        if ($n -lt 1 -or $n -gt 33 -or $i + $n -gt $Der.Length) { return $null }
        $start = $i
        while ($start -lt $i + $n - 1 -and $Der[$start] -eq 0) { $start++ }
        $len = $i + $n - $start
        if ($len -gt 32) { return $null }
        [Array]::Copy($Der, $start, $out, $k * 32 + 32 - $len, $len)
        $i += $n
    }
    if ($i -ne $Der.Length) { return $null }
    return ,$out
}

# Test-FoxSignature checks a P-256 signature (DER) over $Data with the key
# given as the base64 uncompressed point. Windows PowerShell 5.1 imports the
# point through CNG (ECDsaCng, any .NET Framework from 4.6.1); elsewhere, the
# portable ECParameters path is used.
function Test-FoxSignature([byte[]]$Data, [byte[]]$DerSig, [string]$KeyB64 = $ReleaseP256PublicKey) {
    $sig = ConvertFrom-DerSignature $DerSig
    if ($null -eq $sig) { return $false }
    $point = [Convert]::FromBase64String($KeyB64)
    if ($point.Length -ne 65 -or $point[0] -ne 4) { throw "the P-256 release key in this installer is malformed" }
    $x = New-Object byte[] 32; [Array]::Copy($point, 1, $x, 0, 32)
    $y = New-Object byte[] 32; [Array]::Copy($point, 33, $y, 0, 32)
    $sha256 = [System.Security.Cryptography.HashAlgorithmName]::SHA256
    $ecdsa = $null
    try {
        # BCRYPT_ECCPUBLIC_BLOB: magic "ECS1" (ECDSA P-256 public), key length 32, X, Y.
        $blob = New-Object byte[] 72
        [Array]::Copy([byte[]](0x45, 0x43, 0x53, 0x31, 0x20, 0, 0, 0), 0, $blob, 0, 8)
        [Array]::Copy($x, 0, $blob, 8, 32)
        [Array]::Copy($y, 0, $blob, 40, 32)
        $key = [System.Security.Cryptography.CngKey]::Import($blob, [System.Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
        $ecdsa = New-Object System.Security.Cryptography.ECDsaCng($key)
    } catch {
        $p = New-Object System.Security.Cryptography.ECParameters
        $p.Curve = [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256
        $q = New-Object System.Security.Cryptography.ECPoint
        $q.X = $x; $q.Y = $y
        $p.Q = $q
        $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
        $ecdsa.ImportParameters($p)
    }
    try { return [bool]$ecdsa.VerifyData($Data, $sig, $sha256) } finally { $ecdsa.Dispose() }
}

# Assert-FoxSignature checks a listing's P-256 signature, $SigName, and stops
# the install if it does not check. While this installer carries no P-256 key
# it can only warn (once), which is what it did before the key existed.
function Assert-FoxSignature([byte[]]$Data, [string]$SigName, [bool]$Quiet = $false) {
    if ($env:FOX_ALLOW_UNSIGNED -eq '1') {
        if (-not $Quiet) { Write-Warning "FOX_ALLOW_UNSIGNED=1: not checking who published $Version (every file is still checked against SHA256SUMS)" }
        return
    }
    if (-not $ReleaseP256PublicKey) {
        if (-not $Quiet) {
            Write-Warning "the signature of $Version was not checked: this installer has no P-256 release key yet. Every file is still checked against SHA256SUMS, and fox checks signatures on every update."
        }
        return
    }
    try { $sig = Get-FoxBytes (Get-FoxAsset $SigName) } catch {
        throw "$Version has no $SigName, so who published it cannot be checked here -- nothing was installed.`n(Releases from before the P-256 signature have none: set FOX_ALLOW_UNSIGNED=1 to install one on checksums alone.)"
    }
    $ok = $false
    try { $ok = Test-FoxSignature $Data $sig } catch { throw "could not check the signature of $Version ($($_.Exception.Message)) -- nothing was installed.`nSet FOX_ALLOW_UNSIGNED=1 to install on checksums alone." }
    if (-not $ok) {
        throw "$SigName does not match: $Version was not published by $Product, or it was altered. Nothing was installed."
    }
}

function Get-FoxSums {
    if ($env:FOX_NO_VERIFY -eq '1') { return $null }
    if ($null -ne $script:FoxSums) { return $script:FoxSums }
    try {
        $bytes = Get-FoxBytes (Get-FoxAsset 'SHA256SUMS')
    } catch {
        throw "could not fetch SHA256SUMS for $Version -- nothing was installed.`nRetry, or set FOX_NO_VERIFY=1 to install without checking (not recommended)."
    }
    Assert-FoxSignature $bytes 'SHA256SUMS.p256.sig'
    $listing = [System.Text.Encoding]::UTF8.GetString($bytes)
    Assert-FoxVersion $listing $Version
    if ($ReleaseP256PublicKey -and $env:FOX_ALLOW_UNSIGNED -ne '1') { Write-Host "  SHA256SUMS is signed with the $Product release key (P-256)" }
    $script:FoxSums = $listing
    return $script:FoxSums
}

# Get-FoxDistroSums returns the distro image's own listing, or '' for a release
# without one (the distro workflow has not finished, or the release predates it).
# A listing that fails its signature or names another version counts as none:
# the image is then looked up in SHA256SUMS, and without it the install falls
# back to the Ubuntu rootfs rather than trust it.
function Get-FoxDistroSums {
    if ($null -ne $script:FoxDistroSums) { return $script:FoxDistroSums }
    try {
        $bytes = Get-FoxBytes (Get-FoxAsset 'SHA256SUMS.distro')
    } catch {
        $script:FoxDistroSums = ''
        return $script:FoxDistroSums
    }
    try {
        Assert-FoxSignature $bytes 'SHA256SUMS.distro.p256.sig' $true
        $listing = [System.Text.Encoding]::UTF8.GetString($bytes)
        Assert-FoxVersion $listing $Version
        $script:FoxDistroSums = $listing
    } catch {
        Write-Warning "ignoring SHA256SUMS.distro: $($_.Exception.Message)"
        $script:FoxDistroSums = ''
    }
    return $script:FoxDistroSums
}

# Resolve-FoxLatestTag turns "latest" into the tag it stands for, before
# anything is fetched: the signed SHA256SUMS names its version, and that is
# only worth something against the tag being installed. It also keeps one
# install on one release should a new one be promoted part-way through.
# GitHub answers /releases/latest with a redirect to /releases/tag/<tag>,
# which is read without following it.
function Resolve-FoxLatestTag {
    $url = "https://github.com/$Repo/releases/latest"
    $loc = $null
    try {
        $req = [System.Net.HttpWebRequest]::Create($url)
        $req.AllowAutoRedirect = $false
        $req.Timeout = 30000
        $req.UserAgent = "$Slug-installer"
        $resp = $req.GetResponse()
        try { $loc = $resp.Headers['Location'] } finally { $resp.Close() }
    } catch [System.Net.WebException] {
        if ($_.Exception.Response) { $loc = $_.Exception.Response.Headers['Location'] }
    } catch { }
    if ($loc -and $loc -match '/releases/tag/([A-Za-z0-9._-]+)$') { return $Matches[1] }
    throw "could not find which release is the latest one of $Repo -- nothing was installed.`nRetry, or name the release with FOX_VERSION=<tag>."
}

# Find-FoxChecksum returns the SHA256 a listing gives for $Name, or $null. The
# version line is not a file, and is never an answer.
function Find-FoxChecksum([string]$Listing, [string]$Name) {
    foreach ($line in ($Listing -split "`n")) {
        if ($line -match '^0{64}\s+\*?VERSION=') { continue }
        if ($line -match '^([0-9a-fA-F]{64})\s+\*?(.+?)\s*$' -and $Matches[2] -eq $Name) {
            return $Matches[1].ToLower()
        }
    }
    return $null
}

# Get-FoxChecksum returns the expected SHA256 for a release asset, or $null when
# verification is switched off. The distro's own listing goes first, so a distro
# rebuilt for an older release is checked against its current hash; it can never
# answer for any other file.
function Get-FoxChecksum([string]$Name) {
    $sums = Get-FoxSums
    if ($null -eq $sums) { return $null }
    if ($Name -like 'foxbyte-distro.*') {
        $want = Find-FoxChecksum (Get-FoxDistroSums) $Name
        if ($want) { return $want }
    }
    $want = Find-FoxChecksum $sums $Name
    if ($want) { return $want }
    throw "$Name is not listed in SHA256SUMS for $Version -- nothing was installed.`nSet FOX_NO_VERIFY=1 to install without checking (not recommended)."
}

# Test-FoxChecksum reports whether a staged copy still matches the release, for
# deciding if a large download can be reused. Anything unverifiable is $false.
function Test-FoxChecksum([string]$Path, [string]$Name) {
    if ($env:FOX_NO_VERIFY -eq '1') { return $false }
    try { $want = Get-FoxChecksum $Name } catch { return $false }
    if (-not $want) { return $false }
    return (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLower() -eq $want
}

# Test-FoxAssetListed reports whether this release lists $Name in SHA256SUMS,
# so an asset the release does not publish is skipped rather than downloaded
# into a 404. With verification off nothing is known, so it answers yes.
function Test-FoxAssetListed([string]$Name) {
    try { $null = Get-FoxChecksum $Name; return $true } catch { return $false }
}

# Assert-FoxChecksum verifies a download and deletes it if it does not match.
function Assert-FoxChecksum([string]$Path, [string]$Name) {
    $want = Get-FoxChecksum $Name
    if (-not $want) { return }   # FOX_NO_VERIFY=1
    $got = (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLower()
    if ($got -ne $want) {
        Remove-Item $Path -Force -ErrorAction SilentlyContinue
        throw "checksum mismatch for $Name -- the download does not match the release.`n  expected $want`n  got      $got`nNothing was installed."
    }
}

# Add-ToPath appends a directory to the user PATH, idempotently.
function Add-ToPath([string]$Dir) {
    $cur = [Environment]::GetEnvironmentVariable('Path', 'User')
    $parts = @()
    if ($cur) { $parts = $cur -split ';' | Where-Object { $_ -ne '' } }
    if ($parts -notcontains $Dir) {
        $new = (@($parts + $Dir) -join ';')
        [Environment]::SetEnvironmentVariable('Path', $new, 'User')
        return $true
    }
    return $false
}

function Invoke-Install {
    $arch = Resolve-Arch
    if ($arch -ne 'amd64') {
        throw "unsupported architecture '$arch' -- only windows/amd64 is published (WSL2 runs x86_64)."
    }
    Write-Host ""
    Write-Host "FoxByte installer" -ForegroundColor Cyan
    if ($script:Version -eq 'latest') {
        $script:Version = Resolve-FoxLatestTag
        Write-Host "  Installing $($script:Version), the latest release"
    }

    # 1. WSL. Done first because everything else is pointless without it -- and
    #    because it is the only step that can require a reboot.
    if (Test-WslReady) {
        Write-Step "WSL is already installed"
    } else {
        Write-Step "Installing WSL components (no Linux distribution needed)"
        Install-Wsl
        # Parenthesised deliberately: `Test-RebootPending -or ...` would pass
        # `-or` to the function as a parameter rather than combining them.
        if ((Test-RebootPending) -or -not (Test-WslReady)) {
            $resumed = Register-Resume
            Write-Host ""
            Write-Host "Windows needs to restart to finish enabling WSL." -ForegroundColor Yellow
            if ($resumed) {
                Write-Host "FoxByte should continue by itself a moment after you sign back in."
            }
            # Always given, even when the resume was registered: it depends on
            # RunOnce firing and on networking being up, neither guaranteed.
            Write-Host "If it does not, just run the same command again:" -ForegroundColor Yellow
            Write-Host "    irm $InstallUrl | iex"
            Write-Host "Nothing is lost by re-running it -- the install picks up where it stopped."
            Write-Host ""
            return
        }
    }

    New-Item -ItemType Directory -Force -Path $Prefix | Out-Null

    # 2. The launcher and the engine binary, each checked against the release's
    #    own SHA256SUMS before it is kept: both run as root inside the distro.
    Write-Step "Downloading FoxByte"
    Get-File (Get-FoxAsset $HostAsset) "$Prefix\$Cli.exe" | Out-Null
    Assert-FoxChecksum "$Prefix\$Cli.exe" $HostAsset
    # Installers from 21 Sep 2026 until this fix saved the launcher as bb.exe
    # (a rename rule for the SQL schema caught the file name), so `fox` was not a
    # command. Remove that copy so only one launcher is on PATH.
    Remove-Item -LiteralPath "$Prefix\bb.exe" -Force -ErrorAction SilentlyContinue
    Get-File (Get-FoxAsset $EngineAsset) "$Prefix\$EngineAsset" | Out-Null
    Assert-FoxChecksum "$Prefix\$EngineAsset" $EngineAsset

    # The engine finds a Docker build context relative to the working directory,
    # which finds nothing for someone who installed fox rather than cloning the
    # repo -- so ship the context and let `fox setup` stage it into the distro.
    # tar.exe is built into Windows 10 1803+ and Windows 11.
    New-Item -ItemType Directory -Force -Path "$Prefix\docker-context" | Out-Null
    Get-File (Get-FoxAsset 'foxbyte-docker-context.tar.gz') "$Prefix\docker-context.tar.gz" | Out-Null
    Assert-FoxChecksum "$Prefix\docker-context.tar.gz" 'foxbyte-docker-context.tar.gz'
    & tar.exe -xzf "$Prefix\docker-context.tar.gz" -C "$Prefix\docker-context"
    if ($LASTEXITCODE -ne 0) { throw "could not expand the image build context (tar.exe failed)" }
    Remove-Item "$Prefix\docker-context.tar.gz" -Force

    # 3. The distro. Preferred: our prebuilt image, which already contains
    #    Docker, the btrfs tools, the engine and the container images, so `fox
    #    setup` skips an apt install, a docker build and three registry pulls.
    #    It turns setup from many minutes of network-dependent work into an
    #    import. Releases publish it zstd-compressed (fox unpacks it: Windows'
    #    own tar.exe only reads gzip); releases before that published gzip, so
    #    that is tried next. One that cannot be verified, or a release with
    #    neither, falls back to the Ubuntu rootfs.
    $haveDistro = $false
    foreach ($name in 'foxbyte-distro.tar.zst', 'foxbyte-distro.tar.gz') {
        $distro = "$Prefix\$name"
        if (Test-Path $distro) {
            if (Test-FoxChecksum $distro $name) {
                Write-Step "FoxByte distro image already downloaded"
                $haveDistro = $true
                break
            }
            Remove-Item $distro -Force -ErrorAction SilentlyContinue
        }
        if (-not (Test-FoxAssetListed $name)) { continue }
        Write-Step "Downloading the FoxByte distro image (one time)"
        if (Get-File (Get-FoxAsset $name) $distro -Required:$false) {
            try {
                Assert-FoxChecksum $distro $name
                $haveDistro = $true
                break
            } catch {
                Remove-Item $distro -Force -ErrorAction SilentlyContinue
                Write-Warning "$($_.Exception.Message)"
            }
        }
    }
    if (-not $haveDistro) { Write-Warning "no verified distro image; falling back to the Ubuntu rootfs" }
    # A gzip image left from an older install would be preferred by nothing now
    # but would sit in the folder; drop it once a zstd one is in place.
    if ($haveDistro -and $name -eq 'foxbyte-distro.tar.zst') {
        Remove-Item "$Prefix\foxbyte-distro.tar.gz" -Force -ErrorAction SilentlyContinue
    }

    if (-not $haveDistro) {
        # The Ubuntu rootfs. ~340 MB, so don't re-fetch a verified copy.
        $rootfs = "$Prefix\foxbyte-rootfs.tar.gz"
        $verify = -not $env:FOX_ROOTFS_URL
        if ((Test-Path $rootfs) -and $verify -and (Test-UpstreamChecksum $rootfs "$RootfsBase/SHA256SUMS" $RootfsName)) {
            Write-Step "Ubuntu rootfs already downloaded"
        } else {
            Write-Step "Downloading the Ubuntu rootfs (~340 MB, one time)"
            Get-File $RootfsUrl $rootfs | Out-Null
            if ($verify) { Assert-UpstreamChecksum $rootfs "$RootfsBase/SHA256SUMS" $RootfsName }
        }
    }

    # 4. PATH -- persisted for new shells, and live in this one so `fox` works
    #    immediately. Not doing the latter is why "fox is not recognized" was
    #    the single most common complaint.
    Write-Step "Adding fox to your PATH"
    Add-ToPath $Prefix | Out-Null
    if (($env:Path -split ';') -notcontains $Prefix) { $env:Path = "$env:Path;$Prefix" }

    # 5. Finish the job. An installer that stops here and tells the user to run
    #    another command is where most installs died.
    if ($env:FOX_NO_SETUP) {
        Write-Step "Skipping setup (FOX_NO_SETUP)"
        Write-Host ""
        Write-Host "Installed. Run:  fox setup" -ForegroundColor Green
        return
    }
    Write-Step "Setting up FoxByte (first run sets up the database engine)"
    Write-Host ""
    & "$Prefix\$Cli.exe" setup
    if ($LASTEXITCODE -ne 0) {
        throw "fox setup failed. See $Prefix\install.log, then re-run:  fox setup"
    }

    # `fox setup` already printed the "FoxByte is running" summary, including
    # the connection string with the API key. Repeating it here only made the
    # install end with two near-identical blocks, so add the one thing the
    # engine cannot know: where this installer put its log.
    Write-Host ""
    Write-Host "  Installer log: $Prefix\install.log"
}

# Run only when executed/piped -- not when dot-sourced by tests.
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-Install
}
