# SPDX-License-Identifier: Apache-2.0
#
# FoxByte Windows installer: one command, from a machine with nothing on it to
# a running database. Installs WSL if absent (no Linux distribution required),
# installs the fox launcher, and runs `fox setup`.
#
# Usage (PowerShell):
#   irm https://raw.githubusercontent.com/thefoxbyte/foxbyte/main/deploy/install.ps1 | iex
#
# This file must stay free of a UTF-8 BOM: `irm | iex` pipes the BOM into the
# parser, which then reports `The term '# ' is not recognized` on line 1.
#
# Every FoxByte download is checked against the release's SHA256SUMS before it
# is kept -- these files run as root inside the distro. Anything that cannot be
# verified stops the install (FOX_NO_VERIFY=1 deliberately skips the check).
#
# Env overrides: FOX_VERSION (default "latest"), FOX_REPO, FOX_PREFIX,
# FOX_NO_SETUP (skip `fox setup`), FOX_NO_ELEVATE (never prompt for admin),
# FOX_NO_VERIFY (skip checksum verification).

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
# end generated

$Repo    = if ($env:FOX_REPO)    { $env:FOX_REPO }    else { $DefaultRepo }
$Version = if ($env:FOX_VERSION) { $env:FOX_VERSION } else { 'latest' }
$Prefix  = if ($env:FOX_PREFIX)  { $env:FOX_PREFIX }  else { "$env:LOCALAPPDATA\Programs\$Slug" }

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

# Register-Resume arranges for this installer to run again after a reboot, so a
# machine that needed WSL enabled finishes on its own. It is a convenience, never
# the only path: re-running the one-liner by hand always works.
function Register-Resume {
    # RunOnce fires early at logon, typically before networking is up, so the
    # resumed command waits for the download host to answer before starting.
    # Without the wait it fails immediately on `irm` and the user sees only a
    # stray error window -- which is what happened on the first real machine
    # this was tried on.
    $url = 'https://raw.githubusercontent.com/thefoxbyte/foxbyte/main/deploy/install.ps1'
    $cmd = "for (`$i=0; `$i -lt 60; `$i++) { " +
           "if (Test-Connection -ComputerName raw.githubusercontent.com -Count 1 -Quiet) { break }; " +
           "Start-Sleep -Seconds 5 }; irm $url | iex"
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

function Get-File([string]$Url, [string]$Dest, [bool]$Required = $true) {
    try {
        # Progress rendering dominates the runtime of a large download in
        # Windows PowerShell; suppressing it is worth several minutes on the
        # rootfs.
        $prev = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        try { Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Dest }
        finally { $ProgressPreference = $prev }
        return $true
    } catch {
        if ($Required) { throw "download failed: $Url`n$($_.Exception.Message)" }
        Write-Warning "optional asset not in this release yet: $Url"
        return $false
    }
}

# Get-UpstreamChecksum returns the expected SHA256 for $Name from a publisher's
# SHA256SUMS listing, or $null if the listing can't be fetched or doesn't name
# the file. Callers decide what an unknown checksum means.
function Get-UpstreamChecksum([string]$SumsUrl, [string]$Name) {
    try {
        $body = (Invoke-WebRequest -UseBasicParsing -Uri $SumsUrl).Content
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
# Authorship: releases also publish SHA256SUMS.sig, an Ed25519 signature by the
# FoxByte release key (audit v2 G22). PowerShell and .NET have no Ed25519, so
# this installer checks checksums only; fox.exe checks the signature on every
# `fox update`, and `gh attestation verify fox-windows-amd64.exe --repo
# thefoxbyte/foxbyte` proves where a download came from.
# Every release publishes SHA256SUMS beside its assets. It travels over the same
# TLS connection as the files, so it proves integrity (a complete, unaltered
# download), not authorship -- signatures would be needed for that. The files
# below are executed as root inside the distro, so an unverifiable one is not
# installed. FOX_NO_VERIFY=1 skips the check deliberately.
$script:FoxSums = $null

function Get-FoxSums {
    if ($env:FOX_NO_VERIFY -eq '1') { return $null }
    if ($null -ne $script:FoxSums) { return $script:FoxSums }
    try {
        $body = (Invoke-WebRequest -UseBasicParsing -Uri (Get-FoxAsset 'SHA256SUMS')).Content
    } catch {
        throw "could not fetch SHA256SUMS for $Version -- nothing was installed.`nRetry, or set FOX_NO_VERIFY=1 to install without checking (not recommended)."
    }
    $script:FoxSums = if ($body -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($body) } else { [string]$body }
    return $script:FoxSums
}

# Get-FoxChecksum returns the expected SHA256 for a release asset, or $null when
# verification is switched off.
function Get-FoxChecksum([string]$Name) {
    $sums = Get-FoxSums
    if ($null -eq $sums) { return $null }
    foreach ($line in ($sums -split "`n")) {
        if ($line -match '^([0-9a-fA-F]{64})\s+\*?(.+?)\s*$' -and $Matches[2] -eq $Name) {
            return $Matches[1].ToLower()
        }
    }
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
            Write-Host "    irm https://raw.githubusercontent.com/thefoxbyte/foxbyte/main/deploy/install.ps1 | iex"
            Write-Host "Nothing is lost by re-running it -- the install picks up where it stopped."
            Write-Host ""
            return
        }
    }

    New-Item -ItemType Directory -Force -Path $Prefix | Out-Null

    # 2. The launcher and the engine binary, each checked against the release's
    #    own SHA256SUMS before it is kept: both run as root inside the distro.
    Write-Step "Downloading FoxByte"
    Get-File (Get-FoxAsset 'fox-windows-amd64.exe') "$Prefix\$Cli.exe" | Out-Null
    Assert-FoxChecksum "$Prefix\$Cli.exe" 'fox-windows-amd64.exe'
    # Installers from 21 Sep 2026 until this fix saved the launcher as bb.exe
    # (a rename rule for the SQL schema caught the file name), so `fox` was not a
    # command. Remove that copy so only one launcher is on PATH.
    Remove-Item -LiteralPath "$Prefix\bb.exe" -Force -ErrorAction SilentlyContinue
    Get-File (Get-FoxAsset 'fox-linux-amd64') "$Prefix\fox-linux-amd64" | Out-Null
    Assert-FoxChecksum "$Prefix\fox-linux-amd64" 'fox-linux-amd64'

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
