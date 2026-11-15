# SPDX-License-Identifier: Apache-2.0
# Pester tests for install.ps1 (TC4.4). Dot-sourcing install.ps1 loads its
# functions without running the installer (guarded by $MyInvocation.InvocationName).
# Run: Invoke-Pester deploy/install.Tests.ps1

Describe 'Resolve-Arch' {
    BeforeAll { . "$PSScriptRoot/install.ps1" }
    It 'returns a known arch token' {
        Resolve-Arch | Should -BeIn @('amd64', 'arm64')
    }
}

Describe 'Get-FoxAsset (latest)' {
    BeforeAll {
        $env:FOX_VERSION = $null
        . "$PSScriptRoot/install.ps1"
    }
    It 'builds a latest release URL' {
        Get-FoxAsset 'fox-windows-amd64.exe' |
            Should -Be 'https://github.com/thefoxbyte/foxbyte/releases/latest/download/fox-windows-amd64.exe'
    }
}

Describe 'Get-FoxAsset (pinned)' {
    BeforeAll {
        $env:FOX_VERSION = 'v1.2.3'
        . "$PSScriptRoot/install.ps1"
    }
    AfterAll { $env:FOX_VERSION = $null }
    It 'builds a versioned release URL' {
        Get-FoxAsset 'fox-windows-amd64.exe' |
            Should -Be 'https://github.com/thefoxbyte/foxbyte/releases/download/v1.2.3/fox-windows-amd64.exe'
    }
}

Describe 'Add-ToPath' {
    BeforeAll { . "$PSScriptRoot/install.ps1" }
    It 'is idempotent for an already-present dir' {
        $existing = ([Environment]::GetEnvironmentVariable('Path', 'User') -split ';' |
            Where-Object { $_ -ne '' } | Select-Object -First 1)
        if ($existing) { Add-ToPath $existing | Should -BeFalse }
    }
}

# TC4.6 — the ZFS bundle is named for the kernel it was built against, so an
# installer running against a bumped WSL kernel misses the download rather than
# staging modules that cannot load. Must agree with zfsBundleName in
# internal/host/host_wsl.go.
# TC4.6 -- the installer must not depend on WSL. Choosing the ZFS bundle moved
# into `fox setup`, which is the first point the right kernel is knowable; an
# installer that needed WSL first is what forced the old manual multi-step setup.
Describe 'installer is independent of WSL' {
    BeforeAll { . "$PSScriptRoot/install.ps1" }
    It 'no longer chooses the ZFS bundle itself' {
        Get-Command Get-ZfsBundleName -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }

    It 'never asks a running distro for the kernel release' {
        # The installer may legitimately run before WSL exists, so it must not
        # query a distro for anything. It used to, to pick a ZFS bundle, and
        # that is why the docs once told users to install Ubuntu first. Windows
        # stores branches on btrfs now, so nothing is kernel-specific and the
        # question is never asked.
        $src = Get-Content "$PSScriptRoot/install.ps1" -Raw
        $src | Should -Not -Match 'uname -r'
    }
    It 'never mentions a distribution when installing WSL' {
        $src = Get-Content "$PSScriptRoot/install.ps1" -Raw
        $src | Should -Match '--no-distribution'
        $src | Should -Not -Match 'wsl --install -d '
    }
}

# TC4.7 -- encoding. These two invocations pull in opposite directions: a BOM
# breaks `irm | iex` ("The term '# ' is not recognized"), and no BOM makes
# Windows PowerShell 5.1 read non-ASCII as ANSI and fail to parse the file.
# Pure ASCII with no BOM is the only encoding that satisfies both.
Describe 'FoxByte release verification' {
    # Dot-sourcing loads the installer's functions without running it, as every
    # other block here does. The listing is primed through the same script-scoped
    # cache Get-FoxSums fills, so these exercise the real lookup rather than a mock.
    BeforeAll {
        . "$PSScriptRoot/install.ps1"
        $script:listing = ('a' * 64) + "  fox-windows-amd64.exe`n" + ('b' * 64) + " *foxbyte-distro.tar.gz`n"
    }
    BeforeEach {
        $env:FOX_NO_VERIFY = $null
        Set-Variable -Name FoxSums -Scope Script -Value $script:listing
        Set-Variable -Name FoxDistroSums -Scope Script -Value ''
    }
    AfterAll { $env:FOX_NO_VERIFY = $null }

    It 'reads a checksum from the release listing' {
        Get-FoxChecksum 'fox-windows-amd64.exe' | Should -Be ('a' * 64)
    }

    It 'accepts the binary-mode "*name" form' {
        Get-FoxChecksum 'foxbyte-distro.tar.gz' | Should -Be ('b' * 64)
    }

    It 'reads the distro image from its own listing' {
        Set-Variable -Name FoxDistroSums -Scope Script -Value (('c' * 64) + "  foxbyte-distro.tar.zst`n")
        Get-FoxChecksum 'foxbyte-distro.tar.zst' | Should -Be ('c' * 64)
    }

    It 'prefers the distro listing over an older entry in SHA256SUMS' {
        Set-Variable -Name FoxDistroSums -Scope Script -Value (('c' * 64) + "  foxbyte-distro.tar.gz`n")
        Get-FoxChecksum 'foxbyte-distro.tar.gz' | Should -Be ('c' * 64)
    }

    It 'never lets the distro listing answer for another file' {
        Set-Variable -Name FoxDistroSums -Scope Script -Value (('c' * 64) + "  fox-windows-amd64.exe`n")
        Get-FoxChecksum 'fox-windows-amd64.exe' | Should -Be ('a' * 64)
    }

    It 'refuses a distro image neither listing names' {
        { Get-FoxChecksum 'foxbyte-distro.tar.zst' } | Should -Throw '*not listed in SHA256SUMS*'
    }

    It 'refuses an asset the listing does not name' {
        { Get-FoxChecksum 'fox-linux-amd64' } | Should -Throw '*not listed in SHA256SUMS*'
    }

    It 'deletes a file whose checksum does not match and stops the install' {
        $f = Join-Path $TestDrive 'fox-windows-amd64.exe'
        Set-Content -Path $f -Value 'not the real binary' -NoNewline
        { Assert-FoxChecksum $f 'fox-windows-amd64.exe' } | Should -Throw '*checksum mismatch*'
        Test-Path $f | Should -BeFalse
    }

    It 'passes a file that matches' {
        $f = Join-Path $TestDrive 'ok.bin'
        Set-Content -Path $f -Value 'contents' -NoNewline
        $hash = (Get-FileHash -Algorithm SHA256 -Path $f).Hash.ToLower()
        Set-Variable -Name FoxSums -Scope Script -Value "$hash  ok.bin"
        { Assert-FoxChecksum $f 'ok.bin' } | Should -Not -Throw
        Test-Path $f | Should -BeTrue
    }

    It 'skips verification when FOX_NO_VERIFY=1' {
        $env:FOX_NO_VERIFY = '1'
        $f = Join-Path $TestDrive 'skip.bin'
        Set-Content -Path $f -Value 'whatever' -NoNewline
        Get-FoxChecksum 'anything' | Should -BeNullOrEmpty
        { Assert-FoxChecksum $f 'anything' } | Should -Not -Throw
    }

    It 'treats an unverifiable staged copy as unusable' {
        $f = Join-Path $TestDrive 'stale.tar.gz'
        Set-Content -Path $f -Value 'stale' -NoNewline
        Test-FoxChecksum $f 'foxbyte-distro.tar.gz' | Should -BeFalse
    }
}

# Finding SUP-4: the version a release's signed SHA256SUMS names is held to the
# tag being installed, and a release from the cutoff on must name one.
Describe 'signed release version' {
    BeforeAll {
        . "$PSScriptRoot/install.ps1"
        $script:zeros = '0' * 64
    }

    It 'orders versions as fox does' {
        Compare-FoxVersion 'v2.3.0' '2.3' | Should -Be 0
        Compare-FoxVersion 'v2.2.1' '2.3.0' | Should -Be -1
        Compare-FoxVersion 'v10.0' 'v9.9.9' | Should -Be 1
        Compare-FoxVersion 'v2.3.0-rc1' '2.3.0' | Should -Be -1
        Compare-FoxVersion 'main' '2.3.0' | Should -BeNullOrEmpty
    }

    It 'accepts a listing that names the tag being installed' {
        { Assert-FoxVersion "$script:zeros  VERSION=v2.3.0`n" 'v2.3.0' } | Should -Not -Throw
    }

    It 'refuses a listing signed for another version' {
        { Assert-FoxVersion "$script:zeros  VERSION=v2.0.1`n" 'v99.0.0' } | Should -Throw '*signed for v2.0.1*'
    }

    It 'refuses a listing that names two versions' {
        { Assert-FoxVersion "$script:zeros  VERSION=v2.3.0`n$script:zeros  VERSION=v2.0.1`n" 'v2.3.0' } | Should -Throw '*more than one version*'
    }

    It 'refuses a release from the cutoff on that names no version' {
        { Assert-FoxVersion (('a' * 64) + "  fox-windows-amd64.exe`n") "v$FirstVersionedRelease" } | Should -Throw '*does not say which version*'
    }

    It 'still installs an older release, which never had the line' {
        { Assert-FoxVersion (('a' * 64) + "  fox-windows-amd64.exe`n") 'v2.2.1' } | Should -Not -Throw
    }

    It 'never mistakes the version line for a file' {
        Set-Variable -Name FoxSums -Scope Script -Value "$script:zeros  VERSION=v2.3.0`n"
        Set-Variable -Name FoxDistroSums -Scope Script -Value ''
        { Get-FoxChecksum 'VERSION=v2.3.0' } | Should -Throw '*not listed in SHA256SUMS*'
    }
}

# Finding SUP-5: the P-256 signature, which Windows can check. Every key here
# is a throwaway made by the test.
Describe 'P-256 release signature' {
    BeforeAll {
        . "$PSScriptRoot/install.ps1"
        function New-TestKey {
            $k = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
            $q = $k.ExportParameters($false).Q
            $point = [byte[]](@(4) + $q.X + $q.Y)
            return @{ Key = $k; Pub = [Convert]::ToBase64String($point) }
        }
        # .NET signs as r||s; releases carry DER, as openssl and Go write it.
        function ConvertTo-Der([byte[]]$Raw) {
            $body = @()
            foreach ($k in 0, 1) {
                [byte[]]$v = $Raw[($k * 32)..($k * 32 + 31)]
                $s = 0
                while ($s -lt 31 -and $v[$s] -eq 0) { $s++ }
                [byte[]]$v = $v[$s..31]
                if ($v[0] -ge 0x80) { [byte[]]$v = @([byte]0) + $v }
                $body += @([byte]2, [byte]$v.Length) + $v
            }
            return ,([byte[]](@([byte]0x30, [byte]$body.Length) + $body))
        }
        function New-TestSignature($TestKey, [byte[]]$Data) {
            $raw = $TestKey.Key.SignData($Data, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
            return ,(ConvertTo-Der $raw)
        }
        $script:data = [System.Text.Encoding]::UTF8.GetBytes(('0' * 64) + "  VERSION=v2.3.0`n" + ('a' * 64) + "  fox-windows-amd64.exe`n")
        $script:release = New-TestKey
        $script:other = New-TestKey
    }
    # A test pins a key with a plain assignment in its own block, never with
    # Set-Variable -Scope Script: install.ps1 was dot-sourced in BeforeAll, so
    # its (empty) $ReleaseP256PublicKey sits between the test and script scope
    # and would hide a script-scope one, and the fail-closed tests would only
    # ever see "no key yet". The assignment ends with the test.
    AfterEach {
        $env:FOX_ALLOW_UNSIGNED = $null
    }

    It 'accepts a signature by the pinned key' {
        $sig = New-TestSignature $script:release $script:data
        Test-FoxSignature $script:data $sig $script:release.Pub | Should -BeTrue
    }

    It 'refuses a signature by another key' {
        $sig = New-TestSignature $script:other $script:data
        Test-FoxSignature $script:data $sig $script:release.Pub | Should -BeFalse
    }

    It 'refuses a listing altered after signing' {
        $sig = New-TestSignature $script:release $script:data
        $altered = [byte[]]($script:data + [byte]10)
        Test-FoxSignature $altered $sig $script:release.Pub | Should -BeFalse
    }

    It 'refuses something that is not a DER signature' {
        Test-FoxSignature $script:data ([byte[]](1..64)) $script:release.Pub | Should -BeFalse
    }

    It 'fails closed once a key is pinned: no signature, no install' {
        $ReleaseP256PublicKey = $script:release.Pub
        Mock Get-FoxBytes { throw 'not found' }
        { Assert-FoxSignature $script:data 'SHA256SUMS.p256.sig' } | Should -Throw '*has no SHA256SUMS.p256.sig*'
    }

    It 'fails closed once a key is pinned: a bad signature stops the install' {
        $ReleaseP256PublicKey = $script:release.Pub
        $script:mockSig = New-TestSignature $script:other $script:data
        Mock Get-FoxBytes { $script:mockSig }
        { Assert-FoxSignature $script:data 'SHA256SUMS.p256.sig' } | Should -Throw '*does not match*'
    }

    It 'passes a good signature once a key is pinned' {
        $ReleaseP256PublicKey = $script:release.Pub
        $script:mockSig = New-TestSignature $script:release $script:data
        Mock Get-FoxBytes { $script:mockSig }
        { Assert-FoxSignature $script:data 'SHA256SUMS.p256.sig' } | Should -Not -Throw
    }

    It 'FOX_ALLOW_UNSIGNED=1 installs on checksums alone' {
        $ReleaseP256PublicKey = $script:release.Pub
        $env:FOX_ALLOW_UNSIGNED = '1'
        Mock Get-FoxBytes { throw 'not found' }
        { Assert-FoxSignature $script:data 'SHA256SUMS.p256.sig' } | Should -Not -Throw
    }

    It 'only warns while no P-256 key is pinned' {
        Mock Get-FoxBytes { throw 'not found' }
        { Assert-FoxSignature $script:data 'SHA256SUMS.p256.sig' -WarningAction SilentlyContinue } | Should -Not -Throw
    }

    It 'ships with the same P-256 key as fox (or, until it is made, none)' {
        $go = Get-Content -Raw "$PSScriptRoot/../internal/update/signing.go"
        $go -match 'var releaseP256PublicKey = "([^"]*)"' | Should -BeTrue
        $src = Get-Content -Raw "$PSScriptRoot/install.ps1"
        $src -match "(?m)^\`$ReleaseP256PublicKey = '([^']*)'" | Should -BeTrue
        $Matches[1] | Should -Be ([regex]::Match($go, 'var releaseP256PublicKey = "([^"]*)"').Groups[1].Value)
    }
}

# Findings SUP-3 and SUP-8: after a reboot the install resumes with a released
# installer, for the same release, never with whatever is on main.
Describe 'resume after reboot' {
    BeforeAll { . "$PSScriptRoot/install.ps1" }
    AfterEach { Set-Variable -Name Version -Scope Script -Value 'latest' }

    It 'resumes the same release, with that release''s installer' {
        Set-Variable -Name Version -Scope Script -Value 'v2.4.0'
        $cmd = Get-ResumeCommand
        $cmd | Should -Match ([regex]::Escape("`$env:FOX_VERSION='v2.4.0'"))
        $cmd | Should -Match ([regex]::Escape('https://github.com/thefoxbyte/foxbyte/releases/download/v2.4.0/install.ps1'))
    }

    It 'uses the latest release''s installer for a release that has none of its own' {
        Set-Variable -Name Version -Scope Script -Value 'v2.2.1'
        $cmd = Get-ResumeCommand
        $cmd | Should -Match ([regex]::Escape("`$env:FOX_VERSION='v2.2.1'"))
        $cmd | Should -Match ([regex]::Escape('https://github.com/thefoxbyte/foxbyte/releases/latest/download/install.ps1'))
    }

    It 'keeps the edition' {
        Get-ResumeCommand | Should -Match ([regex]::Escape("`$env:FOX_EDITION='standard'"))
    }

    It 'never fetches from main' {
        $src = Get-Content -Raw "$PSScriptRoot/install.ps1"
        $src | Should -Not -Match 'raw\.githubusercontent\.com/[^ ]*/main/'
    }
}

Describe 'installer prefers the prebuilt distro' {
    BeforeAll { $script:src = Get-Content -Raw (Join-Path $PSScriptRoot 'install.ps1') }

    It 'downloads the distro image, zstd first and gzip for older releases' {
        # Single-quoted: inside double quotes PowerShell would interpolate $name
        # (unset here), and the pattern would look for "foreach ( in ...)".
        $script:src | Should -Match ([regex]::Escape('foreach ($name in ''foxbyte-distro.tar.zst'', ''foxbyte-distro.tar.gz'')'))
        $script:src | Should -Match ([regex]::Escape('Get-FoxAsset $name'))
    }

    It 'skips an image the release does not list instead of downloading a 404' {
        $script:src | Should -Match ([regex]::Escape('if (-not (Test-FoxAssetListed $name)) { continue }'))
    }

    It 'falls back to the Ubuntu rootfs when the distro is unusable' {
        $script:src | Should -Match 'falling back to the Ubuntu rootfs'
    }

    It 'verifies every FoxByte asset it keeps' {
        # The launcher and the engine are named from the edition, so looking for
        # their literal names would only prove a string appears somewhere in the
        # file. Assert the verification call itself instead -- which is what the
        # literal scan was standing in for.
        $script:src | Should -Match ([regex]::Escape('Assert-FoxChecksum "$Prefix\$Cli.exe" $HostAsset'))
        $script:src | Should -Match ([regex]::Escape('Assert-FoxChecksum "$Prefix\$EngineAsset" $EngineAsset'))
        foreach ($name in 'foxbyte-docker-context.tar.gz', 'foxbyte-distro.tar.zst', 'foxbyte-distro.tar.gz') {
            $script:src | Should -Match ([regex]::Escape("Assert-FoxChecksum"))
            $script:src | Should -Match ([regex]::Escape($name))
        }
    }

    It 'names both binaries after the edition it was asked for' {
        # A Standard engine under an Enterprise launcher would offer commands the
        # engine does not have, and the mismatch reads as a bug rather than a
        # mixed install. Both names come from one $BinName.
        $script:src | Should -Match '\$BinName\s*=\s*\$Cli\b'
        $script:src | Should -Match '\$BinName\s*=\s*"\$Cli-enterprise"'
        $script:src | Should -Match '\$HostAsset\s*=\s*"\$BinName-windows-amd64\.exe"'
        $script:src | Should -Match '\$EngineAsset\s*=\s*"\$BinName-linux-amd64"'
    }

    It 'refuses an edition it does not have a binary for' {
        $script:src | Should -Match 'unknown FOX_EDITION'
    }
}

Describe 'install.ps1 encoding' {
    It 'has no UTF-8 BOM' {
        $b = [System.IO.File]::ReadAllBytes("$PSScriptRoot/install.ps1")
        ($b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) | Should -BeFalse
    }
    It 'is pure ASCII' {
        $bad = [System.IO.File]::ReadAllBytes("$PSScriptRoot/install.ps1") | Where-Object { $_ -gt 127 }
        $bad | Should -BeNullOrEmpty
    }
    It 'parses the way iex would receive it' {
        $text = [System.IO.File]::ReadAllText("$PSScriptRoot/install.ps1")
        { [scriptblock]::Create($text) } | Should -Not -Throw
    }
}

# TC4.8 -- Windows ships tar.exe (10 1803+/11); the installer uses it to expand
# the image build context, so a missing tar is a hard install failure.
Describe 'tar.exe availability' {
    It 'is present on PATH' {
        Get-Command tar.exe -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}
