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
    }
    AfterAll { $env:FOX_NO_VERIFY = $null }

    It 'reads a checksum from the release listing' {
        Get-FoxChecksum 'fox-windows-amd64.exe' | Should -Be ('a' * 64)
    }

    It 'accepts the binary-mode "*name" form' {
        Get-FoxChecksum 'foxbyte-distro.tar.gz' | Should -Be ('b' * 64)
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
        foreach ($name in 'fox-windows-amd64.exe', 'fox-linux-amd64', 'foxbyte-docker-context.tar.gz', 'foxbyte-distro.tar.zst', 'foxbyte-distro.tar.gz') {
            $script:src | Should -Match ([regex]::Escape("Assert-FoxChecksum"))
            $script:src | Should -Match ([regex]::Escape($name))
        }
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
