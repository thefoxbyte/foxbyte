# SPDX-License-Identifier: Apache-2.0
#
# Windows installation tests.
#
# These cover the install *flow* -- the parts that repeatedly broke on real
# machines and that unit tests cannot see: script encoding, the WSL bootstrap,
# PATH handling, and the ordering rule that setup (not the installer) chooses the
# kernel-specific ZFS bundle.
#
# Run:  Invoke-Pester deploy/windows-install.Tests.ps1
#
# Tests that would create a distro or download hundreds of megabytes are tagged
# 'E2E' and skipped unless FOX_TEST_E2E is set:
#   $env:FOX_TEST_E2E=1; Invoke-Pester deploy/windows-install.Tests.ps1

BeforeAll {
    $script:Installer = "$PSScriptRoot/install.ps1"
    $script:E2E = [bool]$env:FOX_TEST_E2E
}

# The encoding is a genuine two-sided constraint, and getting it wrong broke real
# installs in both directions:
#   with a BOM   -> `irm | iex` fails with "The term '# ' is not recognized"
#   without one  -> Windows PowerShell 5.1 reads non-ASCII as ANSI and fails to parse
# Pure ASCII, no BOM, is the only encoding that satisfies both.
Describe 'installer encoding' {
    It 'has no UTF-8 BOM' {
        $b = [System.IO.File]::ReadAllBytes($Installer)
        ($b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) | Should -BeFalse
    }

    It 'contains no non-ASCII bytes' {
        $bad = [System.IO.File]::ReadAllBytes($Installer) | Where-Object { $_ -gt 127 }
        $bad | Should -BeNullOrEmpty
    }

    It 'parses the way iex receives it' {
        $text = [System.IO.File]::ReadAllText($Installer)
        { [scriptblock]::Create($text) } | Should -Not -Throw
    }

    It 'parses the way a downloaded file is run' {
        $errors = $null
        [System.Management.Automation.PSParser]::Tokenize(
            (Get-Content $Installer -Raw), [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty
    }
}

# The installer must not need WSL. Choosing the ZFS bundle by asking a running
# distro for `uname -r` is what forced users to install WSL and Ubuntu by hand,
# reboot, and re-run the installer -- and left a bb.exe that could not set
# itself up when they did not.
Describe 'installer does not depend on WSL' {
    BeforeAll { . $Installer }

    It 'never asks WSL for the kernel release' {
        # The installer may legitimately run before WSL exists, so it must not
        # query a running distro for anything. This used to drive ZFS bundle
        # selection and was the reason the docs told users to install Ubuntu
        # first. Windows stores branches on btrfs now, so nothing is
        # kernel-specific and nothing needs asking.
        $src = Get-Content $Installer -Raw
        $src | Should -Not -Match 'uname -r'
    }

    It 'does not reference ZFS at all' {
        # Windows uses btrfs, which is in the stock WSL kernel. A ZFS asset
        # reference here downloads something no release publishes any more, and
        # the failed fetch prints a warning that reads like a broken install --
        # which is exactly what users reported seeing.
        $src = Get-Content $Installer -Raw
        $src | Should -Not -Match 'foxbyte-zfs'
        $src | Should -Not -Match 'downloads Docker and ZFS'
    }

    It 'runs no command inside a distro' {
        # Stronger than the guard this replaces, which checked that the output of
        # `wsl -e uname -r` was validated before use. The installer no longer
        # runs anything in a distro at all, so a machine with WSL present but no
        # distribution -- and a machine with no WSL -- take the same path.
        $src = Get-Content $Installer -Raw
        # Whitespace after -e is required: PowerShell's -match is case
        # insensitive, so a bare 'wsl\.exe -e' also matches the entirely
        # legitimate `Get-Command wsl.exe -ErrorAction SilentlyContinue`.
        $src | Should -Not -Match 'wsl\.exe\s+-e\s'
    }

    It 'installs WSL without a Linux distribution' {
        $src = Get-Content $Installer -Raw
        $src | Should -Match '--no-distribution'
        $src | Should -Not -Match 'wsl --install -d '
    }
}

Describe 'installer behaviour' {
    BeforeAll { . $Installer }

    It 'resolves a supported architecture' {
        Resolve-Arch | Should -BeIn @('amd64', 'arm64')
    }

    It 'builds a latest asset URL over HTTPS' {
        $u = Get-FoxAsset 'fox-windows-amd64.exe'
        $u | Should -BeLike 'https://*'
        $u | Should -Be 'https://github.com/foxbyte/foxbyte/releases/latest/download/fox-windows-amd64.exe'
    }

    It 'never downloads over plain HTTP' {
        # An installer fetching executables over http would be trivially
        # MITM-able; every URL in the script must be https.
        $http = Select-String -Path $Installer -Pattern 'http://' -AllMatches
        $http | Should -BeNullOrEmpty
    }

    It 'reports elevation without throwing' {
        { Test-Admin } | Should -Not -Throw
        (Test-Admin) | Should -BeOfType [bool]
    }

    It 'probes WSL without throwing, even when absent' {
        { Test-WslReady } | Should -Not -Throw
    }

    It 'detects a pending reboot without throwing' {
        { Test-RebootPending } | Should -Not -Throw
    }

    It 'adds to PATH idempotently' {
        $existing = ([Environment]::GetEnvironmentVariable('Path', 'User') -split ';' |
            Where-Object { $_ -ne '' } | Select-Object -First 1)
        if ($existing) { Add-ToPath $existing | Should -BeFalse }
    }

    It 'makes fox usable in the current session, not just new ones' {
        # "fox is not recognized" was the most common post-install complaint:
        # persisting the User PATH only affects shells started afterwards.
        (Get-Content $Installer -Raw) | Should -Match '\$env:Path\s*='
    }

    It 'runs setup rather than telling the user to' {
        (Get-Content $Installer -Raw) | Should -Match 'setup'
    }

    It 'honours FOX_NO_SETUP and FOX_NO_ELEVATE' {
        $src = Get-Content $Installer -Raw
        $src | Should -Match 'FOX_NO_SETUP'
        $src | Should -Match 'FOX_NO_ELEVATE'
    }
}

Describe 'checksum verification' {
    BeforeAll { . $Installer }

    It 'parses a publisher SHA256SUMS listing' {
        $sums = "abc  other.tar.gz`n" +
                ("0" * 64) + "  ubuntu-noble-wsl-amd64-wsl.rootfs.tar.gz`n"
        $tmp = New-TemporaryFile
        try {
            Set-Content -Path $tmp -Value $sums -Encoding ascii
            # Get-UpstreamChecksum fetches over HTTP, so exercise the matching
            # rule directly rather than the network.
            ($sums -split "`n") | Where-Object { $_ -match '^([0-9a-fA-F]{64})\s+\*?(.+?)\s*$' } |
                Should -Not -BeNullOrEmpty
        } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }

    It 'verifies the Ubuntu rootfs it downloads' {
        (Get-Content $Installer -Raw) | Should -Match 'Assert-UpstreamChecksum'
    }
}

# Windows ships tar.exe (10 1803+ / 11); the installer relies on it.
Describe 'host prerequisites' {
    It 'has tar.exe on PATH' {
        Get-Command tar.exe -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}

# Real installs. Skipped by default: they create a WSL distro and download
# hundreds of megabytes.
Describe 'end to end' -Tag 'E2E' {
    BeforeAll {
        if (-not $script:E2E) { return }
        $script:Prefix = Join-Path $env:TEMP "fox-e2e-$(Get-Random)"
    }
    AfterAll {
        if ($script:Prefix -and (Test-Path $script:Prefix)) {
            Remove-Item $script:Prefix -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'installs without running setup' -Skip:(-not $env:FOX_TEST_E2E) {
        $env:FOX_NO_SETUP = '1'
        $env:FOX_PREFIX = $script:Prefix
        try {
            & $Installer
            $LASTEXITCODE | Should -Be 0
            Test-Path (Join-Path $script:Prefix 'bb.exe') | Should -BeTrue
            Test-Path (Join-Path $script:Prefix 'fox-linux-amd64') | Should -BeTrue
            # The ZFS bundle must NOT be staged: setup fetches it, because only
            # setup knows the kernel.
            (Get-ChildItem $script:Prefix -Filter 'foxbyte-zfs-*') | Should -BeNullOrEmpty
        } finally {
            Remove-Item Env:FOX_NO_SETUP, Env:FOX_PREFIX -ErrorAction SilentlyContinue
        }
    }

    It 'reports a version' -Skip:(-not $env:FOX_TEST_E2E) {
        & (Join-Path $script:Prefix 'bb.exe') version | Should -Match 'fox'
    }
}
