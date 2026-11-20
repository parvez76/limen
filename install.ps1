# Parvez installer for Windows (PowerShell 5.1 and 7+).
#
#   irm https://parvez76.github.io/parvez/install.ps1 | iex
#
# Downloads the release for Windows, checks it against the release's SHA256SUMS
# (and its GitHub build attestation when the `gh` CLI is installed), installs
# parvez.exe to %USERPROFILE%\.parvez\bin and adds that to your user PATH (no
# admin rights needed). Parvez builds your programs with the Rust toolchain; if
# it's missing, the installer offers to set it up with the official rustup-init.exe.
#
# `iex` can't take parameters, so options are environment variables:
#   $env:PARVEZ_VERSION = "v0.18.0"    a release tag (default: the latest)
#   $env:PARVEZ_HOME = "D:\tools\pz"   install location (default: %USERPROFILE%\.parvez)
#   $env:PARVEZ_YES = "1"              don't ask; install Rust if it's missing
#   $env:PARVEZ_NO_RUST = "1"          never install Rust
#   $env:PARVEZ_NO_MODIFY_PATH = "1"   don't change the user PATH

& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'   # the progress bar makes downloads very slow in PowerShell 5.1
    # PowerShell 5.1 may not offer TLS 1.2 by default; GitHub requires it
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $Repo = 'parvez76/parvez'
    $LegacyRepo = 'parvez76/project-parvez'   # releases before the rename were attested under this name
    $DownloadBase = if ($env:PARVEZ_DOWNLOAD_BASE) { $env:PARVEZ_DOWNLOAD_BASE } else { "https://github.com/$Repo/releases/download" }
    $LatestApi = if ($env:PARVEZ_LATEST_API) { $env:PARVEZ_LATEST_API } else { "https://api.github.com/repos/$Repo/releases/latest" }
    $InstallHome = if ($env:PARVEZ_HOME) { $env:PARVEZ_HOME } else { Join-Path $env:USERPROFILE '.parvez' }

    function Say([string]$m) { Write-Host "parvez-install: $m" }
    # never `exit`: under `iex` that would close the user's PowerShell window
    function Fail([string]$m) { Write-Host "parvez-install: error: $m" -ForegroundColor Red; throw "parvez-install: $m" }

    # ---- platform ------------------------------------------------------------
    $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    switch ($arch) {
        'AMD64' { $target = 'x86_64-pc-windows-msvc' }
        'ARM64' { $target = 'x86_64-pc-windows-msvc'; Say 'Windows on ARM: using the x64 build (it runs under the built-in emulation)' }
        default { Fail "no prebuilt Parvez for $arch Windows. Build it from source: cargo install --git https://github.com/$Repo --locked" }
    }
    if (-not (Get-Command tar.exe -ErrorAction SilentlyContinue)) { Fail 'this installer needs tar.exe (included in Windows 10 version 1803 and later)' }

    # ---- version -------------------------------------------------------------
    $version = $env:PARVEZ_VERSION
    if (-not $version) {
        try { $version = (Invoke-RestMethod -Uri $LatestApi -UseBasicParsing).tag_name } catch { Fail "could not reach GitHub to find the latest release: $_" }
    }
    if ($version -notmatch '^v\d+\.\d+\.\d+$') { Fail "unexpected release tag `"$version`"" }

    # ---- download and verify ---------------------------------------------------
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("parvez-install-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        $archive = "parvez-$version-$target.tar.gz"
        $archivePath = Join-Path $tmp $archive
        $sumsPath = Join-Path $tmp 'SHA256SUMS'
        Say "downloading Parvez $version for $target"
        try {
            Invoke-WebRequest -Uri "$DownloadBase/$version/$archive" -OutFile $archivePath -UseBasicParsing
            Invoke-WebRequest -Uri "$DownloadBase/$version/SHA256SUMS" -OutFile $sumsPath -UseBasicParsing
        } catch { Fail "download failed: $_" }

        $expected = $null
        foreach ($line in Get-Content $sumsPath) {
            $parts = $line -split '\s+', 2
            if ($parts.Count -eq 2 -and $parts[1].TrimStart('*').Trim() -eq $archive -and $parts[0] -match '^[0-9a-fA-F]{64}$') { $expected = $parts[0].ToLower() }
        }
        if (-not $expected) { Fail "$archive is not listed in SHA256SUMS" }
        $actual = (Get-FileHash -Algorithm SHA256 -Path $archivePath).Hash.ToLower()
        if ($actual -ne $expected) { Fail "checksum mismatch for $archive (expected $expected, got $actual). Nothing was installed." }
        Say 'checksum OK'

        if (Get-Command gh -ErrorAction SilentlyContinue) {
            & gh attestation verify $archivePath --repo $Repo *> $null
            if ($LASTEXITCODE -ne 0) { & gh attestation verify $archivePath --repo $LegacyRepo *> $null }
            if ($LASTEXITCODE -ne 0) { Fail "the GitHub build attestation for $archive did not verify. Nothing was installed." }
            Say "build attestation OK (built by $Repo's release workflow)"
        } else {
            Say 'tip: install the GitHub CLI (gh) and the installer also checks the build attestation'
        }

        # ---- install --------------------------------------------------------------
        & tar.exe -xzf $archivePath -C $tmp
        if ($LASTEXITCODE -ne 0) { Fail "could not unpack $archive" }
        $src = Join-Path $tmp "parvez-$version-$target\parvez.exe"
        if (-not (Test-Path $src)) { Fail 'the archive has no parvez.exe' }
        $bin = Join-Path $InstallHome 'bin'
        New-Item -ItemType Directory -Force -Path $bin | Out-Null
        $dest = Join-Path $bin 'parvez.exe'
        # a running parvez.exe can't be overwritten, but it can be renamed (uniquely:
        # an older leftover may still be running); leftovers are removed when free
        Get-ChildItem -Path $bin -Filter '.parvez.old*' -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        if (Test-Path $dest) { Move-Item -Force $dest (Join-Path $bin (".parvez.old-" + [Guid]::NewGuid().ToString('N'))) }
        Copy-Item $src $dest
        Say "installed $(& $dest --version) to $bin"
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }

    # ---- PATH -----------------------------------------------------------------
    if ($env:PARVEZ_NO_MODIFY_PATH -ne '1') {
        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        $entries = if ($userPath) { $userPath -split ';' } else { @() }
        if ($entries -notcontains $bin) {
            $new = if ($userPath) { "$bin;$userPath" } else { $bin }
            [Environment]::SetEnvironmentVariable('Path', $new, 'User')
            Say "added $bin to your user PATH"
        }
    }
    if (($env:Path -split ';') -notcontains $bin) { $env:Path = "$bin;$env:Path" }   # this window too

    # ---- Rust -------------------------------------------------------------------
    $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
    $haveCargo = (Get-Command cargo -ErrorAction SilentlyContinue) -or (Test-Path (Join-Path $cargoHome 'bin\cargo.exe'))
    if (-not $haveCargo) {
        Say "Parvez builds your programs with the Rust toolchain, which isn't installed."
        $install = $false
        if ($env:PARVEZ_NO_RUST -eq '1') {
            $install = $false
        } elseif ($env:PARVEZ_YES -eq '1') {
            $install = $true
        } elseif ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {
            $answer = Read-Host 'parvez-install: install Rust now with the official installer (rustup.rs)? [Y/n]'
            $install = -not ($answer -match '^[nN]')
        }
        if ($install) {
            $init = Join-Path ([IO.Path]::GetTempPath()) 'rustup-init.exe'
            Invoke-WebRequest -Uri 'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe' -OutFile $init -UseBasicParsing
            & $init -y --profile minimal
            if ($LASTEXITCODE -ne 0) { Fail 'installing Rust failed; see https://rustup.rs' }
            Remove-Item -Force $init -ErrorAction SilentlyContinue
            $env:Path = "$(Join-Path $cargoHome 'bin');$env:Path"
            Say 'Rust installed'
        } else {
            Say 'install Rust later from https://rustup.rs (rustup-init.exe)'
        }
    }

    # Rust's linker on Windows comes from the Visual Studio C++ build tools
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $vcTools = $null
    if (Test-Path $vswhere) {
        $vcTools = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    }
    if (-not $vcTools) {
        Say "Rust also needs the Visual Studio C++ build tools (its linker on Windows). Install them with:"
        Write-Host '    winget install Microsoft.VisualStudio.2022.BuildTools --override "--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"'
    }

    Write-Host ''
    Say 'done. Open a new terminal, then:'
    Write-Host '    parvez doctor          # check the setup'
    Write-Host '    parvez new hello       # start a project'
    Write-Host '    parvez upgrade         # later: update to the newest release'
}
