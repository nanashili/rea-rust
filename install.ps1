$ErrorActionPreference = 'Stop'

# Per-user Windows installer for the native REA release.
# The script never edits PATH, PowerShell profiles, or machine-wide state.

$Repository = 'nanashili/rea-rust'
$Target = 'x86_64-pc-windows-msvc'
$RequestedVersion = if ($env:REA_VERSION) { $env:REA_VERSION } else { '' }
$InstallRoot = if ($env:REA_INSTALL_ROOT) { $env:REA_INSTALL_ROOT } else { Join-Path $env:LOCALAPPDATA 'rea-rust' }
$BinDirectory = if ($env:REA_BIN_DIR) { $env:REA_BIN_DIR } else { Join-Path $InstallRoot 'bin' }
$TemporaryDirectory = $null
$TemporaryDirectoryCreated = $false
$PrimaryError = $null
$CleanupError = $null

function Fail([string] $Message) {
    throw "rea-rust installer: $Message"
}

function Resolve-AbsoluteDirectory([string] $Path, [string] $Name) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [System.IO.Path]::IsPathRooted($Path)) {
        Fail "$Name must be an absolute path"
    }
    return [System.IO.Path]::GetFullPath($Path)
}

function Assert-NoReparsePoint([string] $Path, [string] $Description) {
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail "refusing a reparse point for $Description`: $Path"
        }
    }
}

function Assert-NoReparseAncestors([string] $Path, [string] $Description) {
    $current = [System.IO.Path]::GetFullPath($Path)
    while ($current) {
        Assert-NoReparsePoint $current $Description
        $parent = Split-Path -Parent $current
        if ($parent -eq $current) { break }
        $current = $parent
    }
}

function Get-ReleaseVersion {
    if (-not $RequestedVersion) { return '' }
    if ($RequestedVersion.StartsWith('v')) { return $RequestedVersion.Substring(1) }
    return $RequestedVersion
}

function Get-DownloadBase {
    if ($RequestedVersion) {
        $tag = if ($RequestedVersion.StartsWith('v')) { $RequestedVersion } else { "v$RequestedVersion" }
        return "https://github.com/$Repository/releases/download/$tag"
    }
    return "https://github.com/$Repository/releases/latest/download"
}

function Download-File([string] $Url, [string] $Destination) {
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing
    } catch {
        Fail "could not download $Url`: $($_.Exception.Message)"
    }
}

function Test-SafeArchiveEntry([System.IO.Compression.ZipArchiveEntry] $Entry) {
    $name = $Entry.FullName.Replace('\', '/')
    if ([string]::IsNullOrWhiteSpace($name) -or $name.StartsWith('/') -or $name.Contains([char]0)) {
        Fail 'archive contains an unsafe path'
    }
    $parts = $name.Split('/')
    if ($parts[0] -ne 'rea-rust' -or ($parts | Where-Object { $_ -eq '..' -or ($_ -eq '' -and $_ -ne $parts[-1]) })) {
        Fail "archive contains an unsafe path: $name"
    }
    $mode = ($Entry.ExternalAttributes -shr 16) -band 0xF000
    if ($mode -eq 0xA000 -or $mode -eq 0x6000 -or $mode -eq 0x2000) {
        Fail "archive contains a link or special file: $name"
    }
}

function Expand-SafeArchive([string] $Archive, [string] $Destination) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        foreach ($entry in $zip.Entries) { Test-SafeArchiveEntry $entry }
        foreach ($entry in $zip.Entries) {
            $relative = $entry.FullName.Replace('\', '/')
            $target = [System.IO.Path]::GetFullPath((Join-Path $Destination $relative))
            $root = [System.IO.Path]::GetFullPath($Destination) + [System.IO.Path]::DirectorySeparatorChar
            if (-not $target.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
                Fail 'archive entry escapes its extraction directory'
            }
            if ($relative.EndsWith('/')) {
                [System.IO.Directory]::CreateDirectory($target) | Out-Null
                continue
            }
            [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($target)) | Out-Null
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $false)
        }
    } finally { $zip.Dispose() }
    foreach ($item in Get-ChildItem -LiteralPath $Destination -Force -Recurse) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail "archive extracted a reparse point: $($item.FullName)"
        }
    }
}

function Get-ManifestValue($Manifest, [string] $Name) {
    $property = $Manifest.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { Fail "release manifest is missing $Name" }
    return [string] $property.Value
}

function Verify-Payload([string] $Stage) {
    $root = Join-Path $Stage 'rea-rust'
    $manifestPath = Join-Path $root 'release.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { Fail 'archive is missing release.json' }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ((Get-ManifestValue $manifest 'name') -ne 'rea-rust' -or [int](Get-ManifestValue $manifest 'schema_version') -ne 1) { Fail 'release manifest identity is invalid' }
    $version = Get-ManifestValue $manifest 'version'
    if ($version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$') { Fail 'release version is not valid SemVer' }
    if ((Get-ReleaseVersion) -and $version -ne (Get-ReleaseVersion)) { Fail 'release version does not match requested version' }
    if ((Get-ManifestValue $manifest 'target') -ne $Target) { Fail 'release target does not match this Windows build' }
    $versionFile = Join-Path $root 'VERSION'
    if (-not (Test-Path -LiteralPath $versionFile -PathType Leaf)) { Fail 'archive is missing VERSION' }
    $versionContent = [System.IO.File]::ReadAllText($versionFile)
    if ($versionContent -ne "$version`r`n" -and $versionContent -ne "$version`n") { Fail 'VERSION does not match release.json' }
    if (-not (Test-Path -LiteralPath (Join-Path $root 'bin/rea.exe') -PathType Leaf)) { Fail 'archive is missing bin/rea.exe' }
    if (-not (Test-Path -LiteralPath (Join-Path $root 'bin/rea-ghidra-rust-worker.exe') -PathType Leaf)) { Fail 'archive is missing the Ghidra worker' }
    $reportedVersion = & (Join-Path $root 'bin/rea.exe') --version 2>$null
    if ($LASTEXITCODE -ne 0 -or $reportedVersion.Trim() -notin @($version, "v$version")) { Fail 'rea reports an unexpected version' }
    $verification = & (Join-Path $root 'bin/rea.exe') --verify-installation 2>&1
    if ($LASTEXITCODE -ne 0) { Fail "release manifest verification failed: $verification" }
    return $version
}

function Write-StableLauncher([string] $VersionedExecutable, [string] $Destination) {
    $temporary = "$Destination.tmp.$PID.$([guid]::NewGuid().ToString('N'))"
    $primaryError = $null
    $cleanupError = $null
    try {
        if (Test-Path -LiteralPath $temporary) { Fail "temporary launcher path already exists: $temporary" }
        $quoted = $VersionedExecutable.Replace('"', '""').Replace('%', '%%')
        $content = "@echo off" + [char]13 + [char]10 + "setlocal DisableDelayedExpansion" + [char]13 + [char]10 + '"' + $quoted + '" %*' + [char]13 + [char]10
        [System.IO.File]::WriteAllText($temporary, $content, [System.Text.UTF8Encoding]::new($false))
        if (Test-Path -LiteralPath $Destination -PathType Leaf) {
            $replaceMethod = [System.IO.File].GetMethod(
                'Replace',
                [type[]]@([string], [string], [string])
            )
            $replaceArguments = [object[]]@($temporary, $Destination, $null)
            $replaceMethod.Invoke($null, $replaceArguments)
        } else {
            [System.IO.File]::Move($temporary, $Destination)
        }
    } catch {
        $primaryError = $_.Exception
    } finally {
        if (Test-Path -LiteralPath $temporary) {
            try { Remove-Item -LiteralPath $temporary -Force }
            catch { $cleanupError = $_.Exception }
        }
    }
    if ($primaryError) {
        if ($cleanupError) { throw "$primaryError; launcher cleanup also failed: $cleanupError" }
        throw $primaryError
    }
    if ($cleanupError) {
        throw "launcher cleanup failed: $cleanupError"
    }
}

function Confirm-OwnedLauncher([string] $LauncherPath, [string] $Root) {
    if (-not (Test-Path -LiteralPath $LauncherPath)) { return }
    Assert-NoReparsePoint $LauncherPath 'the stable launcher'
    $text = [System.IO.File]::ReadAllText($LauncherPath)
    $match = [regex]::Match($text, '(?s)^@echo off\r?\nsetlocal DisableDelayedExpansion\r?\n"(?<target>.+)" %\*\r?\n$')
    if (-not $match.Success) { Fail "refusing to overwrite an unowned launcher: $LauncherPath" }
    $target = [System.IO.Path]::GetFullPath($match.Groups['target'].Value.Replace('%%', '%'))
    $rootPath = [System.IO.Path]::GetFullPath((Join-Path $Root 'versions'))
    if (-not $target.StartsWith($rootPath + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase) -or
        [System.IO.Path]::GetFileName($target) -ne 'rea.exe') {
        Fail "refusing to overwrite an unowned launcher: $LauncherPath"
    }
    Assert-NoReparseAncestors $target 'the launcher target'
    $versionTarget = Split-Path -Parent (Split-Path -Parent $target)
    $marker = Join-Path $versionTarget '.rea-rust-install'
    if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) { Fail "refusing to overwrite an unowned launcher: $LauncherPath" }
}

function Download-Release([string] $Directory) {
    $archiveName = "rea-rust-$Target.zip"
    $archivePath = Join-Path $Directory $archiveName
    $checksumsPath = Join-Path $Directory 'SHA256SUMS'
    $base = Get-DownloadBase
    Write-Host "Downloading REA Rust ($Target)..."
    Download-File "$base/$archiveName" $archivePath
    Download-File "$base/SHA256SUMS" $checksumsPath
    return @($archivePath, $checksumsPath, $archiveName)
}

function Confirm-ArchiveChecksum([string] $ArchivePath, [string] $ChecksumsPath, [string] $ArchiveName) {
    $escaped = [regex]::Escape($ArchiveName)
    $line = Get-Content -LiteralPath $ChecksumsPath | Where-Object { $_ -match "(?:^|\s)\*?$escaped$" } | Select-Object -First 1
    if (-not $line -or $line -notmatch '^([0-9A-Fa-f]{64})\s+\*?(.+)$') { Fail "SHA256SUMS has no valid checksum for $ArchiveName" }
    $actual = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash
    if ($actual -ine $Matches[1]) { Fail 'checksum mismatch' }
}

function Install-Release([string] $Stage, [string] $ReleaseVersion) {
    $destination = Join-Path (Join-Path $InstallRoot 'versions') (Join-Path $ReleaseVersion $Target)
    Assert-NoReparseAncestors (Split-Path -Parent $destination) 'the version directory'
    if (Test-Path -LiteralPath $destination) {
        Assert-NoReparsePoint $destination 'the existing version directory'
        $existingMarker = Join-Path $destination '.rea-rust-install'
        if (-not (Test-Path -LiteralPath $existingMarker -PathType Leaf)) { Fail "refusing to reuse an unowned installation $destination" }
        $markerLines = Get-Content -LiteralPath $existingMarker
        if ($markerLines -notcontains "version=$ReleaseVersion" -or $markerLines -notcontains "target=$Target") { Fail "existing installation has a different identity: $destination" }
        foreach ($item in Get-ChildItem -LiteralPath $destination -Force -Recurse) { Assert-NoReparsePoint $item.FullName 'the existing installation' }
        $sourceRoot = Join-Path $Stage 'rea-rust'
        $stagedFiles = @(Get-ChildItem -LiteralPath $sourceRoot -File -Force -Recurse | Where-Object { $_.Name -ne '.rea-rust-install' })
        $existingFiles = @(Get-ChildItem -LiteralPath $destination -File -Force -Recurse | Where-Object { $_.Name -ne '.rea-rust-install' })
        if ($stagedFiles.Count -ne $existingFiles.Count) { Fail "existing installation contents differ: $destination" }
        foreach ($stagedFile in $stagedFiles) {
            $relative = $stagedFile.FullName.Substring($sourceRoot.Length).TrimStart('\', '/')
            $existingFile = Join-Path $destination $relative
            if (-not (Test-Path -LiteralPath $existingFile -PathType Leaf) -or (Get-FileHash -LiteralPath $stagedFile.FullName -Algorithm SHA256).Hash -ine (Get-FileHash -LiteralPath $existingFile -Algorithm SHA256).Hash) { Fail "existing installation contents differ in $relative" }
        }
        Remove-Item -LiteralPath $sourceRoot -Recurse -Force
    } else {
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
        $marker = "version=$ReleaseVersion" + [char]13 + [char]10 + "target=$Target" + [char]13 + [char]10 + "repository=$Repository" + [char]13 + [char]10
        [System.IO.File]::WriteAllText((Join-Path $Stage 'rea-rust/.rea-rust-install'), $marker, [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath (Join-Path $Stage 'rea-rust') -Destination $destination
    }
    return $destination
}

function Activate-Release([string] $VersionedExecutable) {
    $launcherPath = Join-Path $BinDirectory 'rea.cmd'
    Confirm-OwnedLauncher $launcherPath $InstallRoot
    Write-StableLauncher $VersionedExecutable $launcherPath
    return $launcherPath
}

try {
    $InstallRoot = Resolve-AbsoluteDirectory $InstallRoot 'REA_INSTALL_ROOT'
    $BinDirectory = Resolve-AbsoluteDirectory $BinDirectory 'REA_BIN_DIR'
    Assert-NoReparseAncestors $InstallRoot 'the installation root'
    Assert-NoReparseAncestors $BinDirectory 'the launcher directory'
    New-Item -ItemType Directory -Force -Path (Join-Path $InstallRoot 'versions'), $BinDirectory | Out-Null
    Assert-NoReparseAncestors (Join-Path $InstallRoot 'versions') 'the versions directory'
    $TemporaryDirectory = Join-Path $InstallRoot ".rea-rust-install-$PID"
    if (Test-Path -LiteralPath $TemporaryDirectory) { Fail "temporary installer directory already exists: $TemporaryDirectory" }
    New-Item -ItemType Directory -Path $TemporaryDirectory | Out-Null
    $TemporaryDirectoryCreated = $true

    $download = Download-Release $TemporaryDirectory
    Confirm-ArchiveChecksum $download[0] $download[1] $download[2]
    $stage = Join-Path $TemporaryDirectory 'stage'
    New-Item -ItemType Directory -Path $stage | Out-Null
    Expand-SafeArchive $download[0] $stage
    $releaseVersion = Verify-Payload $stage
    $destination = Install-Release $stage $releaseVersion
    $launcherPath = Activate-Release (Join-Path $destination 'bin/rea.exe')
    Write-Host "Installed REA Rust $releaseVersion for $Target."
    Write-Host "Executable: $launcherPath"
    Write-Host 'Add the bin directory to PATH yourself if desired; the installer does not edit profiles.'
} catch {
    $PrimaryError = $_.Exception
} finally {
    if ($TemporaryDirectoryCreated -and $TemporaryDirectory -and (Test-Path -LiteralPath $TemporaryDirectory)) {
        try { Remove-Item -LiteralPath $TemporaryDirectory -Recurse -Force }
        catch { $CleanupError = $_.Exception }
    }
}

if ($PrimaryError) {
    if ($CleanupError) { Write-Error "$PrimaryError; cleanup also failed: $CleanupError" }
    else { Write-Error $PrimaryError }
    exit 1
}
if ($CleanupError) { Write-Error "installer cleanup failed: $CleanupError"; exit 1 }
