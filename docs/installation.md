# Installation

The native releases bundle the CLI, MCP server, Ghidra worker, and investigation
skill. They support macOS 13+, Linux with glibc 2.35+ (such as Ubuntu 22.04+),
Windows 10+ x64, and Windows 11 ARM64. Each platform has ARM64 and x86-64
archives. Musl Linux does not have prebuilt packages.

```sh
curl -fsSL https://github.com/nanashili/rea-rust/releases/latest/download/install.sh -o install-rea.sh
sh install-rea.sh
export PATH="$HOME/.local/bin:$PATH"
rea --version
```

On Windows, use PowerShell:

```powershell
irm https://github.com/nanashili/rea-rust/releases/latest/download/install.ps1 -OutFile install-rea.ps1
powershell -ExecutionPolicy Bypass -File .\install-rea.ps1
& "$env:LOCALAPPDATA\rea-rust\bin\rea.cmd" --version
```

The Unix installer requires `curl` or `wget`, `tar`, and `sha256sum` or `shasum`.
The Windows installer uses PowerShell's built-in download, ZIP, and SHA-256
support and selects the native Windows architecture, including from an emulated
shell. Both install under your account, verify the archive against the
release's `SHA256SUMS`, and require no sudo, administrator account, or package
manager. Other providers, browser tooling, and platform utilities are installed
separately when needed.

Linux download names omit the Rust vendor field, for example
`rea-rust-x86_64-linux-gnu.tar.gz` and `rea-rust-aarch64-linux-gnu.tar.gz`.
The manifest and installation directory keep the canonical Rust target, such as
`x86_64-unknown-linux-gnu`.

## Paths and versions

The default executable is `~/.local/bin/rea`. Files live under
`${XDG_DATA_HOME:-$HOME/.local/share}/rea-rust/versions/<version>/<target>`.
The Ghidra worker stays beside the real executable; keep that layout intact.

On Windows, files live under
`%LOCALAPPDATA%\rea-rust\versions\<version>\<target>`, where `<target>` is
`x86_64-pc-windows-msvc` or `aarch64-pc-windows-msvc`.
The stable launcher is `%LOCALAPPDATA%\rea-rust\bin\rea.cmd`; the worker stays
beside `rea.exe` in the versioned directory.

To select a version or custom absolute paths:

```sh
REA_VERSION=6.7.0 sh install-rea.sh
REA_INSTALL_ROOT="$HOME/tools/rea-rust" REA_BIN_DIR="$HOME/bin" sh install-rea.sh
```

PowerShell uses the same version selector and accepts absolute custom paths:

```powershell
$env:REA_VERSION = '6.7.0'
$env:REA_INSTALL_ROOT = 'D:\Tools\rea-rust'
$env:REA_BIN_DIR = 'D:\Tools\bin'
powershell -ExecutionPolicy Bypass -File .\install-rea.ps1
```

Rerun the installer to update. Existing versions are retained, and unrelated
executables are never overwritten. `rea update` directs native installations
back to the installer. Shell profile changes remain yours to make.

## MCP clients

Run `rea setup` to review supported client registrations and skill destinations.
It asks for approval before writing and backs up existing configuration. For
manual configuration, use an absolute path with the `mcp` argument:

```json
{
  "mcpServers": {
    "rea": {
      "command": "/Users/you/.local/bin/rea",
      "args": ["mcp"]
    }
  }
}
```

Use your own home directory on Linux or macOS. On Windows, run `rea setup`
from PowerShell using the stable launcher. Setup resolves and registers the
versioned `rea.exe` path, so MCP clients do not need to launch a `.cmd` file.
The server runs locally over stdio; the client launches the installed binary.
`rea mcp doctor --json`
reports installation and client configuration details. After an update, rerun
`rea setup` and restart the client's REA connection.

For a manual Windows registration, use the actual versioned executable and
escape backslashes in JSON:

```json
{
  "mcpServers": {
    "rea": {
      "command": "C:\\Users\\you\\AppData\\Local\\rea-rust\\versions\\6.7.0\\x86_64-pc-windows-msvc\\bin\\rea.exe",
      "args": ["mcp"]
    }
  }
}
```

Repeat the manual update after installing a newer version. Unix registrations
using `~/.local/bin/rea` follow the active version automatically.

## Removal

`rea uninstall` removes owned client registrations and skills. It leaves the
installed executables in place. After unregistering, remove the `rea` symlink
and the installation directory you selected. With the default paths:

```sh
rea uninstall
rm "$HOME/.local/bin/rea"
rm -r "${XDG_DATA_HOME:-$HOME/.local/share}/rea-rust"
```

On Windows, after `rea uninstall`, remove the owned default directory if you
also want to remove the installed binaries:

```powershell
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\rea-rust"
```

Analysis caches and evidence are separate from the installation. Remove them
only if you intend to discard that local data.

## CI builds and release builds

Every pull request and push to `main` builds and smoke-tests all six native
platforms with Cargo's `ci` profile (optimization level 1, no LTO, 16 codegen
units). These Actions archives are for validation; they are not published as
GitHub releases. Version tags and manual workflow runs use the unchanged fully
optimized `release` profile. Only a version tag can publish a GitHub release.

Installer checks run alongside native builds. All checks must pass before assets
can be collected or published. The independently built Ghidra worker may be
reused only when its source, build configuration, toolchain, target, profile,
and runner image match; the packaged CLI and worker are smoke-tested every run.
