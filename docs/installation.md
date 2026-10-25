# Installation

The native releases bundle the CLI, MCP server, Ghidra worker, and investigation
skill. They support macOS 13+ and Linux with glibc 2.35+ (such as Ubuntu 22.04+),
on ARM64 and x86-64. Prebuilt packages are not available for Windows or
musl-based Linux distributions.

```sh
curl -fsSL https://github.com/nanashili/rea-rust/releases/latest/download/install.sh -o install-rea.sh
sh install-rea.sh
export PATH="$HOME/.local/bin:$PATH"
rea --version
```

The installer requires `curl` or `wget`, `tar`, and `sha256sum` or `shasum`.
It verifies the archive against the release's `SHA256SUMS`, installs under your
account, and activates the version through a symlink. No sudo or package
manager is used. Other providers, browser tooling, and platform utilities are
installed separately when needed.

## Paths and versions

The default executable is `~/.local/bin/rea`. Files live under
`${XDG_DATA_HOME:-$HOME/.local/share}/rea-rust/versions/<version>/<target>`.
The Ghidra worker stays beside the real executable; keep that layout intact.

To select a version or custom absolute paths:

```sh
REA_VERSION=6.7.0 sh install-rea.sh
REA_INSTALL_ROOT="$HOME/tools/rea-rust" REA_BIN_DIR="$HOME/bin" sh install-rea.sh
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

Use your own home directory on Linux or macOS. The server runs locally over
stdio; the client launches the installed binary. `rea mcp doctor --json`
reports installation and client configuration details. After an update, rerun
`rea setup` if you used it to register a versioned executable path, then restart
the client's REA connection. Manual registrations using `~/.local/bin/rea`
follow the active version automatically.

## Removal

`rea uninstall` removes owned client registrations and skills. It leaves the
installed executables in place. After unregistering, remove the `rea` symlink
and the installation directory you selected. With the default paths:

```sh
rea uninstall
rm "$HOME/.local/bin/rea"
rm -r "${XDG_DATA_HOME:-$HOME/.local/share}/rea-rust"
```

Analysis caches and evidence are separate from the installation. Remove them
only if you intend to discard that local data.
