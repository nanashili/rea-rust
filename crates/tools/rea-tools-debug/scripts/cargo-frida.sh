#!/bin/sh
# Run cargo with the pinned frida-core devkit and the `frida` feature.
#
# Usage (from native/): crates/tools/rea-tools-debug/scripts/cargo-frida.sh build -p rea --release
# Appends `--features rea-tools-debug/frida` to the cargo arguments.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
eval "$("$here/fetch-frida-devkit.sh" --env)"
exec cargo "$@" --features rea-tools-debug/frida
