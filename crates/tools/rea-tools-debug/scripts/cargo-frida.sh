#!/usr/bin/env bash
# Run cargo with the pinned frida-core devkit and the `frida` feature.
#
# Usage (from native/): crates/tools/rea-tools-debug/scripts/cargo-frida.sh build -p rea --release
# Appends `--features rea-tools-debug/frida` to the cargo arguments.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
eval "$("$here/fetch-frida-devkit.sh" --env)"

# Cargo treats every argument after `--` as an argument to the test or run
# binary. Insert the feature before that separator so `cargo-frida.sh test
# ... -- --nocapture` still enables the Frida feature on Cargo itself.
args=("$@")
feature=(--features rea-tools-debug/frida)
for index in "${!args[@]}"; do
    if [[ "${args[index]}" == "--" ]]; then
        args=("${args[@]:0:index}" "${feature[@]}" "${args[@]:index}")
        exec cargo "${args[@]}"
    fi
done

exec cargo "${args[@]}" "${feature[@]}"
