#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
temp_dir=$(mktemp -d)
trap 'rm -rf "$temp_dir"' EXIT

cat >"$temp_dir/cargo" <<'FAKE_CARGO'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" >"$CARGO_FRIDA_TEST_LOG"
FAKE_CARGO
chmod +x "$temp_dir/cargo"

export CARGO_FRIDA_TEST_LOG="$temp_dir/args"
PATH="$temp_dir:$PATH" "$script_dir/cargo-frida.sh" test -p rea-tools-debug -- --nocapture

expected=(test -p rea-tools-debug --features rea-tools-debug/frida -- --nocapture)
actual=$(tr '\n' ' ' <"$CARGO_FRIDA_TEST_LOG")
expected_text="${expected[*]} "
if [[ "$actual" != "$expected_text" ]]; then
    printf 'unexpected cargo arguments:\n%s\n' "$(cat "$CARGO_FRIDA_TEST_LOG")" >&2
    exit 1
fi

printf 'cargo-frida.sh preserves the Cargo/test argument separator\n'
