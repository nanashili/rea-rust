#!/bin/sh
# Build and exercise the real C ABI in a private, automatically retired directory.
set -eu
cd "$(dirname "$0")"
case "$(uname -s)" in
    Darwin|Linux) ;;
    *) echo "C ABI verification currently supports macOS and Linux only" >&2; exit 1 ;;
esac
temporary=$(mktemp -d "${TMPDIR:-/tmp}/rea-c-abi.XXXXXXXX")
trap 'rm -rf "$temporary"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export CARGO_TARGET_DIR="$temporary/target"
cargo build --locked --offline --release
compiler=${CC:-cc}
for source in tests/abi.c examples/inspect_process_stat.c; do
    binary="$temporary/$(basename "$source" .c)"
    "$compiler" -std=c11 -Wall -Wextra -Werror -I include "$source" \
        -L "$CARGO_TARGET_DIR/release" -lrea_ffi \
        "-Wl,-rpath,$CARGO_TARGET_DIR/release" -o "$binary"
done
"$temporary/abi"
record='42 (worker) S 17 18 19 0 0 4 0 0 0 0 0 0 0 0 0 0 0 0 000123'
actual=$("$temporary/inspect_process_stat" "$record")
expected='pid=42 parent=17 group=18 session=19 lifecycle=2 start_time=000123'
test "$actual" = "$expected"
if "$temporary/inspect_process_stat" 'malformed' > "$temporary/out" 2> "$temporary/error"; then
    echo 'malformed input unexpectedly succeeded' >&2
    exit 1
fi
grep -F 'status=3 kind=1 field=0' "$temporary/error" >/dev/null
echo 'C shared-library ABI and example checks passed'
