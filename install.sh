#!/bin/sh
set -eu

REPOSITORY=nanashili/rea-rust
INSTALL_ROOT=${REA_INSTALL_ROOT:-${XDG_DATA_HOME:-$HOME/.local/share}/rea-rust}
BIN_DIR=${REA_BIN_DIR:-$HOME/.local/bin}
REQUESTED_VERSION=${REA_VERSION:-}
TARGET='' VERSION_TAG='' DOWNLOAD_BASE='' TEMP_DIR='' ARCHIVE='' CHECKSUMS='' ARCHIVE_NAME='' STAGE=''
RELEASE_VERSION='' VERSION_DIR=''

error() {
    printf '%s\n' "rea-rust installer: $*" >&2
    exit 1
}

cleanup() {
    if [ -n "${TEMP_DIR:-}" ] && [ -d "$TEMP_DIR" ] && ! rm -rf "$TEMP_DIR"; then
        printf '%s\n' "rea-rust installer: could not remove temporary directory $TEMP_DIR" >&2
        return 1
    fi
}
on_signal() {
    cleanup
    exit 130
}
trap cleanup 0
trap on_signal 1 2 3 15

download() {
    url=$1
    destination=$2
    if command -v curl >/dev/null 2>&1; then
        curl --fail --location --silent --show-error --retry 3 --output "$destination" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget --quiet --output-document="$destination" "$url"
    else
        error "curl or wget is required"
    fi
}

detect_target() {
    case "$(uname -s):$(uname -m)" in
        Darwin:arm64|Darwin:aarch64) TARGET=aarch64-apple-darwin ;;
        Darwin:x86_64|Darwin:amd64) TARGET=x86_64-apple-darwin ;;
        Linux:x86_64|Linux:amd64) TARGET=x86_64-unknown-linux-gnu ;;
        Linux:arm64|Linux:aarch64) TARGET=aarch64-unknown-linux-gnu ;;
        *) error "unsupported platform: $(uname -s) $(uname -m)" ;;
    esac
}

configure_download() {
    if [ -n "$REQUESTED_VERSION" ]; then
        printf '%s\n' "$REQUESTED_VERSION" | grep -Eq '^v?[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$' \
            || error "REA_VERSION must be a semantic version such as 0.1.0 or v0.1.0"
        VERSION_TAG=$REQUESTED_VERSION
        case "$VERSION_TAG" in v*) ;; *) VERSION_TAG="v$VERSION_TAG" ;; esac
        REQUESTED_VERSION=${VERSION_TAG#v}
        DOWNLOAD_BASE="https://github.com/$REPOSITORY/releases/download/$VERSION_TAG"
    else
        DOWNLOAD_BASE="https://github.com/$REPOSITORY/releases/latest/download"
    fi
}

resolve_paths() {
    case "$INSTALL_ROOT:$BIN_DIR" in
        /*:/*) ;;
        *) error "REA_INSTALL_ROOT and REA_BIN_DIR must be absolute paths" ;;
    esac
    mkdir -p "$INSTALL_ROOT" "$BIN_DIR"
    INSTALL_ROOT=$(CDPATH='' cd -P "$INSTALL_ROOT" && pwd)
    BIN_DIR=$(CDPATH='' cd -P "$BIN_DIR" && pwd)
    [ ! -L "$INSTALL_ROOT/versions" ] || error "refusing symlinked versions directory"
    mkdir -p "$INSTALL_ROOT/versions"
}

download_release() {
    TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/rea-rust-install.XXXXXX")
    ARCHIVE_NAME="rea-rust-$TARGET.tar.gz"
    ARCHIVE="$TEMP_DIR/$ARCHIVE_NAME"
    CHECKSUMS="$TEMP_DIR/SHA256SUMS"
    STAGE="$TEMP_DIR/stage"
    printf 'Downloading REA Rust (%s) for %s...\n' "${VERSION_TAG:-latest}" "$TARGET"
    download "$DOWNLOAD_BASE/$ARCHIVE_NAME" "$ARCHIVE" || error "could not download $ARCHIVE_NAME"
    download "$DOWNLOAD_BASE/SHA256SUMS" "$CHECKSUMS" || error "could not download SHA256SUMS"
}

verify_checksum() {
    expected_sha=$(awk -v file="$ARCHIVE_NAME" '$2 == file || $2 == "*" file { print $1; exit }' "$CHECKSUMS")
    printf '%s\n' "$expected_sha" | grep -Eq '^[[:xdigit:]]{64}$' || error "SHA256SUMS has no valid checksum for $ARCHIVE_NAME"
    if command -v sha256sum >/dev/null 2>&1; then
        actual_sha=$(sha256sum "$ARCHIVE" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual_sha=$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')
    else
        error "sha256sum or shasum is required"
    fi
    [ "$expected_sha" = "$actual_sha" ] || error "checksum mismatch for $ARCHIVE_NAME"
}

verify_archive_paths() {
    archive_list="$TEMP_DIR/archive.list"
    tar -tzf "$ARCHIVE" >"$archive_list" || error "archive is not a readable gzip tar archive"
    awk '$0 !~ /^rea-rust\// || $0 ~ /(^|\/)\.\.(\/|$)/ || $0 ~ /^\// { bad=1 } END { exit bad }' "$archive_list" \
        || error "archive contains an unsafe path"
    tar -tvzf "$ARCHIVE" | awk '$1 !~ /^[-d]/ { bad=1 } END { exit bad }' \
        || error "archive contains a symlink, hard link, or special file"
}

json_value() {
    key=$1
    sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$STAGE/rea-rust/release.json" | sed -n '1p'
}

verify_payload() {
    mkdir "$STAGE"
    tar -xzf "$ARCHIVE" -C "$STAGE" || error "could not extract archive"
    [ -d "$STAGE/rea-rust" ] || error "archive must contain a rea-rust/ directory"
    [ -f "$STAGE/rea-rust/release.json" ] || error "archive is missing release.json"
    [ -f "$STAGE/rea-rust/VERSION" ] || error "archive is missing VERSION"
    [ -x "$STAGE/rea-rust/bin/rea" ] || error "archive is missing executable bin/rea"
    [ -x "$STAGE/rea-rust/bin/rea-ghidra-rust-worker" ] || error "archive is missing executable Ghidra worker"
    RELEASE_VERSION=$(sed -n '1p' "$STAGE/rea-rust/VERSION")
    release_target=$(json_value target)
    [ -n "$RELEASE_VERSION" ] || error "VERSION is empty"
    [ -z "$REQUESTED_VERSION" ] || [ "$RELEASE_VERSION" = "$REQUESTED_VERSION" ] || error "release version does not match requested version"
    [ "$release_target" = "$TARGET" ] || error "release target is $release_target, expected $TARGET"
    printf '%s\n' "$RELEASE_VERSION" | grep -Eq '^v?[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$' || error "VERSION contains an invalid version"
    reported_version=$("$STAGE/rea-rust/bin/rea" --version 2>/dev/null) || error "rea could not report its version"
    [ "$reported_version" = "$RELEASE_VERSION" ] || [ "$reported_version" = "v$RELEASE_VERSION" ] || error "rea reports version $reported_version, expected $RELEASE_VERSION"
    (CDPATH='' cd "$STAGE/rea-rust" && ./bin/rea --verify-installation) \
        || error "release manifest verification failed"
}

verify_existing_install() {
    VERSION_DIR="$INSTALL_ROOT/versions/$RELEASE_VERSION/$TARGET"
    [ ! -L "$INSTALL_ROOT/versions/$RELEASE_VERSION" ] || error "refusing symlinked release directory"
    if [ ! -e "$VERSION_DIR" ] && [ ! -L "$VERSION_DIR" ]; then
        REUSE_VERSION_DIR=0
        return
    fi
    [ ! -L "$VERSION_DIR" ] || error "refusing symlinked installation directory"
    [ -d "$VERSION_DIR" ] || error "existing installation path is not a directory"
    [ -f "$VERSION_DIR/.rea-rust-install" ] || error "refusing to reuse unowned installation"
    grep -Fqx "version=$RELEASE_VERSION" "$VERSION_DIR/.rea-rust-install" || error "existing installation has a different version"
    grep -Fqx "target=$TARGET" "$VERSION_DIR/.rea-rust-install" || error "existing installation has a different target"
    while IFS= read -r relative_path; do
        [ -f "$VERSION_DIR/$relative_path" ] || error "existing installation is missing $relative_path"
        cmp -s "$STAGE/rea-rust/$relative_path" "$VERSION_DIR/$relative_path" || error "existing installation differs in $relative_path"
    done <<EOF
$(cd "$STAGE/rea-rust" && find . -type f ! -name '.rea-rust-install' -print | sed 's#^./##')
EOF
    REUSE_VERSION_DIR=1
}

validate_existing_link() {
    LINK="$BIN_DIR/rea"
    if [ -e "$LINK" ] && [ ! -L "$LINK" ]; then
        error "refusing to overwrite existing file $LINK"
    fi
    if [ ! -L "$LINK" ]; then
        return
    fi
    link_target=$(readlink "$LINK")
    case "$link_target" in
        *..*) error "refusing symlink traversal in $LINK" ;;
    esac
    case "$link_target" in "$INSTALL_ROOT"/versions/*/bin/rea) link_root=${link_target%/bin/rea} ;; *) error "refusing to overwrite unrelated symlink $LINK" ;; esac
    [ -d "$link_root" ] || error "refusing symlink to missing installation"
    canonical_link_root=$(CDPATH='' cd -P "$link_root" && pwd) || error "could not resolve existing installation symlink"
    [ "$canonical_link_root" = "$link_root" ] || error "refusing symlink through a linked installation directory"
    [ -f "$link_root/.rea-rust-install" ] || error "refusing to overwrite unowned symlink"
    grep -Fqx "target=$TARGET" "$link_root/.rea-rust-install" || error "refusing symlink for another target"
}

stage_install() {
    mkdir -p "$INSTALL_ROOT/versions/$RELEASE_VERSION"
    if [ "$REUSE_VERSION_DIR" -eq 0 ]; then
        printf 'version=%s\ntarget=%s\nrepository=%s\n' "$RELEASE_VERSION" "$TARGET" "$REPOSITORY" >"$STAGE/rea-rust/.rea-rust-install"
        mv "$STAGE/rea-rust" "$VERSION_DIR" || error "could not install staged release"
    fi
}

activate() {
    old_target=
    if [ -L "$LINK" ]; then
        old_target=$(readlink "$LINK")
    fi
    if [ "$old_target" = "$VERSION_DIR/bin/rea" ]; then
        return
    fi
    temporary_link="$BIN_DIR/.rea-rust.$$"
    if ! ln -s "$VERSION_DIR/bin/rea" "$temporary_link"; then
        error "could not stage $LINK"
    fi
    if ! mv -f "$temporary_link" "$LINK"; then
        rm -f "$temporary_link"
        error "could not activate $LINK"
    fi
}

main() {
    command -v tar >/dev/null 2>&1 || error "tar is required"
    command -v mktemp >/dev/null 2>&1 || error "mktemp is required"
    detect_target
    configure_download
    resolve_paths
    download_release
    verify_checksum
    verify_archive_paths
    verify_payload
    verify_existing_install
    validate_existing_link
    stage_install
    activate
    printf '\nInstalled REA Rust %s for %s.\n' "$RELEASE_VERSION" "$TARGET"
    printf 'Executable: %s/rea\n' "$BIN_DIR"
    case ":${PATH:-}:" in
        *:"$BIN_DIR":*) ;;
        *) printf "Add this to PATH: export PATH=\"%s:\$PATH\"\n" "$BIN_DIR" ;;
    esac
    printf 'MCP: add {"command":"%s/rea","args":["mcp"]} to your client config.\n' "$BIN_DIR"
}

main "$@"
