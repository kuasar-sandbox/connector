# Shared tarball fetch and extraction helpers, following the native-deps
# conventions used by Sandboxer and Guest Runtime; not executable on its own.
#
# Callers must set $BUILD_DIR (absolute path to the repo's build/ root).

die() { echo "error: $*" >&2; exit 1; }
log() { echo "==> $*"; }

require_cmd() {
    for c in "$@"; do
        command -v "$c" >/dev/null 2>&1 || die "missing required tool: $c"
    done
}

# resolve_tarball VAR_NAME
#
# Parses the caller-provided tarball spec, caching the tarball at
# $BUILD_DIR/tarball/$filename and echoing that path on stdout.
#
# Accepted spec forms (value of $1):
#   https://host/path/file.tar.gz              url, filename = basename
#   https://host/path/file.tar.gz#pretty.tgz   url, filename = after '#'
#   /abs/or/rel/path.tar.gz                    local file, filename = basename
#
# $2 (optional) is an expected SHA256; empty → skip verification.
resolve_tarball() {
    local spec="$1"
    local sha256="${2:-}"
    [ -n "$spec" ] || die "tarball spec is empty"

    local url="" filename="" local_src=""
    case "$spec" in
        *'#'*)
            url="${spec%#*}"
            filename="${spec##*#}"
            ;;
        http://*|https://*)
            url="$spec"
            # Strip query string, then take basename.
            local u="${url%%\?*}"
            filename="${u##*/}"
            ;;
        *)
            [ -f "$spec" ] || die "local tarball not found: $spec"
            local_src="$spec"
            filename="$(basename "$spec")"
            ;;
    esac
    [ -n "$filename" ] || die "could not derive filename from spec: $spec"

    # Tarball cache is shared across architectures (same upstream source
    # for both x86_64 and aarch64 builds). Defaults under $BUILD_DIR for
    # backward compat with single-arch callers; multi-arch Makefile sets
    # TARBALL_CACHE to an arch-neutral location (build/tarball).
    : "${TARBALL_CACHE:=$BUILD_DIR/tarball}"
    mkdir -p "$TARBALL_CACHE"
    local cache="$TARBALL_CACHE/$filename"

    if [ -f "$cache" ]; then
        log "tarball cache hit: $cache" >&2
    elif [ -n "$url" ]; then
        require_cmd curl
        log "downloading $url → $cache" >&2
        curl -fL --retry 3 -o "$cache.tmp" "$url" \
            || die "source download failed; temporary bytes were not promoted into the cache"
        mv "$cache.tmp" "$cache"
    elif [ -n "$local_src" ]; then
        log "copying $local_src → $cache" >&2
        cp "$local_src" "$cache"
    else
        die "internal: neither url nor local_src set"
    fi

    if [ -n "$sha256" ]; then
        require_cmd sha256sum
        log "verifying sha256 of $cache" >&2
        echo "$sha256  $cache" | sha256sum -c - >&2 || die "sha256 mismatch for $cache"
    fi

    echo "$cache"
}

# extract_tarball TARBALL_PATH DEST_DIR
#
# Extracts $1 into $2. Handles both nested (single top-level dir like
# rocksdb-9.7.4/...) and flat (erofs-utils' github archive) layouts —
# in both cases $DEST_DIR ends up holding the source tree contents
# directly. Re-run idempotent: if $DEST_DIR/.extracted marker exists,
# the extraction is skipped.
#
# Echoes $DEST_DIR on stdout.
extract_tarball() {
    local tarball="$1"
    local dest_dir="$2"
    local marker="$dest_dir/.extracted"

    if [ -f "$marker" ]; then
        log "extract cache hit: $dest_dir" >&2
        echo "$dest_dir"
        return
    fi

    require_cmd tar
    log "extracting $tarball → $dest_dir" >&2
    mkdir -p "$(dirname "$dest_dir")"
    rm -rf "$dest_dir"
    local staging
    staging="$(mktemp -d)"
    tar -xf "$tarball" -C "$staging"

    # If staging has exactly one entry and it's a directory, promote it.
    local entries
    entries=("$staging"/*)
    if [ ${#entries[@]} -eq 1 ] && [ -d "${entries[0]}" ]; then
        mv "${entries[0]}" "$dest_dir"
        rmdir "$staging"
    else
        mkdir -p "$dest_dir"
        # Move both visible and hidden entries.
        shopt -s dotglob nullglob
        mv "$staging"/* "$dest_dir"/
        shopt -u dotglob nullglob
        rmdir "$staging"
    fi

    : > "$marker"
    echo "$dest_dir"
}
