#!/usr/bin/env bash
# fetch.sh - robust fetcher for lfsctl
# Responsibilities:
#  - read package manifest
#  - download sources & patches (mirrors, aria2c, curl, wget)
#  - verify checksums and formats
#  - unpack sources to build dir
#  - apply patches with rollback
#  - run hooks (pre/post) in sandbox
#  - extensive error handling, logging, recovery and concurrency protections
#
# Usage: fetch.sh <package> [--force] [--dry-run] [--manifest <path>] [--allow-http]
#
set -Eeuo pipefail
IFS=$'\n\t'

# ---- helpers: find project lib files (try multiple locations) ----
_find_and_source() {
  local name="$1" candidate
  # allow LFS_ROOT to be set externally
  : "${LFS_ROOT:=${PWD}}"
  local tries=(
    "$LFS_ROOT/lib/$name"
    "$LFS_ROOT/lib/$name.sh"
    "$(dirname "$0")/../lib/$name"
    "$(dirname "$0")/../lib/$name.sh"
    "$(dirname "$0")/lib/$name"
    "$(dirname "$0")/lib/$name.sh"
    "/usr/local/lib/lfsctl/$name"
    "/usr/local/lib/lfsctl/$name.sh"
  )
  for candidate in "${tries[@]}"; do
    [ -f "$candidate" ] || continue
    # shellcheck disable=SC1090
    source "$candidate"
    return 0
  done
  return 1
}

# try to source log and utils; if missing, provide basic fallbacks
if ! _find_and_source "log"; then
  echo "WARNING: lib/log.sh not found; using minimal logger" >&2
  log_info() { printf "[INFO] %s\n" "$*"; }
  log_warn() { printf "[WARN] %s\n" "$*"; }
  log_error() { printf "[ERROR] %s\n" "$*" >&2; }
  log_debug(){ [ "${LOG_LEVEL:-0}" -ge 3 ] && printf "[DEBUG] %s\n" "$*"; }
  log_ok() { printf "[OK] %s\n" "$*"; }
  log_section(){ printf "==> %s\n" "$*"; }
  log_run(){ log_section "$1"; shift; "$@"; }
fi

if ! _find_and_source "utils"; then
  echo "ERROR: lib/utils.sh not found in common locations." >&2
  echo "Please ensure lib/utils.sh is installed and try again." >&2
  exit 1
fi

# ---- initialization ----
: "${FETCH_LOG_DIR:=${LFS_LOGS:-${PWD}/logs}/fetch}"
ensure_dir "$FETCH_LOG_DIR" || true

DRY_RUN=0
FORCE=0
MANIFEST_PATH=""
ALLOW_HTTP=0
PKG=""
VERBOSE=0

usage() {
  cat <<EOF
Usage: $(basename "$0") <pkg> [options]
Options:
  --force           : force re-download & re-prepare
  --dry-run         : show operations without performing destructive actions
  --manifest <file> : explicit manifest file path
  --allow-http      : allow fallback to http mirrors (less secure)
  -v|--verbose      : verbose mode (debug)
  -h|--help         : show this help
EOF
  exit "${1:-0}"
}

fetch_on_error() {
  local lineno=${1:-0} rc=${2:-1}
  log_error "fetch.sh: error at line ${lineno} (rc=${rc})"
  log_error "Package: ${PKG:-unknown}"
  [ -n "${CURRENT_LOG:-}" ] && log_error "See log: ${CURRENT_LOG}"
  # attempt to leave build dir in recoverable state
  exit "$rc"
}
trap 'fetch_on_error ${LINENO} $?' ERR

# ---- parse args ----
_parse_args() {
  if [ $# -lt 1 ]; then usage 1; fi
  while [ $# -gt 0 ]; do
    case "$1" in
      --force) FORCE=1; shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      --manifest) MANIFEST_PATH="$2"; shift 2 ;;
      --allow-http) ALLOW_HTTP=1; LFS_ALLOW_HTTP=1; shift ;;
      -v|--verbose) VERBOSE=1; log_set_level debug; shift ;;
      -h|--help) usage 0 ;;
      --) shift; break ;;
      -*)
        log_error "Unknown option: $1"; usage 1;;
      *)
        if [ -z "$PKG" ]; then PKG="$1"; shift; else
          log_warn "Ignoring extra arg: $1"; shift;
        fi
        ;;
    esac
  done
  if [ -z "$PKG" ]; then log_error "No package specified"; usage 1; fi
  export PKG FORCE DRY_RUN ALLOW_HTTP
}

# ---- manifest reading & validation ----
fetch_read_manifest() {
  # supports shell-style manifest at pkgs/<pkg>/metadata or provided path
  local pkg="$1"
  local manifest=""
  if [ -n "$MANIFEST_PATH" ]; then
    manifest="$MANIFEST_PATH"
  else
    manifest="pkgs/$pkg/metadata"
    [ -f "$manifest" ] || manifest="pkgs/$pkg/metadata.sh"
  fi
  if [ ! -f "$manifest" ]; then
    log_error "Manifest not found for package $pkg (looked at $manifest)"
    return 2
  fi
  # read manifest in subshell to avoid polluting env; capture important vars
  local tmpfile; tmpfile=$(mktemp -t "manifest-${pkg}.XXXX") || return 1
  # ensure manifest defines NAME and VERSION and URLS or SOURCE_URLS
  # Use a safe parser: extract lines that look like assignments for known fields
  awk '/^NAME=|^VERSION=|^SOURCE_URLS=|^URLS=|^CHECKSUM=|^PATCHES=|^DEPENDENCIES=/' "$manifest" > "$tmpfile"
  # shellcheck disable=SC1090
  ( set -o posix; . "$tmpfile"; printf "OK" ) 2>/dev/null || true
  # Source into associative scratch via subshell to extract values
  # For simplicity, we source into current shell but guard variable names
  unset NAME VERSION CHECKSUM PATCHES SOURCE_URLS URLS DEPENDENCIES || true
  # shellcheck disable=SC1090,SC1091
  . "$tmpfile" || { rm -f "$tmpfile"; log_error "Failed to parse manifest $manifest"; return 3; }
  rm -f "$tmpfile"
  # normalize arrays/values
  PACKAGE_NAME="${NAME:-$pkg}"
  PACKAGE_VERSION="${VERSION:-}"
  PACKAGE_CHECKSUM="${CHECKSUM:-}"
  # coalesce URLS/SOURCE_URLS
  if [ "${#SOURCE_URLS[@]-}" -gt 0 ]; then
    SOURCE_URLS=("${SOURCE_URLS[@]}")
  elif [ "${#URLS[@]-}" -gt 0 ]; then
    SOURCE_URLS=("${URLS[@]}")
  else
    SOURCE_URLS=()
  fi
  if [ "${#SOURCE_URLS[@]}" -eq 0 ]; then
    log_error "No SOURCE_URLS defined in manifest for $pkg"
    return 4
  fi
  PATCHES_ARRAY=()
  if [ "${#PATCHES[@]-}" -gt 0 ]; then PATCHES_ARRAY=("${PATCHES[@]}"); fi
  DEP_ARRAY=()
  if [ "${#DEPENDENCIES[@]-}" -gt 0 ]; then DEP_ARRAY=("${DEPENDENCIES[@]}"); fi
  export PACKAGE_NAME PACKAGE_VERSION PACKAGE_CHECKSUM SOURCE_URLS PATCHES_ARRAY DEP_ARRAY
  return 0
}

# ---- per-package locking to avoid race conditions ----
_pkg_lock_acquire() {
  local pkg="$1"
  local lockdir="${LFS_CACHE}/locks/${pkg}.lock"
  ensure_dir "$(dirname "$lockdir")"
  local i=0
  while ! mkdir "$lockdir" 2>/dev/null; do
    i=$((i+1))
    sleep 0.1
    [ $i -ge 200 ] && { log_error "Timeout acquiring lock for $pkg"; return 1; }
  done
  printf "%s" "$lockdir"
}
_pkg_lock_release() {
  local lockdir="$1"; rm -rf "$lockdir" || true
}

# ---- main fetch operations ----
_fetch_download_and_cache() {
  local url="$1" outdir="$2" expected="$3"
  local fname dest cache_key cache_path
  fname=$(basename "$url")
  cache_key=$(fetch_cache_path "$url" | xargs -n1 basename)
  cache_path="$LFS_CACHE/downloads/$cache_key"
  dest="$outdir/$fname"
  ensure_dir "$outdir"
  # try cache
  if cache_get "$cache_key" "$dest" >/dev/null 2>&1; then
    log_info "Using cache for $url -> $dest"
    if [ -n "$expected" ]; then
      if ! verify_checksum "$dest" "$expected"; then
        log_warn "Cached file checksum mismatch, removing cache and re-downloading"
        rm -f "$dest" "$cache_path" || true
      else
        return 0
      fi
    else
      return 0
    fi
  fi
  # try mirrors resolution
  local candidate resolved tried=0
  local candidates=()
  for candidate in "${SOURCE_URLS[@]}"; do candidates+=("$candidate"); done
  # Prepend resolved mirrors for first candidate only to avoid over-expanding
  if resolve_mirror "${SOURCE_URLS[0]}" >/dev/null 2>&1; then
    local m; m=$(resolve_mirror "${SOURCE_URLS[0]}") || true
    [ -n "$m" ] && candidates=("$m" "${candidates[@]}")
  fi
  local success=1
  for candidate in "${candidates[@]}"; do
    tried=$((tried+1))
    log_info "Attempting download candidate ($tried/${#candidates[@]}): $candidate"
    if [ "$DRY_RUN" -eq 1 ]; then
      log_info "(DRY-RUN) would download $candidate to $dest"
      success=0
      break
    fi
    if download_file "$candidate" "$dest" "$expected"; then
      log_ok "Downloaded $candidate -> $dest"
      success=0
      break
    else
      log_warn "Candidate failed: $candidate"
    fi
  done
  if [ $success -ne 0 ]; then
    # try http fallback if allowed
    if [ "${ALLOW_HTTP:-0}" -eq 1 ] && [[ "${SOURCE_URLS[0]}" == https:* ]]; then
      local http="${SOURCE_URLS[0]/https:\/\//http://}"
      log_warn "Trying HTTP fallback: $http"
      if download_file "$http" "$dest" "$expected"; then
        log_ok "HTTP fallback succeeded"
        return 0
      fi
    fi
    log_error "All download attempts failed for URL list of package ${PKG}"
    return 2
  fi
  # verify checksum if provided (download_file already does if expected passed)
  if [ -n "$expected" ]; then
    verify_checksum "$dest" "$expected" || { log_error "Checksum failed for $dest"; rm -f "$dest"; return 3; }
  else
    # generate checksum meta
    verify_checksum "$dest" || true
  fi
  # add to cache
  cache_add "$dest" "$cache_key" || log_warn "Warning: cache_add failed for $dest"
  return 0
}

_fetch_download_patches() {
  local pkg="$1" patches_dir="$2" outdir="$3"
  [ -d "$patches_dir" ] || { log_info "No patch dir for $pkg"; return 0; }
  ensure_dir "$outdir"
  # iterate patch files in sorted order
  local f
  while IFS= read -r -d '' f; do
    local base; base=$(basename "$f")
    local dest="$outdir/$base"
    # if patch is a local file inside pkgs/<pkg>/patches, copy; otherwise treat as URL
    if [[ "$f" = /* ]] || [[ "$f" = ./* ]] || [[ "$f" = pkgs/* ]]; then
      cp -a -- "$f" "$dest" || { log_error "Failed to copy patch $f"; return 1; }
      verify_checksum "$dest" || true
    else
      # treat as URL
      if ! _fetch_download_and_cache "$f" "$outdir" ""; then
        log_error "Failed to download patch $f for $pkg"
        return 1
      fi
    fi
  done < <(find "$patches_dir" -maxdepth 1 -type f -print0 | sort -z)
  return 0
}

_fetch_unpack_and_prepare() {
  local pkg="$1" src_archive="$2" build_root="$3"
  ensure_dir "$build_root"
  local tmpdir; tmpdir=$(mktemp -d -t "build-${pkg}.XXXX") || return 1
  # extract into tmpdir
  log_info "Extracting $src_archive into $tmpdir"
  if [ "$DRY_RUN" -eq 1 ]; then
    log_info "(DRY-RUN) would extract $src_archive to $tmpdir"
    return 0
  fi
  tar_extract "$src_archive" "$tmpdir" || { log_error "Extraction failed for $src_archive"; rm -rf "$tmpdir"; return 2; }
  # find top-level dir (first entry)
  local top; top=$(find "$tmpdir" -maxdepth 1 -mindepth 1 -type d | head -n1 || true)
  if [ -z "$top" ]; then
    # maybe files directly; move into build_root/pkg-version
    mv "$tmpdir"/* "$build_root/" 2>/dev/null || true
  else
    mv "$top"/* "$build_root/" || true
  fi
  rm -rf "$tmpdir"
  chmod -R u+rwX "$build_root" || true
  log_info "Prepared build dir: $build_root"
  return 0
}

_fetch_apply_patches() {
  local pkg="$1" patches_dir="$2" build_root="$3"
  if [ ! -d "$patches_dir" ]; then log_debug "No patches to apply for $pkg"; return 0; fi
  # create backup of build_root before applying patches
  local backup="${build_root}.backup.$(date +%s)"
  cp -a -- "$build_root" "$backup" || { log_error "Failed to backup before patching"; return 1; }
  log_info "Applying patches for $pkg (backup: $backup)"
  # iterate patches in order and apply with patch -p1 inside build_root
  local f base rc=0
  while IFS= read -r -d '' f; do
    base=$(basename "$f")
    log_info "Applying patch: $base"
    if [ -x "$f" ]; then
      sandbox_exec "$f" || { rc=$?; log_error "Patch script failed: $base (rc=$rc)"; break; }
    else
      (cd "$build_root" && patch -p1 < "$f") || { rc=$?; log_error "patch -p1 failed for $base (rc=$rc)"; break; }
    fi
  done < <(find "$patches_dir" -maxdepth 1 -type f -print0 | sort -z)
  if [ $rc -ne 0 ]; then
    log_error "Patching failed; restoring backup"
    rm -rf "$build_root" || true
    mv -f "$backup" "$build_root" || true
    return $rc
  fi
  rm -rf "$backup" || true
  log_info "Patches applied successfully for $pkg"
  return 0
}

# ---- hook execution helper ----
fetch_run_hooks() {
  local stage="$1" pkg="$2" hooks_global_dir="hooks/global/${stage}" hooks_pkg_dir="pkgs/${pkg}/hooks/${stage}"
  local any=0
  for h in "$hooks_global_dir"/* "$hooks_pkg_dir"/*; do
    [ -f "$h" ] || continue
    any=1
    log_info "Running hook: $h (stage: $stage)"
    if [ "$DRY_RUN" -eq 1 ]; then log_info "(DRY-RUN) would run $h"; continue; fi
    sandbox_exec "$h" || { log_error "Hook failed: $h"; return 1; }
  done
  if [ $any -eq 0 ]; then log_debug "No hooks for stage $stage (pkg $pkg)"; fi
  return 0
}

# ---- high-level orchestrator ----
fetch_one_package() {
  local pkg="$1"
  local lock; lock=$(_pkg_lock_acquire "$pkg") || return 1
  log_section "fetch: $pkg"
  local logpath="${FETCH_LOG_DIR}/${pkg}-$(date -u +%Y%m%dT%H%M%SZ).log"
  CURRENT_LOG="$logpath"
  ensure_dir "$(dirname "$logpath")"
  # redirect detailed logs to CURRENT_LOG via fd 7 (do not clobber stderr)
  exec 7>>"$logpath" || { log_error "Failed to open per-package log $logpath"; _pkg_lock_release "$lock"; return 1; }
  export LOG_FILE="$logpath"
  log_info "Logging to $logpath"
  # read manifest
  if ! fetch_read_manifest "$pkg"; then log_error "Manifest read failed for $pkg"; exec 7>&-; _pkg_lock_release "$lock"; return 2; fi
  # show minimal progress to terminal
  printf "Fetching %s %s -> log: %s\n" "${PACKAGE_NAME:-$pkg}" "${PACKAGE_VERSION:-}" "$logpath"
  # run pre-fetch hooks
  fetch_run_hooks pre-fetch "$pkg" || { log_error "pre-fetch hooks failed"; exec 7>&-; _pkg_lock_release "$lock"; return 3; }
  # download source (first URL list entry used for mirror resolution)
  local outdir="${LFS_CACHE}/work/${pkg}"; ensure_dir "$outdir"
  if [ "$FORCE" -eq 1 ]; then rm -f "$outdir"/* || true; fi
  if ! _fetch_download_and_cache "${SOURCE_URLS[0]}" "$outdir" "${PACKAGE_CHECKSUM:-}"; then log_error "Source download failed for $pkg"; exec 7>&-; _pkg_lock_release "$lock"; return 4; fi
  # assume downloaded file is first entry in outdir
  local downloaded; downloaded=$(ls -1 "$outdir" 2>/dev/null | head -n1 || true)
  if [ -z "$downloaded" ]; then log_error "No downloaded file found for $pkg"; exec 7>&-; _pkg_lock_release "$lock"; return 5; fi
  local src_archive="$outdir/$downloaded"
  # verify format & integrity
  fetch_verify_format() {
    local f="$1"
    if file -b --mime-type "$f" | grep -qiE 'html|xml|text'; then log_error "Downloaded file appears to be HTML (error page): $f"; return 2; fi
    # basic extension check
    case "$f" in *.tar.*|*.zip|*.tgz|*.tar) return 0;; *) log_warn "Unknown archive extension for $f"; return 0;; esac
  }
  fetch_verify_format "$src_archive" || { log_error "Format check failed for $src_archive"; exec 7>&-; _pkg_lock_release "$lock"; return 6; }
  # download patches if present
  local patches_dir="pkgs/${pkg}/patches"
  local patch_outdir="${outdir}/patches"
  if ! _fetch_download_patches "$pkg" "$patches_dir" "$patch_outdir"; then log_error "Failed to download patches for $pkg"; exec 7>&-; _pkg_lock_release "$lock"; return 7; fi
  # create build dir
  local build_root="${LFS_BUILD}/${pkg}-${PACKAGE_VERSION:-unknown}"
  ensure_dir "$build_root"
  if [ "$FORCE" -eq 1 ]; then rm -rf "$build_root"/* || true; fi
  # unpack and prepare
  if ! _fetch_unpack_and_prepare "$pkg" "$src_archive" "$build_root"; then log_error "Prepare failed for $pkg"; exec 7>&-; _pkg_lock_release "$lock"; return 8; fi
  # run pre-patch hooks
  fetch_run_hooks pre-patch "$pkg" || { log_error "pre-patch hooks failed"; exec 7>&-; _pkg_lock_release "$lock"; return 9; }
  # apply patches
  if [ -d "$patch_outdir" ]; then
    if ! _fetch_apply_patches "$pkg" "$patch_outdir" "$build_root"; then log_error "Patch application failed for $pkg"; exec 7>&-; _pkg_lock_release "$lock"; return 10; fi
  fi
  # run post-patch hooks
  fetch_run_hooks post-patch "$pkg" || { log_error "post-patch hooks failed"; exec 7>&-; _pkg_lock_release "$lock"; return 11; }
  # success summary
  log_ok "Fetch prepared for $pkg at $build_root"
  log_info "Package ready: $pkg"
  # close log FD and release lock
  exec 7>&-
  _pkg_lock_release "$lock"
  return 0
}

# ---- main ----
main() {
  _parse_args "$@"
  utils_init || { log_error "utils_init failed"; exit 1; }
  check_root || true
  detect_cores || true
  ensure_dir "$FETCH_LOG_DIR" || true
  # perform fetch for one package
  fetch_one_package "$PKG"
}

main "$@"
