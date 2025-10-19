#!/usr/bin/env bash
# lib/utils.sh
# Robust utility library for lfsctl project.
# Implements: environment detection, safe file ops, downloads with mirrors/aria2c/curl/wget,
# cache with checksum, sandbox_exec unified, retries with exponential backoff, and more.
#
# This script expects lib/log.sh to be available and sourced by callers. If not present,
# it provides minimal fallback logging functions.

set -Eeuo pipefail
IFS=$'\n\t'

# --------------------------- Fallback logging (if lib/log.sh not loaded) ---------------------------
if ! type log_info >/dev/null 2>&1; then
  log_info()  { printf "[INFO] %s\n" "$*"; }
  log_warn()  { printf "[WARN] %s\n" "$*"; }
  log_error() { printf "[ERROR] %s\n" "$*" >&2; }
  log_debug() { [ "${LOG_LEVEL:-0}" -ge 3 ] && printf "[DEBUG] %s\n" "$*"; }
  log_ok()    { printf "[OK] %s\n" "$*"; }
  log_section(){ printf "==> %s\n" "$*"; }
  log_run()   { # simple wrapper: logs, runs, and returns code
    local desc="$1"; shift || true
    log_section "$desc"; log_info "Running: $*"
    "$@" >/dev/null 2>&1 || { local rc=$?; log_error "Command failed ($rc): $*"; return $rc; }
    log_ok "Done: $desc"; return 0
  }
fi

# --------------------------- Defaults & globals ---------------------------
: "${LFS_ROOT:=${PWD}/lfs_root}"
: "${LFS_BUILD:=${PWD}/builds}"
: "${LFS_CACHE:=${PWD}/cache}"
: "${LFS_LOGS:=${PWD}/logs}"
: "${LFS_ETC:=${PWD}/etc}"
: "${LFS_MIRRORS_CONF:=/etc/lfsctl/mirrors.conf}"
: "${LFS_DOWNLOAD_RETRIES:=5}"
: "${LFS_BACKOFF_BASE:=1}"   # seconds
: "${LFS_BACKOFF_MAX:=16}"   # seconds maximum backoff
: "${LFS_ALLOW_HTTP:=0}"     # allow fallback to http if https fails
: "${LFS_ARIA2C_SPLIT:=8}"   # default split for aria2c segmented download
: "${LFS_ARIA2C_CONN_PER_SERVER:=4}"

export LFS_ROOT LFS_BUILD LFS_CACHE LFS_LOGS LFS_ETC

# mirrors array (populated by load_mirrors)
MIRRORS=()

# Lockfile dir for db operations
: "${LFS_DB_DIR:=${LFS_ROOT}/var}" ; mkdir -p "$LFS_DB_DIR" || true
: "${LFS_PKG_DB:=${LFS_DB_DIR}/packages.db}"

# --------------------------- Error handling & traps ---------------------------
_on_error() {
  local lineno=${1:-0}
  local rc=${2:-1}
  log_error "Error at line ${lineno}, exit status ${rc}."
  # attempt to print a snippet of log file if exists
  [ -n "${LOG_FILE:-}" ] && { log_error "See full log: $LOG_FILE"; tail -n 40 "$LOG_FILE" 2>/dev/null || true; }
  # propagate exit
  exit "$rc"
}
trap ' _on_error "${LINENO}" "$?" ' ERR

set_traps() {
  # call early to capture unexpected failures
  trap ' _on_error "${LINENO}" "$?" ' ERR
  trap 'log_info "Exiting (cleanup)";' EXIT
}

# --------------------------- utils_init & environment detection ---------------------------
utils_init() {
  : "${LOG_PREFIX:=utils}"
  mkdir -p "$LFS_BUILD" "$LFS_CACHE" "$LFS_LOGS" "$LFS_ETC" || true
  export LFS_BUILD LFS_CACHE LFS_LOGS LFS_ETC
  detect_cores
  detect_mem
  load_mirrors
  set_traps
  log_debug "utils_init: LFS_ROOT=$LFS_ROOT LFS_BUILD=$LFS_BUILD LFS_CACHE=$LFS_CACHE"
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log_error "Required command not found: $cmd"
    return 1
  fi
  return 0
}

# --------------------------- System detection ---------------------------
detect_cores() {
  local n=1
  if command -v nproc >/dev/null 2>&1; then
    n=$(nproc --all 2>/dev/null || echo 1)
  elif [ -r /proc/cpuinfo ]; then
    n=$(grep -c '^processor' /proc/cpuinfo || echo 1)
  fi
  NPROC=${NPROC:-$n}
  export NPROC
  log_debug "Detected CPU cores: $NPROC"
}

detect_mem() {
  local total_kb=0 available_kb=0
  if [ -r /proc/meminfo ]; then
    total_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
    available_kb=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
  fi
  MEM_TOTAL_KB=${MEM_TOTAL_KB:-$total_kb}
  MEM_AVAILABLE_KB=${MEM_AVAILABLE_KB:-$available_kb}
  export MEM_TOTAL_KB MEM_AVAILABLE_KB
  log_debug "Memory: total=${MEM_TOTAL_KB}KB available=${MEM_AVAILABLE_KB}KB"
}

check_root() {
  if [ "$(id -u)" -eq 0 ]; then
    log_warn "Running as root. Be careful with destructive operations."
  fi
}

check_sandbox() {
  # simple heuristic: check if running under bwrap/proot/systemd-nspawn
  if [ -n "${IN_SANDBOX:-}" ]; then
    log_debug "Sandbox flag detected (IN_SANDBOX=$IN_SANDBOX)"
    return 0
  fi
  # fallback: check for /proc/1/comm typical differences (not foolproof)
  if [ -r /proc/1/comm ]; then
    local p1; p1=$(cat /proc/1/comm 2>/dev/null || true)
    case "$p1" in
      systemd|init) ;;
      *) log_debug "Process 1 is $p1 (non-systemd)";;
    esac
  fi
}

# --------------------------- File and dir helpers ---------------------------
ensure_dir() {
  local d="$1"
  [ -z "$d" ] && return 0
  mkdir -p "$d" || { log_error "Failed to create dir: $d"; return 1; }
  log_debug "ensure_dir: $d"
}

realpath_safe() {
  # return absolute path or error
  local p="$1"
  if command -v realpath >/dev/null 2>&1; then
    realpath "$p"
  else
    # portable fallback
    (cd "$(dirname "$p")" 2>/dev/null && printf "%s/%s\n" "$(pwd -P)" "$(basename "$p")") || return 1
  fi
}

_safe_path_check() {
  # protect against dangerous removals
  local p="$1"
  local rp
  rp=$(realpath_safe "$p" 2>/dev/null) || { log_error "realpath failed for $p"; return 1; }
  case "$rp" in
    "/"|"/bin"|"/sbin"|"/usr"|"/usr/bin"|"/usr/sbin"|"${HOME}"|""|"/root")
      log_error "Refusing to operate on critical path: $rp"; return 2;;
    *)
      printf "%s" "$rp"; return 0;;
  esac
}

safe_rm() {
  # usage: safe_rm path...
  for p in "$@"; do
    local rp
    rp=$(_safe_path_check "$p") || { log_warn "safe_rm refused: $p"; continue; }
    if [ -e "$rp" ]; then
      log_info "Removing: $rp"
      rm -rf -- "$rp" || { log_error "Failed to remove $rp"; return 1; }
    else
      log_debug "safe_rm: does not exist $rp"
    fi
  done
  return 0
}

clean_dir() {
  local d="$1"
  [ -z "$d" ] && return 0
  if [ ! -d "$d" ]; then log_warn "clean_dir: not a directory: $d"; return 1; fi
  # remove contents but keep directory
  log_info "Cleaning directory: $d"
  find "$d" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + || true
  return 0
}

copy_safe() {
  local src="$1" dst="$2"
  [ -e "$src" ] || { log_error "copy_safe: source not found: $src"; return 1; }
  ensure_dir "$(dirname "$dst")"
  cp -a -- "$src" "$dst" || { log_error "copy_safe failed: $src -> $dst"; return 1; }
  log_debug "copy_safe: $src -> $dst"
  return 0
}

tar_create() {
  local out="$1"; shift
  local dir="$1"
  require_cmd tar || return 1
  require_cmd zstd || return 1
  ensure_dir "$(dirname "$out")"
  (cd "$dir" && tar --numeric-owner --sort=name -cf - .) | zstd -T0 -o "$out" || { log_error "tar_create failed"; return 1; }
  log_debug "tar_create: $out from $dir"
  # verify archive readability
  tar -tf "$out" >/dev/null 2>&1 || { log_error "tar_create verification failed for $out"; return 1; }
  return 0
}

tar_extract() {
  local archive="$1" target="${2:-.}"
  ensure_dir "$target"
  require_cmd tar || return 1
  case "$archive" in
    *.tar.zst|*.tzst) require_cmd zstd || return 1; zstd -d < "$archive" | tar -xf - -C "$target" || { log_error "tar_extract failed"; return 1; } ;;
    *.tar.xz) tar -xJf "$archive" -C "$target" || { log_error "tar_extract failed"; return 1; } ;;
    *.tar.gz|*.tgz) tar -xzf "$archive" -C "$target" || { log_error "tar_extract failed"; return 1; } ;;
    *.tar.bz2) tar -xjf "$archive" -C "$target" || { log_error "tar_extract failed"; return 1; } ;;
    *.zip) require_cmd unzip || return 1; unzip -q "$archive" -d "$target" || { log_error "tar_extract failed"; return 1; } ;;
    *) log_error "Unsupported archive format: $archive"; return 2 ;;
  esac
  log_debug "tar_extract: $archive -> $target"
  return 0
}

patch_apply_dir() {
  local patches_dir="$1"
  [ -d "$patches_dir" ] || { log_info "No patches dir: $patches_dir"; return 0; }
  local applied_marker="$patches_dir/.applied"
  mkdir -p "$patches_dir"
  local patchfile
  # apply in lexicographic order (use version sort if available)
  while IFS= read -r -d '' patchfile; do
    case "$patchfile" in *.patch|*.diff|*.sh) : ;; *) continue ;; esac
    local base; base=$(basename "$patchfile")
    log_info "Applying patch $base"
    if [ -x "$patchfile" ]; then
      # executable script patch
      if ! "$patchfile"; then log_error "Patch script failed: $base"; return 1; fi
    else
      if ! patch -p1 < "$patchfile"; then log_error "Patch apply failed: $base"; return 1; fi
    fi
    echo "$base" >> "$applied_marker"
  done < <(find "$patches_dir" -maxdepth 1 -type f -print0 | sort -z)
  log_debug "patch_apply_dir completed for $patches_dir"
  return 0
}

# --------------------------- Mirrors & cache helpers ---------------------------
load_mirrors() {
  MIRRORS=()
  # priority: $LFS_ROOT/etc/mirrors.conf, /etc/lfsctl/mirrors.conf, $LFS_MIRRORS_CONF env
  local paths=("$LFS_ROOT/etc/mirrors.conf" "/etc/lfsctl/mirrors.conf" "${LFS_MIRRORS_CONF-}")
  for p in "${paths[@]}"; do
    [ -f "$p" ] || continue
    while IFS= read -r line; do
      line=${line%%#*} # strip comments
      line=$(echo "$line" | awk '{$1=$1;print}') # trim
      [ -z "$line" ] && continue
      MIRRORS+=("$line")
    done < "$p"
  done
  log_debug "Loaded mirrors: ${MIRRORS[*]:-none}"
}

fetch_cache_path() {
  local url="$1"
  require_cmd sha256sum || true
  local key
  if command -v sha256sum >/dev/null 2>&1; then
    key=$(printf "%s" "$url" | sha256sum | awk '{print $1}')
  else
    key=$(printf "%s" "$url" | md5sum | awk '{print $1}')
  fi
  printf "%s/%s" "$LFS_CACHE/downloads" "$key"
}

# verify or generate checksum (sha256). If expected provided, compare.
verify_checksum() {
  local file="$1"; shift
  local expected="${1:-}"
  if [ ! -f "$file" ]; then log_error "verify_checksum: file not found: $file"; return 2; fi
  if command -v sha256sum >/dev/null 2>&1; then
    local calculated; calculated=$(sha256sum "$file" | awk '{print $1}')
  else
    log_warn "sha256sum not available; skipping checksum verification for $file"
    return 0
  fi
  if [ -n "$expected" ]; then
    if [ "$calculated" != "$expected" ]; then
      log_error "Checksum mismatch for $file (expected $expected, got $calculated)"
      return 1
    fi
    log_debug "Checksum OK for $file"
    return 0
  fi
  # no expected provided: write .sha256 next to file if absent
  local sha_file="${file}.sha256"
  if [ ! -f "$sha_file" ]; then
    printf "%s  %s\n" "$calculated" "$(basename "$file")" > "$sha_file"
    log_debug "Wrote checksum to $sha_file"
  fi
  return 0
}

cache_add() {
  local file="$1"; local key="${2:-}"
  [ -f "$file" ] || { log_error "cache_add: missing file: $file"; return 1; }
  ensure_dir "$LFS_CACHE/downloads"
  local dest
  if [ -n "$key" ]; then
    dest="$LFS_CACHE/downloads/$key"
  else
    dest="$LFS_CACHE/downloads/$(basename "$file")"
  fi
  if [ -f "$dest" ]; then
    log_warn "cache_add: destination already exists, will overwrite after validation: $dest"
  fi
  cp -a -- "$file" "$dest" || { log_error "cache_add: copy failed"; return 1; }
  verify_checksum "$dest" || { rm -f "$dest"; return 1; }
  log_info "Cached file as: $dest"
  return 0
}

cache_get() {
  local key="$1" dest="$2"
  local path="$LFS_CACHE/downloads/$key"
  if [ -f "$path" ]; then
    verify_checksum "$path" || { log_error "cache_get: checksum invalid, removing $path"; rm -f "$path"; return 2; }
    ensure_dir "$(dirname "$dest")"
    cp -a -- "$path" "$dest" || { log_error "cache_get: copy failed"; return 1; }
    log_info "Restored from cache: $path -> $dest"
    return 0
  fi
  log_debug "cache_get: not found: $path"
  return 2
}

resolve_mirror() {
  # Replace the origin base with a mirror that responds. Returns URL or empty on failure.
  local url="$1"
  local scheme host path base
  scheme=$(printf "%s" "$url" | awk -F: '{print $1}')
  host=$(printf "%s" "$url" | awk -F/ '{print $3}')
  path=$(printf "%s" "$url" | cut -d/ -f4-)
  for m in "${MIRRORS[@]}"; do
    # skip if mirror scheme mismatch for https requirement? we'll try https mirrors first
    local candidate="${m%/}/$path"
    log_debug "resolve_mirror: testing $candidate"
    if command -v curl >/dev/null 2>&1; then
      if curl -s --head --fail --connect-timeout 5 "$candidate" >/dev/null 2>&1; then
        printf "%s" "$candidate"; return 0
      fi
    elif command -v wget >/dev/null 2>&1; then
      if wget --spider --timeout=5 --tries=1 "$candidate" >/dev/null 2>&1; then
        printf "%s" "$candidate"; return 0
      fi
    fi
  done
  # no mirror found
  return 1
}

# --------------------------- Downloading (with retries, backoff, segmented) ---------------------------
_http_download_with_curl() {
  local url="$1" dest="$2" retries="$3"
  local attempt=0 backoff
  while : ; do
    attempt=$((attempt+1))
    log_info "curl: downloading (attempt $attempt/$retries): $url -> $dest"
    if curl --fail --location --retry 0 --connect-timeout 15 --max-time 600 -o "$dest" "$url"; then
      return 0
    fi
    if [ "$attempt" -ge "$retries" ]; then break; fi
    backoff=$((LFS_BACKOFF_BASE << (attempt-1)))
    [ "$backoff" -gt "$LFS_BACKOFF_MAX" ] && backoff=$LFS_BACKOFF_MAX
    log_warn "curl download failed, retrying in ${backoff}s..."
    sleep "$backoff"
  done
  return 1
}

_http_download_with_wget() {
  local url="$1" dest="$2" retries="$3"
  local attempt=0 backoff
  while : ; do
    attempt=$((attempt+1))
    log_info "wget: downloading (attempt $attempt/$retries): $url -> $dest"
    if wget -O "$dest" --timeout=30 --tries=1 --connect-timeout=15 "$url"; then
      return 0
    fi
    if [ "$attempt" -ge "$retries" ]; then break; fi
    backoff=$((LFS_BACKOFF_BASE << (attempt-1)))
    [ "$backoff" -gt "$LFS_BACKOFF_MAX" ] && backoff=$LFS_BACKOFF_MAX
    log_warn "wget download failed, retrying in ${backoff}s..."
    sleep "$backoff"
  done
  return 1
}

_aria2c_download() {
  local url="$1" dest="$2" retries="$3" split="$4" conn="$5"
  local attempt=0 backoff
  while : ; do
    attempt=$((attempt+1))
    log_info "aria2c: downloading (attempt $attempt/$retries): $url -> $dest (split=$split)"
    if aria2c --file-allocation=none --dir="$(dirname "$dest")" --out="$(basename "$dest")" --max-connection-per-server="$conn" --split="$split" --continue=true --timeout=60 --retry-wait=5 --min-tls-version=TLSv1.2 -q "$url"; then
      return 0
    fi
    if [ "$attempt" -ge "$retries" ]; then break; fi
    backoff=$((LFS_BACKOFF_BASE << (attempt-1)))
    [ "$backoff" -gt "$LFS_BACKOFF_MAX" ] && backoff=$LFS_BACKOFF_MAX
    log_warn "aria2c download failed, retrying in ${backoff}s..."
    sleep "$backoff"
  done
  return 1
}

download_file() {
  # download_file <url> <dest> [expected_sha256]
  local url="$1" dest="$2" expected="${3:-}"
  ensure_dir "$(dirname "$dest")"
  local tmp="${dest}.part.$$"
  local retries="${LFS_DOWNLOAD_RETRIES:-5}" split="${LFS_ARIA2C_SPLIT}" conn="${LFS_ARIA2C_CONN_PER_SERVER}" res=1

  # If cache contains equivalent, try cache_get first (by URL-derived key)
  local cache_key; cache_key=$(fetch_cache_path "$url" | xargs -n1 basename)
  if cache_get "$cache_key" "$dest" >/dev/null 2>&1; then
    log_info "Using cached file for URL: $url"
    verify_checksum "$dest" "$expected" || { log_warn "Cached checksum mismatch; will re-download"; rm -f "$dest"; }
    [ -f "$dest" ] && return 0
  fi

  # Try mirrors first (resolve_mirror). Build list: mirror candidates then original
  local candidates=()
  if resolve_mirror "$url" >/dev/null 2>&1; then
    local m; m=$(resolve_mirror "$url") || true
    [ -n "$m" ] && candidates+=("$m")
  fi
  candidates+=("$url")

  for candidate in "${candidates[@]}"; do
    log_info "Attempting download candidate: $candidate"
    # choose downloader
    if command -v aria2c >/dev/null 2>&1; then
      if _aria2c_download "$candidate" "$tmp" "$retries" "$split" "$conn"; then res=0; fi
    fi
    if [ $res -ne 0 ] && command -v curl >/dev/null 2>&1; then
      if _http_download_with_curl "$candidate" "$tmp" "$retries"; then res=0; fi
    fi
    if [ $res -ne 0 ] && command -v wget >/dev/null 2>&1; then
      if _http_download_with_wget "$candidate" "$tmp" "$retries"; then res=0; fi
    fi
    if [ $res -eq 0 ]; then
      mv -f "$tmp" "$dest" || { log_error "Failed to move temp to dest"; rm -f "$tmp"; continue; }
      log_info "Downloaded: $candidate -> $dest"
      # verify checksum if provided or create .sha256
      if ! verify_checksum "$dest" "$expected"; then
        log_warn "Downloaded file failed checksum for $candidate"
        rm -f "$dest"
        res=1
        continue
      fi
      # add to cache by key
      cache_add "$dest" "$cache_key" || log_warn "cache_add failed (continuing)"
      return 0
    else
      log_warn "Candidate failed: $candidate"
      # if candidate was a mirror and allowed, continue to next mirror
    fi
  done

  # final fallback: if https failed and HTTP allowed, try replacing scheme
  if [ "$LFS_ALLOW_HTTP" -eq 1 ]; then
    local http_url; http_url="${url/https:\/\//http://}"
    if [ "$http_url" != "$url" ]; then
      log_warn "Trying HTTP fallback: $http_url"
      if command -v curl >/dev/null 2>&1 && _http_download_with_curl "$http_url" "$tmp" "$retries"; then
        mv -f "$tmp" "$dest" || true
        verify_checksum "$dest" "$expected" || { log_warn "HTTP fallback checksum failed"; rm -f "$dest"; return 1; }
        cache_add "$dest" "$cache_key" || true
        return 0
      fi
    fi
  fi

  log_error "All download attempts failed for $url"
  return 1
}

download_parallel() {
  # download_parallel <file_with_urls> OR list of urls
  local args=("$@")
  local urls_file="/tmp/aria2c_urls.$$"
  if [ "${#args[@]}" -eq 1 ] && [ -f "${args[0]}" ]; then
    cp -a -- "${args[0]}" "$urls_file"
  else
    printf "%s\n" "${args[@]}" > "$urls_file"
  fi
  if command -v aria2c >/dev/null 2>&1; then
    aria2c --file-allocation=none --split="$LFS_ARIA2C_SPLIT" --max-connection-per-server="$LFS_ARIA2C_CONN_PER_SERVER" --continue=true -i "$urls_file" -d "$LFS_CACHE/downloads" || { log_error "aria2c parallel download failed"; rm -f "$urls_file"; return 1; }
    rm -f "$urls_file"
    log_info "Parallel downloads started/completed via aria2c"
    return 0
  fi
  log_warn "aria2c not available; falling back to sequential download"
  while IFS= read -r u; do
    local dest="$LFS_CACHE/downloads/$(basename "$u")"
    download_file "$u" "$dest" || log_warn "download_parallel: failed for $u"
  done < "$urls_file"
  rm -f "$urls_file"
  return 0
}

# --------------------------- Sandbox & execution wrappers ---------------------------
sandbox_exec() {
  # sandbox_exec <command...>
  # Detect and use bwrap/proot/chroot/systemd-nspawn if available. Fallback to direct exec.
  local cmd=("$@")
  if command -v bwrap >/dev/null 2>&1; then
    log_debug "sandbox_exec: using bwrap"
    # minimal bwrap sandbox: isolate /tmp and a bind of LFS_ROOT
    bwrap --unshare-all --die-with-parent --proc /proc --dev /dev --bind "$LFS_ROOT" "$LFS_ROOT" --tmpfs /tmp --ro-bind /usr /usr --ro-bind /bin /bin --ro-bind /lib /lib --ro-bind /lib64 /lib64 --chdir "$LFS_ROOT" -- "${cmd[@]}"
    return $?
  elif command -v proot >/dev/null 2>&1; then
    log_debug "sandbox_exec: using proot"
    proot -R "$LFS_ROOT" "${cmd[@]}"
    return $?
  elif [ "$(id -u)" -ne 0 ] && command -v fakeroot >/dev/null 2>&1; then
    log_debug "sandbox_exec: using fakeroot fallback"
    fakeroot -- "${cmd[@]}"
    return $?
  elif [ "$(id -u)" -eq 0 ]; then
    log_debug "sandbox_exec: running in chroot as root"
    chroot "$LFS_ROOT" "${cmd[@]}"
    return $?
  else
    log_warn "No sandbox available; running command directly (not isolated)"
    "${cmd[@]}"
    return $?
  fi
}

run_with_fakeroot() {
  # run_with_fakeroot <command...>
  if command -v fakeroot >/dev/null 2>&1; then
    fakeroot -- "$@"
    return $?
  fi
  log_warn "fakeroot not available; running without fakeroot"
  "$@"
  return $?
}

run_stage() {
  # run_stage "<Stage Name>" command... ; wrapper to log and capture stats
  local stage="$1"; shift
  log_section "$stage"
  log_info "Starting stage: $stage"
  log_system_stats || true
  # capture start time
  local start ts rc
  start=$(date +%s)
  if ! "$@"; then
    rc=$?
    log_error "Stage failed: $stage (rc=$rc)"
    return $rc
  fi
  ts=$(date +%s); log_info "Stage completed: $stage (duration=$((ts-start))s)"
  log_system_stats || true
  return 0
}

try_run() {
  # try_run command... : run but do not exit on error (useful for cleanup)
  if "$@"; then return 0; else
    local rc=$?; log_warn "try_run: command failed (rc=$rc): $*"; return $rc
  fi
}

# --------------------------- Package DB helpers (simple text DB) ---------------------------
_pkg_db_lock() {
  # simple flock via directory creation
  local lockdir="${LFS_PKG_DB}.lock"
  local i=0
  while ! mkdir "$lockdir" 2>/dev/null; do
    i=$((i+1))
    sleep 0.1
    [ $i -gt 100 ] && { log_error "Failed to acquire db lock"; return 1; }
  done
  printf "%s" "$lockdir"
}

_pkg_db_unlock() {
  local lockdir="$1"; rm -rf "$lockdir" || true
}

pkg_record_install() {
  local pkg="$1" manifest="$2"
  ensure_dir "$(dirname "$LFS_PKG_DB")"
  local lock; lock=$(_pkg_db_lock) || return 1
  printf "%s\t%s\t%s\n" "$pkg" "$(date -u +%Y%m%dT%H%M%SZ)" "$manifest" >> "$LFS_PKG_DB" || { _pkg_db_unlock "$lock"; return 1; }
  _pkg_db_unlock "$lock"
  log_info "Recorded package: $pkg"
  return 0
}

pkg_remove_record() {
  local pkg="$1"
  local lock; lock=$(_pkg_db_lock) || return 1
  if [ -f "$LFS_PKG_DB" ]; then
    grep -v "^$pkg	" "$LFS_PKG_DB" > "${LFS_PKG_DB}.tmp" || true
    mv -f "${LFS_PKG_DB}.tmp" "$LFS_PKG_DB"
  fi
  _pkg_db_unlock "$lock"
  log_info "Removed package record: $pkg"
  return 0
}

pkg_installed() {
  local pkg="$1"
  if [ -f "$LFS_PKG_DB" ] && grep -q "^$pkg	" "$LFS_PKG_DB"; then
    return 0
  fi
  return 1
}

pkg_list_deps() {
  # simple: look for pkgs/<pkg>/metadata file containing DEPENDENCIES variable (bash-like)
  local pkg="$1" meta="pkgs/$pkg/metadata"
  if [ -f "$meta" ]; then
    # shellcheck disable=SC1090,SC1091
    . "$meta"
    # if DEPENDENCIES declared as array-like (bash), try to echo them
    if [ -n "${DEPENDENCIES:-}" ]; then
      printf "%s\n" "${DEPENDENCIES[@]-}" 2>/dev/null || printf "%s\n" "$DEPENDENCIES"
      return 0
    fi
  fi
  return 1
}

# --------------------------- Cleanup helpers ---------------------------
clean_logs() {
  local keep="${1:-5}"
  ensure_dir "$LFS_LOGS"
  local files; files=($(ls -1t "$LFS_LOGS" 2>/dev/null || true))
  local i=0
  for f in "${files[@]}"; do
    i=$((i+1))
    if [ "$i" -gt "$keep" ]; then rm -f "$LFS_LOGS/$f" || true; fi
  done
  log_info "clean_logs: kept $keep logs"
}

clean_cache() {
  local days="${1:-30}"
  find "$LFS_CACHE" -type f -mtime +"$days" -print0 | xargs -0r rm -f -- || true
  log_info "clean_cache: removed files older than $days days"
}

clean_all() {
  log_info "Performing full clean (builds, cache, logs)"
  safe_rm "$LFS_BUILD" "$LFS_CACHE"
  ensure_dir "$LFS_BUILD" "$LFS_CACHE"
  clean_logs 5
  return 0
}

recover_session() {
  # look for last incomplete build markers in $LFS_BUILD
  local markers; markers=($(find "$LFS_BUILD" -maxdepth 2 -name '.incomplete' -print 2>/dev/null || true))
  if [ "${#markers[@]}" -eq 0 ]; then
    log_info "No incomplete sessions found"
    return 0
  fi
  log_warn "Found incomplete sessions:"
  printf "%s\n" "${markers[@]}"
  # decision left to caller (interactive / CI)
}

# --------------------------- System stats (calls log_system_stats from log.sh) ---------------------------
log_system_stats() {
  # try to call log_system_stats if provided; otherwise print compact summary
  if type log_system_stats >/dev/null 2>&1; then
    log_system_stats
    return 0
  fi
  # compact fallback
  detect_cores
  detect_mem
  printf "[sys] cores=%s mem_available_kb=%s\n" "${NPROC:-?}" "${MEM_AVAILABLE_KB:-?}"
  return 0
}

# --------------------------- End of lib/utils.sh ---------------------------
