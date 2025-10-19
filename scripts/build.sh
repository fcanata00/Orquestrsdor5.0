#!/usr/bin/env bash
# build.sh - robust build orchestrator for lfsctl
# - compiles a package inside a sandbox
# - installs into DESTDIR with fakeroot
# - creates tar.zst packages, strips binaries, records metadata
# - extensive error handling, traps, logging, resource checks, rollback
#
# Usage: build.sh <pkg> [--version <ver>] [--destdir <path>] [--jobs N] [--dry-run] [--keep-build] [--verbose]
set -Eeuo pipefail
IFS=$'\n\t'

# ---- helper to source libs ----
_find_and_source() {
  local name="$1" candidate
  : "${LFS_ROOT:=${PWD}}"
  local tries=(
    "$LFS_ROOT/lib/$name"
    "$LFS_ROOT/lib/$name.sh"
    "$(dirname "$0")/../lib/$name"
    "$(dirname "$0")/../lib/$name.sh"
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

# source log and utils (exit if utils missing)
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
  echo "ERROR: lib/utils.sh not found. Install it before running build.sh" >&2
  exit 1
fi

# ---- defaults and globals ----
: "${LFS_BUILD:=./builds}"
: "${LFS_ROOT:=${PWD}}"
: "${LFS_LOGS:=${PWD}/logs}"
: "${LFS_CACHE:=${PWD}/cache}"
: "${SANDBOX:=bwrap}"
: "${JOBS:=0}"
: "${DRY_RUN:=0}"
: "${KEEP_BUILD:=0}"
: "${PKG:=""}"
: "${PKG_VERSION:=""}"
: "${DESTDIR:=""}"
: "${STRIP:=1}"
: "${PACKAGE_OUTDIR:=${LFS_CACHE}/packages}"

export LFS_BUILD LFS_ROOT LFS_LOGS LFS_CACHE SANDBOX

# internal
BUILD_ID=""
BUILD_DIR=""
BUILD_LOG=""
PACKAGE_FILE=""
LOCK_DIR=""

usage() {
  cat <<EOF
Usage: $(basename "$0") <pkg> [options]
Options:
  --version <ver>    : specify package version (optional)
  --destdir <path>   : final installation root (for bootstrap); default uses DESTDIR temp
  --jobs N           : parallel build jobs (default: autodetect)
  --dry-run          : simulate actions
  --keep-build       : do not delete build dir after success
  --no-strip         : do not strip binaries
  -v|--verbose       : verbose logging
  -h|--help          : show this help
EOF
  exit "${1:-0}"
}

# ---- error handler & traps ----
error_handler() {
  local lineno=${1:-0} rc=${2:-1}
  log_error "build.sh: error at line ${lineno} (rc=${rc})"
  [ -n "${PKG:-}" ] && log_error "Package: $PKG"
  [ -n "${BUILD_LOG:-}" ] && log_error "See full log: ${BUILD_LOG}"
  cleanup_on_error || true
  exit "$rc"
}
trap 'error_handler ${LINENO} $?' ERR

cleanup_on_error() {
  log_warn "Running cleanup due to error..."
  if [ -n "$BUILD_DIR" ] && [ -d "$BUILD_DIR" ]; then
    log_info "Preserving build dir for inspection: $BUILD_DIR"
  fi
  if [ -n "$LOCK_DIR" ]; then
    _pkg_lock_release "$LOCK_DIR" || true
  fi
}

# ---- parse args ----
_parse_args() {
  if [ $# -lt 1 ]; then usage 1; fi
  while [ $# -gt 0 ]; do
    case "$1" in
      --version) PKG_VERSION="$2"; shift 2 ;;
      --destdir) DESTDIR="$2"; shift 2 ;;
      --jobs|-j) JOBS="$2"; shift 2 ;;
      --dry-run) DRY_RUN=1; shift ;;
      --keep-build) KEEP_BUILD=1; shift ;;
      --no-strip) STRIP=0; shift ;;
      -v|--verbose) log_set_level debug; shift ;;
      -h|--help) usage 0 ;;
      --) shift; break ;;
      -*) log_error "Unknown option $1"; usage 1 ;;
      *) if [ -z "$PKG" ]; then PKG="$1"; shift; else log_warn "Ignoring extra arg $1"; shift; fi ;;
    esac
  done
  if [ -z "$PKG" ]; then log_error "No package specified"; usage 1; fi
}

# ---- build init ----
build_init() {
  log_section "build_init"
  utils_init || { log_error "utils_init failed"; return 1; }
  detect_cores || true
  detect_mem || true

  if [ "$JOBS" -eq 0 ]; then
    JOBS=${NPROC:-1}
  fi
  export JOBS

  # ensure required commands exist
  for cmd in tar zstd strip fakeroot; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      log_warn "Required command missing: $cmd"
    fi
  done

  # don't run as real root (unless explicit and careful)
  if [ "$(id -u)" -eq 0 ]; then
    log_warn "Running as root. It's safer to run as non-root with fakeroot for packaging."
  fi

  # prepare IDs and dirs
  BUILD_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  BUILD_DIR="${LFS_BUILD}/${PKG}-${PKG_VERSION:-unknown}-${BUILD_ID}"
  BUILD_LOG="${LFS_LOGS}/${PKG}-${BUILD_ID}.log"
  PACKAGE_OUTDIR="${PACKAGE_OUTDIR%/}"
  ensure_dir "$(dirname "$BUILD_LOG")"
  ensure_dir "$BUILD_DIR"
  ensure_dir "$PACKAGE_OUTDIR"

  # per-package lock
  LOCK_DIR="$(_pkg_lock_acquire "$PKG")" || { log_error "Failed to acquire pkg lock"; return 1; }

  log_info "Build init: PKG=$PKG VERSION=${PKG_VERSION:-unknown} JOBS=$JOBS BUILD_DIR=$BUILD_DIR"
  # open a dedicated log FD (7) for verbose logging
  exec 7>>"$BUILD_LOG" || { log_error "Failed to open build log $BUILD_LOG"; _pkg_lock_release "$LOCK_DIR"; return 1; }
  export LOG_FILE="$BUILD_LOG"
  log_info "Detailed logs: $BUILD_LOG"
  return 0
}

# ---- prepare source (expects fetch prepared build dir) ----
prepare_source() {
  log_section "prepare_source"
  # fetch.sh should have prepared LFS_BUILD/<pkg>-<version> (we may accept existing build dir)
  local prepared_dir="${LFS_BUILD}/${PKG}-${PKG_VERSION:-unknown}"
  if [ -d "$prepared_dir" ] && [ "$(ls -A "$prepared_dir" 2>/dev/null || true)" ]; then
    log_info "Using prepared source at $prepared_dir"
    # copy into isolated BUILD_DIR (to avoid altering cached source)
    if [ "$DRY_RUN" -eq 1 ]; then
      log_info "(DRY-RUN) would copy $prepared_dir -> $BUILD_DIR/src"
    else
      mkdir -p "$BUILD_DIR/src"
      cp -a -- "$prepared_dir/." "$BUILD_DIR/src/" || { log_error "Failed to copy source to build dir"; return 1; }
    fi
  else
    log_error "Prepared source not found: $prepared_dir (run fetch.sh first)"
    return 2
  fi

  # run pre-build hooks
  fetch_run_hooks pre-build "$PKG" || { log_error "pre-build hooks failed"; return 3; }

  # detect build system
  local src="$BUILD_DIR/src"
  if [ -f "$src/configure" ]; then
    BUILD_SYSTEM="autotools"
  elif [ -f "$src/CMakeLists.txt" ]; then
    BUILD_SYSTEM="cmake"
  elif [ -d "$src/meson.build" ]; then
    BUILD_SYSTEM="meson"
  else
    BUILD_SYSTEM="unknown"
  fi
  log_info "Detected build system: $BUILD_SYSTEM"
  return 0
}

# ---- compile (inside sandbox) ----
build_package() {
  log_section "build_package"
  local src="$BUILD_DIR/src"
  local buildsub="$BUILD_DIR/build"
  ensure_dir "$buildsub"

  case "$BUILD_SYSTEM" in
    autotools)
      log_info "Running autotools sequence"
      if [ "$DRY_RUN" -eq 1 ]; then
        log_info "(DRY-RUN) would run configure && make -j$JOBS"
      else
        sandbox_exec bash -lc "cd '$src' && ./configure --prefix=/usr" || { log_error "configure failed"; return 1; }
        sandbox_exec bash -lc "cd '$src' && make -j$JOBS" || { log_error "make failed"; return 1; }
      fi
      ;;
    cmake)
      if [ "$DRY_RUN" -eq 1 ]; then
        log_info "(DRY-RUN) would run cmake && make -j$JOBS"
      else
        sandbox_exec bash -lc "mkdir -p '$buildsub' && cd '$buildsub' && cmake '$src' -DCMAKE_INSTALL_PREFIX=/usr" || { log_error "cmake configure failed"; return 1; }
        sandbox_exec bash -lc "cd '$buildsub' && make -j$JOBS" || { log_error "cmake make failed"; return 1; }
      fi
      ;;
    meson)
      if [ "$DRY_RUN" -eq 1 ]; then
        log_info "(DRY-RUN) would run meson && ninja -j$JOBS"
      else
        sandbox_exec bash -lc "mkdir -p '$buildsub' && cd '$buildsub' && meson setup .. --prefix=/usr" || { log_error "meson setup failed"; return 1; }
        sandbox_exec bash -lc "cd '$buildsub' && ninja -j$JOBS" || { log_error "meson build failed"; return 1; }
      fi
      ;;
    *)
      log_warn "Unknown build system; attempting generic 'make -j$JOBS' in source dir"
      if [ "$DRY_RUN" -eq 1 ]; then
        log_info "(DRY-RUN) would run make -j$JOBS"
      else
        sandbox_exec bash -lc "cd '$src' && make -j$JOBS" || { log_error "make failed"; return 1; }
      fi
      ;;
  esac

  log_ok "Build completed for $PKG"
  return 0
}

# ---- install into DESTDIR via fakeroot and package ----
install_and_package() {
  log_section "install_and_package"
  local dest="${DESTDIR:-${BUILD_DIR}/destdir}"
  ensure_dir "$dest"
  if [ "$DRY_RUN" -eq 1 ]; then
    log_info "(DRY-RUN) would run installation into $dest"
  else
    # perform install using package-specific install command if present in metadata
    # try common install patterns
    local src="$BUILD_DIR/src" buildsub="$BUILD_DIR/build"
    # prefer running 'make install DESTDIR=...'
    if [ -f "$buildsub/Makefile" ] || [ -f "$src/Makefile" ]; then
      sandbox_exec bash -lc "cd '${buildsub:-$src}' && ${MAKE_CMD:-make} install DESTDIR='$dest'" || { log_error "make install failed"; return 1; }
    else
      # fallback: try 'ninja install' or copy from staged layout
      sandbox_exec bash -lc "cd '$src' && ${MAKE_CMD:-make} install DESTDIR='$dest'" || { log_error "installation fallback failed"; return 1; }
    fi
  fi

  # strip binaries if requested
  if [ "$STRIP" -eq 1 ] && [ "$DRY_RUN" -eq 0 ]; then
    log_info "Stripping binaries under $dest"
    # find ELF files and strip --strip-unneeded
    find "$dest" -type f -print0 2>/dev/null | while IFS= read -r -d '' f; do
      if file -b --mime-type "$f" 2>/dev/null | grep -qiE 'application/x-executable|application/x-sharedlib|application/x-elf'; then
        if command -v strip >/dev/null 2>&1; then
          strip --strip-unneeded "$f" >/dev/null 2>&1 || true
        fi
      fi
    done
  fi

  # package into tar.zst
  local pkgname="${PKG}-${PKG_VERSION:-unknown}.tar.zst"
  PACKAGE_FILE="${PACKAGE_OUTDIR}/${pkgname}"
  ensure_dir "$(dirname "$PACKAGE_FILE")"
  if [ "$DRY_RUN" -eq 1 ]; then
    log_info "(DRY-RUN) would create package $PACKAGE_FILE from $dest"
  else
    (cd "$dest" && tar --numeric-owner --sort=name -cf - .) | zstd -T0 -o "$PACKAGE_FILE" || { log_error "Packaging failed"; return 1; }
    log_info "Created package: $PACKAGE_FILE"
    # verify package can be listed
    if ! tar -tf "$PACKAGE_FILE" >/dev/null 2>&1; then
      log_error "Package verification failed (tar -tf) for $PACKAGE_FILE"
      rm -f "$PACKAGE_FILE" || true
      return 1
    fi
    # write metadata file alongside package
    local meta="${PACKAGE_FILE}.PKGINFO"
    {
      echo "NAME=${PKG}"
      echo "VERSION=${PKG_VERSION:-unknown}"
      echo "TIME=$(date -u +%Y%m%dT%H%M%SZ)"
      echo "BUILDDIR=${BUILD_DIR}"
    } > "$meta"
    sha256sum "$PACKAGE_FILE" | awk '{print $1}' > "${PACKAGE_FILE}.sha256"
    log_info "Package metadata written: $meta and sha256"
  fi

  # record package to db
  if [ "$DRY_RUN" -eq 0 ]; then
    pkg_record_install "${PKG}-${PKG_VERSION:-unknown}" "${PACKAGE_FILE}" || log_warn "pkg_record_install failed"
  fi

  return 0
}

# ---- final cleanup ----
cleanup() {
  log_section "cleanup"
  # close per-build log fd 7
  if [ -e /proc/$$/fd/7 ]; then
    exec 7>&-
  fi
  # release lock
  if [ -n "$LOCK_DIR" ]; then
    _pkg_lock_release "$LOCK_DIR" || true
  fi
  # compress big logs
  if [ -f "$BUILD_LOG" ]; then
    local sz; sz=$(stat -c%s "$BUILD_LOG" 2>/dev/null || echo 0)
    if [ "$sz" -gt $((10*1024*1024)) ]; then
      log_info "Compressing large log: $BUILD_LOG"
      zstd -q -19 "$BUILD_LOG" || true
    fi
  fi
  # remove build dir unless user asked to keep
  if [ "$KEEP_BUILD" -eq 0 ] && [ -d "$BUILD_DIR" ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
      log_info "(DRY-RUN) would remove build dir $BUILD_DIR"
    else
      rm -rf "$BUILD_DIR" || log_warn "Failed to remove build dir $BUILD_DIR"
    fi
  else
    log_info "Keeping build dir: $BUILD_DIR"
  fi
  return 0
}
trap 'cleanup' EXIT

# ---- main flow orchestrator ----
main() {
  _parse_args "$@"
  build_init || exit 1
  prepare_source || exit 1
  build_package || exit 1
  install_and_package || exit 1
  log_ok "Build workflow completed successfully for $PKG"
}

main "$@"
