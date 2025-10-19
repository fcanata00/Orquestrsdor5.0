#!/usr/bin/env bash
# uninstall.sh - safe, transactional uninstaller for lfsctl-managed packages
# Features:
#  - dry-run, force, clean-orphans, rollback
#  - per-package locking and global transaction support
#  - pre/post hooks executed in sandbox with timeout
#  - backup (rsync/cp) before removals and rollback capability
#  - JSON and text logs, compressed on completion
#  - robust error handling, traps, and non-silent failures
#
# Assumptions:
#  - lib/log.sh and lib/utils.sh exist and provide functions used here
#  - installed file lists are stored in $LFS_DB/installed/<pkg>.manifest (one absolute path per line)
#
set -Eeuo pipefail
IFS=$'\n\t'

_find_and_source() {
  local name="$1" candidate
  : "${LFS_ROOT:=${PWD}}"
  local tries=( "$LFS_ROOT/lib/$name" "$LFS_ROOT/lib/$name.sh" "$(dirname "$0")/../lib/$name" "$(dirname "$0")/../lib/$name.sh" "/usr/local/lib/lfsctl/$name" "/usr/local/lib/lfsctl/$name.sh" )
  for candidate in "${tries[@]}"; do
    [ -f "$candidate" ] || continue
    # shellcheck disable=SC1090
    source "$candidate"
    return 0
  done
  return 1
}

# minimal logging fallback
if ! _find_and_source "log"; then
  echo "WARNING: lib/log.sh not found; minimal logger active" >&2
  log_info(){ printf "[INFO] %s\n" "$*"; }
  log_warn(){ printf "[WARN] %s\n" "$*"; }
  log_error(){ printf "[ERROR] %s\n" "$*" >&2; }
  log_debug(){ [ "${LOG_LEVEL:-0}" -ge 3 ] && printf "[DEBUG] %s\n" "$*"; }
  log_ok(){ printf "[OK] %s\n" "$*"; }
  log_section(){ printf "==> %s\n" "$*"; }
fi

# require utils
if ! _find_and_source "utils"; then
  log_error "lib/utils.sh not found. Aborting."
  exit 1
fi

# defaults
: "${LFS_DB:=${LFS_ROOT:-.}/var/lib/lfsctl}"
: "${LFS_LOGS:=${LFS_ROOT:-.}/var/log/lfsctl}"
: "${BACKUP_ROOT:=${LFS_ROOT:-.}/var/backups/uninstall}"
: "${TMPDIR:=/tmp}"
: "${JSON_LOG:=0}"
: "${DRY_RUN:=0}"
: "${FORCE:=0}"
: "${CLEAN_ORPHANS:=0}"
: "${KEEP_LOGS:=0}"
: "${CONFIRM_EACH:=0}"
: "${VERBOSE:=0}"

export LFS_DB LFS_LOGS BACKUP_ROOT

INSTALLED_MANIFEST_DIR="${LFS_DB}/installed"
PACKAGES_DB="${LFS_DB}/packages.db"
DEPENDS_DB="${LFS_DB}/depends.db"
LOCKS_DIR="${LFS_DB}/locks"

ensure_dir "$INSTALLED_MANIFEST_DIR"
ensure_dir "$LFS_LOGS"
ensure_dir "$BACKUP_ROOT"
ensure_dir "$LOCKS_DIR"

PKG=""
LOGFILE=""
JSONFILE=""
LOCK_PATH=""
BACKUP_DIR=""
BACKUP_META=""
OP_START=""
ROLLBACK=0

_json_out() {
  [ "${JSON_LOG:-0}" -ne 1 ] && return 0
  local key="$1"; shift
  local val="$*"
  printf '{"time":"%s","pkg":"%s","key":"%s","value":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${PKG:-}" "$key" "$(echo "$val" | sed 's/"/\\"/g')" >> "$JSONFILE"
}

usage() {
  cat <<EOF
Usage: $(basename "$0") <pkg> [options]
Options:
  --dry-run          simulate actions
  --force            ignore dependency checks
  --clean-orphans    detect and remove orphaned packages
  --keep-logs        keep logs/backups after success
  --rollback         attempt rollback for last uninstall
  --confirm-each     prompt for each file deletion
  --json-log         write JSON events
  -v, --verbose      verbose
  -h, --help         help
EOF
  exit 1
}

_parse_args() {
  if [ $# -lt 1 ]; then usage; fi
  PKG="$1"; shift
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run) DRY_RUN=1; shift;;
      --force) FORCE=1; shift;;
      --clean-orphans) CLEAN_ORPHANS=1; shift;;
      --keep-logs) KEEP_LOGS=1; shift;;
      --rollback) ROLLBACK=1; shift;;
      --confirm-each) CONFIRM_EACH=1; shift;;
      --json-log) JSON_LOG=1; shift;;
      -v|--verbose) VERBOSE=1; log_set_level debug; shift;;
      -h|--help) usage;;
      --) shift; break;;
      *) log_warn "Unknown arg: $1"; shift;;
    esac
  done
}

_on_error() {
  local lineno=${1:-0}; local rc=${2:-1}
  log_error "Error at line ${lineno}, rc=${rc}"
  _json_out "error" "line:${lineno} rc:${rc}"
  # attempt rollback if backup exists
  if [ -n "${BACKUP_DIR:-}" ] && [ -d "${BACKUP_DIR}/files" ]; then
    log_warn "Attempting rollback from backup"
    _rollback_from_backup || log_error "Rollback failed; manual recovery required"
  fi
  _release_lock || true
  exit "$rc"
}
trap ' _on_error ${LINENO} $?' ERR
trap ' _on_signal ' INT TERM

_on_signal() {
  log_warn "Signal received; aborting and attempting rollback"
  _on_error "${LINENO}" 130
}

_acquire_lock() {
  ensure_dir "$LOCKS_DIR"
  if type _pkg_lock_acquire >/dev/null 2>&1; then
    LOCK_PATH="$(_pkg_lock_acquire "$PKG")" || return 1
    return 0
  fi
  local lock="${LOCKS_DIR}/${PKG}.lock"
  local i=0
  while ! mkdir "$lock" 2>/dev/null; do
    i=$((i+1)); sleep 0.1
    [ $i -gt 200 ] && { log_error "Timeout acquiring lock"; return 1; }
  done
  LOCK_PATH="$lock"
  return 0
}

_release_lock() {
  if [ -z "${LOCK_PATH:-}" ]; then return 0; fi
  if type _pkg_lock_release >/dev/null 2>&1; then
    _pkg_lock_release "$LOCK_PATH" || true
  else
    rm -rf "$LOCK_PATH" || true
  fi
  LOCK_PATH=""
  return 0
}

_init() {
  OP_START=$(date -u +%Y%m%dT%H%M%SZ)
  LOGFILE="${LFS_LOGS}/uninstall-${PKG}-${OP_START}.log"
  JSONFILE="${LOGFILE}.json"
  BACKUP_DIR="${BACKUP_ROOT}/${PKG}-${OP_START}"
  BACKUP_META="${BACKUP_DIR}/backup.meta"
  ensure_dir "$(dirname "$LOGFILE")"
  ensure_dir "$BACKUP_DIR"
  exec 7>>"$LOGFILE" || { echo "Cannot open log $LOGFILE" >&2; exit 1; }
  export LOG_FILE="$LOGFILE"
  log_info "Starting uninstall: $PKG at $OP_START"
  _json_out "start" "$OP_START"
}

_find_manifest() {
  local m="${INSTALLED_MANIFEST_DIR}/${PKG}.manifest"
  if [ -f "$m" ]; then printf "%s" "$m"; return 0; fi
  if [ -f "$PACKAGES_DB" ]; then
    local line; line=$(grep -E "^${PKG}\t" "$PACKAGES_DB" || true)
    if [ -n "$line" ]; then
      local mp; mp=$(printf "%s" "$line" | awk -F'\t' '{print $3}' | sed 's/^[ \t]*//;s/[ \t]*$//')
      [ -n "$mp" ] && [ -f "$mp" ] && { printf "%s" "$mp"; return 0; }
    fi
  fi
  return 1
}

_verify_pkg_installed() {
  local manifest; manifest=$(_find_manifest || true)
  if [ -z "$manifest" ]; then
    log_warn "No installed manifest for $PKG"
    _json_out "manifest" "missing"
    return 1
  fi
  log_info "Manifest: $manifest"
  _json_out "manifest" "$manifest"
  printf "%s" "$manifest"
  return 0
}

_create_backup() {
  local manifest="$1"
  log_info "Creating backup at $BACKUP_DIR"
  _json_out "backup" "$BACKUP_DIR"
  if [ ! -f "$manifest" ]; then log_warn "Manifest not found; nothing to backup"; return 0; fi
  if [ "$DRY_RUN" -eq 1 ]; then log_info "(DRY-RUN) Would create backup"; return 0; fi
  ensure_dir "$BACKUP_DIR/files"
  > "$BACKUP_META" || true
  while IFS= read -r file; do
    [ -z "$file" ] && continue
    if [ ! -e "$file" ]; then
      printf "%s\tMISSING\n" "$file" >> "$BACKUP_META"
      continue
    fi
    # copy preserving parent dirs under backup/files
    local destdir="$BACKUP_DIR/files/$(dirname "$file")"
    ensure_dir "$destdir"
    if cp -a -- "$file" "$destdir/" 2>/dev/null; then
      printf "%s\tCOPIED\n" "$file" >> "$BACKUP_META"
      if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$destdir/$(basename "$file")" > "$BACKUP_DIR/$(echo "$file" | sed 's/[\/]/_/g').sha256" || true
      fi
    else
      log_warn "cp failed for $file, trying tar fallback"
      if (cd / && tar -cf - "$file" 2>/dev/null) | (cd "$BACKUP_DIR/files" && tar -xf -) ; then
        printf "%s\tCOPIED_TAR\n" "$file" >> "$BACKUP_META"
      else
        log_error "Failed to backup $file"
        printf "%s\tBACKUP_FAILED\n" "$file" >> "$BACKUP_META"
        return 1
      fi
    fi
  done < "$manifest"
  printf "backup_time=%s\n" "$(date -u +%Y%m%dT%H%M%SZ)" >> "$BACKUP_META"
  log_info "Backup done at $BACKUP_DIR"
  _json_out "backup_done" "$BACKUP_DIR"
  return 0
}

_remove_files_from_manifest() {
  local manifest="$1"
  if [ ! -f "$manifest" ]; then log_warn "Manifest missing; nothing to remove"; return 0; fi
  local total; total=$(grep -cve '^\s*$' "$manifest" || echo 0)
  log_info "Removing $total entries"
  _json_out "to_remove" "$total"
  local idx=0
  while IFS= read -r file; do
    [ -z "$file" ] && continue
    idx=$((idx+1))
    # safety checks
    local rp; rp=$(realpath_safe "$file" 2>/dev/null) || { log_warn "Skipping unsafe path: $file"; printf "%s\tSKIP_UNSAFE\n" "$file" >> "$BACKUP_META"; continue; }
    case "$rp" in
      "/"|"/bin"|"/sbin"|"/usr"|"/etc"|"/home"|"${HOME}"|"/root")
        log_error "Refusing to remove critical path: $rp"; printf "%s\tREFUSED\n" "$file" >> "$BACKUP_META"; return 1;;
    esac
    if [ ! -e "$rp" ]; then
      log_warn "Already absent: $rp"; printf "%s\tMISSING\n" "$file" >> "$BACKUP_META"; continue
    fi
    # check shared usage: naive check in depends DB (could be improved)
    if [ -f "$DEPENDS_DB" ]; then
      if grep -qF "$rp" "$DEPENDS_DB" 2>/dev/null; then
        if grep -v "^${PKG}\s" "$DEPENDS_DB" | grep -qF "$rp"; then
          log_warn "Shared by other packages, skipping: $rp"; printf "%s\tSKIPPED_SHARED\n" "$file" >> "$BACKUP_META"; continue
        fi
      fi
    fi
    if [ "$CONFIRM_EACH" -eq 1 ]; then
      printf "Remove %s ? [y/N]: " "$rp"; read -r ans || ans="n"
      case "$ans" in [yY]|[yY][eE][sS]) ;; *) log_info "User skipped $rp"; printf "%s\tUSER_SKIP\n" "$file" >> "$BACKUP_META"; continue ;; esac
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
      log_info "(DRY-RUN) Would remove: $rp"; printf "%s\tDRYRUN\n" "$file" >> "$BACKUP_META"; continue
    fi
    if [ -f "$rp" ] || [ -L "$rp" ]; then
      rm -f -- "$rp" || { log_error "Failed to remove $rp"; printf "%s\tREMOVE_FAIL\n" "$file" >> "$BACKUP_META"; return 1; }
      printf "%s\tREMOVED\n" "$file" >> "$BACKUP_META"
    elif [ -d "$rp" ]; then
      # only rmdir empty dirs
      if [ -z "$(ls -A "$rp" 2>/dev/null || true)" ]; then
        rmdir "$rp" || { log_warn "rmdir failed: $rp"; printf "%s\tDIR_RMD_FAIL\n" "$file" >> "$BACKUP_META"; }
        printf "%s\tDIR_REMOVED\n" "$file" >> "$BACKUP_META"
      else
        log_warn "Directory not empty, skipping: $rp"; printf "%s\tDIR_NOT_EMPTY\n" "$file" >> "$BACKUP_META"
      fi
    else
      log_warn "Unknown type for $rp, skipping"; printf "%s\tSKIPPED_UNKNOWN\n" "$file" >> "$BACKUP_META"
    fi
  done < "$manifest"
  return 0
}

_unregister_package() {
  log_info "Removing package entry from DB: $PKG"
  _json_out "unregister" "$PKG"
  if [ -f "$PACKAGES_DB" ]; then
    local tmp="${PACKAGES_DB}.tmp.$$"
    grep -vE "^${PKG}\t" "$PACKAGES_DB" > "$tmp" || true
    mv -f "$tmp" "$PACKAGES_DB" || { log_error "Failed updating packages DB"; return 1; }
  fi
  rm -f "${INSTALLED_MANIFEST_DIR}/${PKG}.manifest" || true
  return 0
}

_detect_orphans() {
  if [ ! -f "$DEPENDS_DB" ]; then log_warn "Depends DB missing"; return 0; fi
  # naive: a package is orphan if no other package lists it as dependency
  local allpkgs; allpkgs=($(awk -F'\t' '{print $1}' "$PACKAGES_DB" 2>/dev/null || true))
  local orphans=()
  for p in "${allpkgs[@]:-}"; do
    # count reverse deps
    local cnt; cnt=$(grep -F "$p" "$DEPENDS_DB" | wc -l || echo 0)
    if [ "$cnt" -eq 0 ]; then orphans+=("$p"); fi
  done
  printf "%s\n" "${orphans[@]:-}"
  return 0
}

_rollback_from_backup() {
  if [ -z "${BACKUP_DIR:-}" ] || [ ! -d "${BACKUP_DIR}/files" ]; then
    log_error "No backup available for rollback"
    return 1
  fi
  log_info "Restoring backup to system paths"
  # use tar pipeline to restore preserving attributes
  (cd "$BACKUP_DIR/files" && tar -cf - .) | (cd / && tar -xpf -) || { log_error "Rollback restore failed"; return 1; }
  log_info "Rollback completed (basic restore). Validate logs for details"
  _json_out "rollback" "completed"
  return 0
}

_run_hooks() {
  local stage="$1" pkg="$2"
  local g="hooks/global/${stage}" p="pkgs/${pkg}/hooks/${stage}"
  local any=0
  for h in "$g"/* "$p"/*; do
    [ -f "$h" ] || continue
    any=1
    log_info "Running hook $h (stage $stage)"
    _json_out "hook" "$h"
    if [ "$DRY_RUN" -eq 1 ]; then log_info "(DRY-RUN) would run $h"; continue; fi
    if ! timeout 120 sandbox_exec "$h"; then
      log_warn "Hook failed or timed out: $h"
      printf "%s\tHOOK_FAILED\n" "$h" >> "$BACKUP_META"
    fi
  done
  if [ "$any" -eq 0 ]; then log_debug "No hooks for $stage"; fi
  return 0
}

_uninstall_main() {
  log_section "uninstall:$PKG"
  local manifest; manifest=$(_verify_pkg_installed || true)
  if [ -z "$manifest" ]; then
    if [ "$FORCE" -eq 1 ]; then
      log_warn "Manifest missing but proceeding due to --force"
    else
      log_error "Cannot find installed manifest for $PKG; abort or use --force"
      return 1
    fi
  fi

  _run_hooks pre-uninstall "$PKG" || log_warn "pre-uninstall hooks warned"

  if [ -n "$manifest" ]; then
    if ! _create_backup "$manifest"; then
      log_error "Backup failed; aborting uninstall"
      return 1
    fi
  fi

  if [ -n "$manifest" ]; then
    if ! _remove_files_from_manifest "$manifest"; then
      log_error "Removal failed; attempting rollback"
      _rollback_from_backup || log_error "Rollback failed"
      return 1
    fi
  else
    log_warn "No manifest: cannot reliably remove files"
    if [ "$FORCE" -ne 1 ]; then return 1; fi
  fi

  if ! _unregister_package; then
    log_error "Failed to unregister package; rolling back"
    _rollback_from_backup || log_error "Rollback failed"
    return 1
  fi

  _run_hooks post-uninstall "$PKG" || log_warn "post-uninstall hooks warned"

  if [ "$CLEAN_ORPHANS" -eq 1 ]; then
    log_info "Detecting orphans..."
    local ors; ors=$(_detect_orphans || true)
    if [ -n "$ors" ]; then
      log_info "Orphan candidates:\n$ors"
      if [ "$DRY_RUN" -eq 1 ]; then
        log_info "(DRY-RUN) would remove orphans"
      else
        if [ "$FORCE" -eq 1 ]; then
          for o in $ors; do
            log_info "Removing orphan: $o"
            bash "$(realpath_safe "$0")" "$o" --force --keep-logs || log_warn "Failed to remove orphan $o"
          done
        else
          log_info "Use --force to auto-remove orphans"
        fi
      fi
    else
      log_info "No orphans detected"
    fi
  fi

  _json_out "completed" "true"
  log_ok "Uninstall completed for $PKG"
  return 0
}

main() {
  _parse_args "$@"
  _acquire_lock || { log_error "Failed to acquire lock"; exit 1; }
  _init
  if [ "$ROLLBACK" -eq 1 ]; then
    log_info "Rollback requested"
    _rollback_from_backup || { log_error "Rollback failed"; _release_lock; exit 1; }
    _release_lock
    exit 0
  fi
  _uninstall_main || { log_error "Uninstall failed"; _release_lock; exit 1; }
  # compress logs if not keeping
  if [ "$KEEP_LOGS" -eq 0 ] && [ -f "$LOGFILE" ]; then
    zstd -q -19 "$LOGFILE" -o "${LOGFILE}.zst" || true
    rm -f "$LOGFILE" || true
  fi
  _release_lock || true
  log_info "Finished uninstall for $PKG"
  return 0
}

main "$@"
