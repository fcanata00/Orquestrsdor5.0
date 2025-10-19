#!/usr/bin/env bash
# cli.sh - Unified command-line for lfsctl
# Features:
#  - Subcommand dispatcher: fetch, build, depends, uninstall, upgrade, clean, status, log, watch, rest, info, plugin
#  - Robust argument parsing with flags and command-specific options
#  - Global flags: --dry-run, --verbose, --quiet, --no-color, --parallel, --profile
#  - Parallel job control (POSIX semaphore using FIFO) for builds
#  - Plugin system: pkgs/plugins and /usr/local/lib/lfsctl/plugins
#  - Program info: reads pkgs/<pkg>/metadata or packages.db
#  - Extensive error handling, traps, logging, rotation
#  - Integrates with fetch.sh, build.sh, depends.sh, uninstall.sh, upgrade.sh, utils.sh, log.sh
#
# Requirements: bash >= 4.4 recommended. Utilities: awk, sed, tar, jq (optional), python3 (optional)
set -Eeuo pipefail
IFS=$'\n\t'

# ---- helpers for colorized output (respect --no-color) ----
COLOR=yes
_red(){ [ "${COLOR}" = yes ] && printf "\e[31m%s\e[0m\n" "$*"; [ "${COLOR}" != yes ] && printf "%s\n" "$*"; }
_green(){ [ "${COLOR}" = yes ] && printf "\e[32m%s\e[0m\n" "$*"; [ "${COLOR}" != yes ] && printf "%s\n" "$*"; }
_yellow(){ [ "${COLOR}" = yes ] && printf "\e[33m%s\e[0m\n" "$*"; [ "${COLOR}" != yes ] && printf "%s\n" "$*"; }
_blue(){ [ "${COLOR}" = yes ] && printf "\e[34m%s\e[0m\n" "$*"; [ "${COLOR}" != yes ] && printf "%s\n" "$*"; }
_plain(){ printf "%s\n" "$*"; }

# ---- find and source libs ----
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

# fallback minimal log functions if lib/log.sh not present
if ! _find_and_source "log"; then
  log_section(){ _blue "==> $*"; }
  log_info(){ _plain "[INFO] $*"; }
  log_warn(){ _yellow "[WARN] $*"; }
  log_error(){ _red "[ERROR] $*"; }
  log_debug(){ [ "${VERBOSE:-0}" -ge 1 ] && _plain "[DEBUG] $*"; }
  log_ok(){ _green "[OK] $*"; }
else
  # lib/log.sh may define log_set_level etc.
  :
fi

# require utils (will exit if missing)
if ! _find_and_source "utils"; then
  log_warn "lib/utils.sh not found; some features (sandbox, checksums) may be limited"
fi

# ---- defaults ----
CLI_NAME="$(basename "$0")"
PKGS_DIR="${PKGS_DIR:-pkgs}"
LFS_DB="${LFS_DB:-${LFS_ROOT:-.}/var/lib/lfsctl}"
LFS_LOGS="${LFS_LOGS:-${LFS_ROOT:-.}/var/log/lfsctl}"
LOCK_DIR="${LFS_DB}/locks"
ensure_dir() { mkdir -p "$1" 2>/dev/null || true; }

ensure_dir "$LFS_LOGS"
ensure_dir "$LOCK_DIR"

# Global flags (defaults)
DRY_RUN=0
VERBOSE=0
QUIET=0
NO_COLOR=0
PARALLEL_JOBS=1
PROFILE="default"
PLUGIN_DIRS=("$PKGS_DIR/plugins" "/usr/local/lib/lfsctl/plugins")
LOG_FILE="${LFS_LOGS}/cli-$(date -u +%Y%m%dT%H%M%SZ).log"

# semaphore for parallelism
_semaphore_init() {
  local slots=$1
  semfifo="${TMPDIR:-/tmp}/cli_semaphore_$$"
  rm -f "$semfifo" || true
  mkfifo "$semfifo"
  exec 9<>"$semfifo"
  rm -f "$semfifo"
  # fill tokens
  for i in $(seq 1 $slots); do printf '%s\n' "token" >&9; done
}
_semaphore_acquire() {
  local token
  read -r -u 9 token || return 1
}
_semaphore_release() {
  printf '%s\n' "token" >&9 || true
}
_semaphore_destroy() {
  exec 9>&- || true
}

# error handling
_on_error() {
  local lineno=${1:-0} rc=${2:-1}
  log_error "CLI error at line ${lineno} (rc=${rc})"
  log_error "See log: $LOG_FILE"
  _semaphore_destroy || true
  exit "$rc"
}
trap ' _on_error ${LINENO} $?' ERR
trap ' _on_exit ' EXIT INT TERM

_on_exit() {
  # cleanup
  _semaphore_destroy || true
}

# ---- argument parser helper ----
_parse_global_args() {
  # parse global flags until a command is found
  local args=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run) DRY_RUN=1; shift ;;
      --verbose|-v) VERBOSE=$((VERBOSE+1)); shift ;;
      --quiet|-q) QUIET=1; shift ;;
      --no-color) NO_COLOR=1; COLOR=no; shift ;;
      --parallel|-j) PARALLEL_JOBS="$2"; shift 2 ;;
      --profile) PROFILE="$2"; shift 2 ;;
      --help|-h) _cli_help; exit 0 ;;
      --) shift; break ;;
      fetch|build|depends|uninstall|upgrade|clean|status|log|watch|rest|info|plugin) break ;;
      *) 
        # if unknown and looks like a command, break to let subcommand parser handle
        if [[ "$1" =~ ^[a-zA-Z] ]]; then break; fi
        args+=("$1"); shift ;; 
    esac
  done
  # export parsed globals
  export DRY_RUN VERBOSE QUIET PARALLEL_JOBS PROFILE
  return 0
}

# ---- help text ----
_cli_help() {
  cat <<EOF
$CLI_NAME - LFSCTL command line

Usage: $CLI_NAME [global-options] <command> [command-options]

Global options:
  --dry-run            simulate actions
  --verbose, -v        increase verbosity (can repeat)
  --quiet, -q          quiet mode
  --no-color           disable colored output
  --parallel N, -j N   number of parallel jobs for build/upgrade (default 1)
  --profile NAME       select build profile (default: default)
  --help, -h           show this help

Commands (aliases):
  fetch (f)            fetch sources for one or more packages
  build (b)            build packages (supports --parallel)
  depends (d)          resolve dependencies or check graph
  uninstall (rm)       remove package
  upgrade (u)          upgrade packages (uses depends.sh)
  clean (c)            clean caches, builds, logs
  status (s)           show system/package status
  log (l)              view logs
  watch (w)            watch pkgs dir and trigger actions
  rest                 start/stop REST API service
  info                 show package info (reads metadata.json)
  plugin               list/install/uninstall plugins
  help                 show per-command help

Examples:
  $CLI_NAME --parallel 4 build gcc
  $CLI_NAME --dry-run upgrade --category dev
  $CLI_NAME info gcc
EOF
}

# ---- utility: execute command with logging and dry-run support ----
_run() {
  local label="$1"; shift
  local cmd=("$@")
  log_section "CMD: $label"
  log_info "Running: ${cmd[*]}"
  printf "[%s] %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "Running: ${cmd[*]}" >> "$LOG_FILE"
  if [ "$DRY_RUN" -eq 1 ]; then
    log_info "(DRY-RUN) Skipping execution of: ${cmd[*]}"
    return 0
  fi
  if [ "${VERBOSE:-0}" -ge 1 ]; then
    "${cmd[@]}"
  else
    "${cmd[@]}" >>"$LOG_FILE" 2>&1
  fi
  local rc=$?
  if [ $rc -ne 0 ]; then
    log_error "Command failed (rc=$rc): ${cmd[*]}"
    return $rc
  fi
  log_ok "Command completed: $label"
  return 0
}

# ---- program info: read metadata.json or packages.db ----
_program_info_from_metadata() {
  local pkg="$1"; local md="${PKGS_DIR}/${pkg}/metadata.json"
  if [ -f "$md" ]; then
    if command -v jq >/dev/null 2>&1; then
      jq . "$md"
    else
      cat "$md"
    fi
    return 0
  fi
  # fallback: packages.db
  if [ -f "${LFS_DB}/packages.db" ]; then
    grep -E "^${pkg}\t" "${LFS_DB}/packages.db" || true
    return 0
  fi
  log_warn "No metadata found for $pkg"
  return 1
}

# ---- plugin system ----
_plugin_list_dirs() {
  for d in "${PLUGIN_DIRS[@]}"; do
    [ -d "$d" ] && printf "%s\n" "$d"
  done
}
_plugin_list() {
  for d in "${PLUGIN_DIRS[@]}"; do
    [ -d "$d" ] || continue
    for f in "$d"/*; do
      [ -x "$f" ] || continue
      printf "%s\t%s\n" "$(basename "$f")" "$f"
    done
  done
}
_plugin_run() {
  local name="$1"; shift
  local found=0
  for d in "${PLUGIN_DIRS[@]}"; do
    local p="$d/$name"
    if [ -x "$p" ]; then
      found=1
      _run "plugin:$name" "$p" "$@"
      break
    fi
  done
  [ $found -eq 0 ] && log_error "Plugin not found: $name"
}

# ---- command implementations ----

cmd_fetch() {
  local pkgs=("$@")
  [ "${#pkgs[@]}" -gt 0 ] || { log_error "Usage: fetch <pkg>..."; return 1; }
  for p in "${pkgs[@]}"; do
    if [ -x "./fetch.sh" ]; then
      _run "fetch $p" bash ./fetch.sh "$p" || return 1
    else
      log_warn "fetch.sh not present; skipping $p"
    fi
  done
}

# build with parallel job control; each build runs in background limited by semaphore
cmd_build() {
  local pkgs=("$@")
  [ "${#pkgs[@]}" -gt 0 ] || { log_error "Usage: build <pkg>..."; return 1; }
  _semaphore_init "$PARALLEL_JOBS"
  local p
  for p in "${pkgs[@]}"; do
    _semaphore_acquire
    {
      if [ -x "./build.sh" ]; then
        if [ "$DRY_RUN" -eq 1 ]; then
          log_info "(DRY-RUN) Would build $p"
        else
          log_info "Building $p (parallel worker)"
          if ! bash ./build.sh "$p"; then
            log_error "build.sh failed for $p"
          fi
        fi
      else
        log_warn "build.sh missing; cannot build $p"
      fi
      _semaphore_release
    } &
  done
  wait
  _semaphore_destroy
  log_ok "Build (parallel) completed for: ${pkgs[*]}"
  return 0
}

cmd_depends() {
  local sub="${1:-}"
  shift || true
  if [ -x "./depends.sh" ]; then
    if [ -z "$sub" ]; then
      bash ./depends.sh check
    else
      bash ./depends.sh "$sub" "$@"
    fi
  else
    log_error "depends.sh not found"
    return 1
  fi
}

cmd_uninstall() {
  local pkg="$1"
  [ -n "$pkg" ] || { log_error "Usage: uninstall <pkg>"; return 1; }
  if [ -x "./uninstall.sh" ]; then
    _run "uninstall $pkg" bash ./uninstall.sh "$pkg"
  else
    log_error "uninstall.sh not found"
    return 1
  fi
}

cmd_upgrade() {
  local opts=()
  local pkgs=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --category) opts+=("$1" "$2"); shift 2 ;;
      --all) opts+=("$1"); shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      *) pkgs+=("$1"); shift ;;
    esac
  done
  # call upgrade.sh with forwarded options
  if [ -x "./upgrade.sh" ]; then
    if [ "${#pkgs[@]}" -eq 0 ]; then
      _run "upgrade (opts)" bash ./upgrade.sh "${opts[@]}"
    else
      for p in "${pkgs[@]}"; do
        _run "upgrade $p" bash ./upgrade.sh "${opts[@]}" --package "$p"
      done
    fi
  else
    log_error "upgrade.sh not found"
    return 1
  fi
}

cmd_clean() {
  local target="${1:-all}"
  case "$target" in
    cache) rm -rf "${LFS_DB}/cache" || true; log_ok "Cache cleaned" ;;
    logs) find "$LFS_LOGS" -maxdepth 1 -type f -name '*.log*' -print0 | xargs -0 -r rm -f || true; log_ok "Logs cleaned" ;;
    builds) rm -rf "${LFS_DB}/builds" || true; log_ok "Builds cleaned" ;;
    all) rm -rf "${LFS_DB}/cache" "${LFS_LOGS}"/* || true; log_ok "All cleaned" ;;
    *) log_error "Unknown clean target: $target"; return 1 ;;
  esac
}

cmd_status() {
  local pkg="$1"
  if [ -z "$pkg" ]; then
    # summary from state dir
    echo "LFSCTL Status Summary"
    echo "Parallel jobs: $PARALLEL_JOBS"
    echo "Profile: $PROFILE"
    echo "Dry-run: $DRY_RUN"
    echo "Log file: $LOG_FILE"
  else
    # show package info
    _program_info_from_metadata "$pkg" || return 1
  fi
}

cmd_log() {
  local pkg="$1"
  if [ -z "$pkg" ]; then
    tail -n 200 "$LOG_FILE" || true
  else
    # try package specific logs
    local ldir="${LFS_LOGS}/${pkg}"
    if [ -d "$ldir" ]; then
      ls -1 "$ldir" | sed -e 's/^/  /'
    else
      log_warn "No logs found for $pkg"
    fi
  fi
}

cmd_watch() {
  local cmdline="${*:-}"
  if [ -z "$cmdline" ]; then
    log_error "Usage: watch --cmd \"<command>\""
    return 1
  fi
  # delegate to depends.sh watch or upgrade.sh --watch where appropriate
  if [ -x "./depends.sh" ]; then
    bash ./depends.sh watch --cmd "$cmdline"
  else
    log_warn "depends.sh missing; fallback polling"
    while true; do
      sleep 5
      eval "$cmdline" || log_warn "Watch action failed"
    done
  fi
}

cmd_rest() {
  local action="${1:-start}"
  case "$action" in
    start)
      if [ -x "./upgrade.sh" ]; then
        bash ./upgrade.sh --rest &
        log_ok "REST API started"
      else
        log_error "upgrade.sh not found (REST implemented there)"
      fi
      ;;
    stop)
      log_info "Stop not implemented; kill python process manually"
      ;;
    *) log_error "Unknown rest action: $action"; return 1 ;;
  esac
}

cmd_info() {
  local pkg="$1"
  [ -n "$pkg" ] || { log_error "Usage: info <pkg>"; return 1; }
  _program_info_from_metadata "$pkg"
}

cmd_plugin() {
  local action="${1:-list}"; shift || true
  case "$action" in
    list)
      _plugin_list || true
      ;;
    run)
      local name="$1"; shift
      [ -n "$name" ] || { log_error "Usage: plugin run <name>"; return 1; }
      _plugin_run "$name" "$@"
      ;;
    *) log_error "Unknown plugin action: $action"; return 1 ;;
  esac
}

# ---- main dispatcher ----
main() {
  if [ $# -eq 0 ]; then _cli_help; exit 0; fi
  # parse globals until the command token
  _parse_global_args "$@"
  # find first non-flag token as command
  local cmd=""
  for a in "$@"; do
    case "$a" in
      fetch|f) cmd="fetch"; break ;;
      build|b) cmd="build"; break ;;
      depends|d) cmd="depends"; break ;;
      uninstall|rm) cmd="uninstall"; break ;;
      upgrade|u) cmd="upgrade"; break ;;
      clean|c) cmd="clean"; break ;;
      status|s) cmd="status"; break ;;
      log|l) cmd="log"; break ;;
      watch|w) cmd="watch"; break ;;
      rest) cmd="rest"; break ;;
      info) cmd="info"; break ;;
      plugin) cmd="plugin"; break ;;
      help|h) _cli_help; exit 0 ;;
      --*) ;;
      *) 
         # if not recognized as flag and not a command, treat as command arg; if no cmd set yet, assume build
         if [ -z "$cmd" ]; then cmd="build"; fi
         break
         ;;
    esac
  done
  # fallback
  if [ -z "$cmd" ]; then _cli_help; exit 1; fi

  # adjust color flag
  if [ "$NO_COLOR" -eq 1 ]; then COLOR=no; fi

  # dispatch to handlers: shift off global args up to command
  # find index of command in "$@"
  local idx=1 total=$#
  for ((i=1;i<=total;i++)); do
    eval "tok=\${$i}"
    case "$tok" in
      fetch|f|build|b|depends|d|uninstall|rm|upgrade|u|clean|c|status|s|log|l|watch|w|rest|info|plugin|help|h)
        idx=$i; break ;;
    esac
  done
  # build args array for subcommand
  local subargs=("${@:$idx+1}")
  # run command
  case "$cmd" in
    fetch) cmd_fetch "${@:$idx+1}" ;;
    build) cmd_build "${@:$idx+1}" ;;
    depends) cmd_depends "${@:$idx+1}" ;;
    uninstall) cmd_uninstall "${@:$idx+1}" ;;
    upgrade) cmd_upgrade "${@:$idx+1}" ;;
    clean) cmd_clean "${@:$idx+1}" ;;
    status) cmd_status "${@:$idx+1}" ;;
    log) cmd_log "${@:$idx+1}" ;;
    watch) cmd_watch "${@:$idx+1}" ;;
    rest) cmd_rest "${@:$idx+1}" ;;
    info) cmd_info "${@:$idx+1}" ;;
    plugin) cmd_plugin "${@:$idx+1}" ;;
    *) log_error "Unknown command: $cmd"; _cli_help; exit 1 ;;
  esac
}

main "$@"
