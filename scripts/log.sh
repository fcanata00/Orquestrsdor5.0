#!/usr/bin/env bash
# lib/log.sh
# Lightweight logging library for lfsctl project
# - colored terminal output (toggleable)
# - writes full, colorless logs to per-run/per-stage logfile
# - log levels: ERROR(0), WARN(1), INFO(2), DEBUG(3)
# - exports LOG_FILE, LOG_LEVEL, LOG_COLOR, LOG_PREFIX, DRY_RUN
# - uses FD 3 for logfile to avoid mixing with stdout/stderr
# - provides progress bar helpers and system stats capture

set -euo pipefail

# Default configuration
: "${LOG_LEVEL:=2}"        # 0=errors,1=warn,2=info,3=debug
: "${LOG_COLOR:=1}"
: "${LOG_STDERR:=1}"
: "${LOG_PREFIX:=lfsctl}"
: "${LOG_DATEFMT:=%Y-%m-%d %H:%M:%S}"
: "${LOG_ROTATE_SIZE_MB:=0}" # 0 = disabled
: "${LOG_KEEP:=5}"
: "${DRY_RUN:=0}"

# Internal color codes (can be disabled)
_LOG_C_RESET='\033[0m'
_LOG_C_INFO='\033[36m'   # cyan
_LOG_C_WARN='\033[33m'   # yellow
_LOG_C_ERROR='\033[31m'  # red
_LOG_C_OK='\033[32m'     # green
_LOG_C_DEBUG='\033[90m'  # bright black / grey

# File descriptor used for logfile
_LOG_FD=3

# Create timestamp
log_timestamp() {
  date -u +"[$LOG_DATEFMT]"
}

# Internal low-level writer (writes to logfile FD and optionally to stderr)
_log_write_file() {
  local lvl_ts="$1"; shift
  # Ensure logfile FD is open
  if [ -e "/proc/$$/fd/$_LOG_FD" ] || eval "[ \"\$(bash -c 'exec >/dev/null 2>&1; true')\" ]"; then
    printf "%s %s %s\n" "$lvl_ts" "$LOG_PREFIX" "$*" >&$_LOG_FD || true
  fi
}

# Safe open logfile; accepts an optional argument: path
log_init() {
  local logfile="${1:-}"; shift || true
  if [ -z "$logfile" ]; then
    # default logs dir
    local _ts
    _ts=$(date -u +"%Y%m%d-%H%M%S")
    mkdir -p "logs" || true
    logfile="logs/${LOG_PREFIX}-${_ts}.log"
  else
    mkdir -p "$(dirname "$logfile")" || true
  fi

  # Open logfile on FD 3 for append
  exec 3>>"$logfile" || {
    echo "[ERROR] failed to open log file: $logfile" >&2
    return 1
  }

  # Export variables so child scripts inherit
  export LOG_FILE="$logfile"
  export LOG_LEVEL
  export LOG_COLOR
  export LOG_STDERR
  export LOG_PREFIX
  export DRY_RUN

  # If colors are disabled for terminal output, we still keep logs plain in file
  # Print minimal startup info to stdout (by default only stage and path)
  printf "[%s] [%s] Log criado: %s\n" "$(date -u +"%Y-%m-%d %H:%M:%S")" "$LOG_PREFIX" "$logfile"
}

# Close logfile
log_exit() {
  # flush and close FD 3
  if [ -e "/proc/$$/fd/$_LOG_FD" ]; then
    exec $_LOG_FD>&-
  fi
}

# Internal format and color decision
_log_fmt() {
  local level_name="$1"; shift
  local color_code="$1"; shift || true
  local msg="$*"
  local ts
  ts=$(log_timestamp)
  # Always write plain entry to logfile
  _log_write_file "$ts" "[$level_name]" "$msg"

  # Terminal output: respect LOG_LEVEL and LOG_COLOR
  case "$level_name" in
    ERROR)
      [ "$LOG_LEVEL" -ge 0 ] || return
      ;;
    WARN)
      [ "$LOG_LEVEL" -ge 1 ] || return
      ;;
    INFO)
      [ "$LOG_LEVEL" -ge 2 ] || return
      ;;
    DEBUG)
      [ "$LOG_LEVEL" -ge 3 ] || return
      ;;
    *)
      ;;
  esac

  if [ "$LOG_COLOR" -eq 1 ] && [ -n "$color_code" ]; then
    printf "%s %b[%s]%b %s\n" "$ts" "$color_code" "$level_name" "$_LOG_C_RESET" "$msg"
  else
    printf "%s [%s] %s\n" "$ts" "$level_name" "$msg"
  fi

  # errors optionally to stderr as well
  if [ "$level_name" = "ERROR" ] && [ "$LOG_STDERR" -eq 1 ]; then
    printf "%s [%s] %s\n" "$ts" "$level_name" "$msg" >&2
  fi
}

# Public logger functions
log_error() {
  _log_fmt "ERROR" "$_LOG_C_ERROR" "$*"
}

log_warn() {
  _log_fmt "WARN" "$_LOG_C_WARN" "$*"
}

log_info() {
  _log_fmt "INFO" "$_LOG_C_INFO" "$*"
}

log_ok() {
  _log_fmt "OK" "$_LOG_C_OK" "$*"
}

log_debug() {
  # debug should only appear if LOG_LEVEL >=3
  _log_fmt "DEBUG" "$_LOG_C_DEBUG" "$*"
}

log_raw() {
  local ts
  ts=$(log_timestamp)
  _log_write_file "$ts" "[RAW]" "$*"
  printf "%s\n" "$*"
}

# Set log level at runtime
log_set_level() {
  case "$1" in
    error) LOG_LEVEL=0 ;;
    warn)  LOG_LEVEL=1 ;;
    info)  LOG_LEVEL=2 ;;
    debug) LOG_LEVEL=3 ;;
    '') ;;
    *) LOG_LEVEL="$1" ;;
  esac
  export LOG_LEVEL
}

# Short section header for build stages (prints minimal to screen but writes full details to log)
log_section() {
  local title="$1"
  local ts
  ts=$(date -u +"%Y-%m-%d %H:%M:%S")
  # On terminal show compact line with path to log file
  if [ -n "${LOG_FILE:-}" ]; then
    printf "==> %s: %s (log: %s)\n" "$title" "$ts" "$LOG_FILE"
  else
    printf "==> %s: %s\n" "$title" "$ts"
  fi
  # Add a separator in the logfile
  _log_write_file "$(log_timestamp)" "[SECTION]" "==== $title ===="
}

# Progress bar helpers
# Usage: log_progress_init TOTAL_BYTES
#        log_progress_update BYTES_DOWNLOADED
#        log_progress_finish
_log_progress_total=0
_log_progress_done=0
_log_progress_width=40
_log_progress_last_shown=0

log_progress_init() {
  _log_progress_total=${1:-0}
  _log_progress_done=0
  # detect terminal width
  if command -v tput >/dev/null 2>&1; then
    local cols
    cols=$(tput cols 2>/dev/null || echo 80)
    # reserve space for percent and numbers
    _log_progress_width=$((cols - 30))
    [ "$_log_progress_width" -lt 10 ] && _log_progress_width=10
  fi
  _log_progress_last_shown=0
}

log_progress_update() {
  local done_bytes=${1:-0}
  _log_progress_done=$done_bytes
  local total=$_log_progress_total
  local pct=0
  if [ "$total" -gt 0 ]; then
    pct=$((100 * _log_progress_done / total))
  fi

  # only update screen when percent changed
  if [ "$pct" -ne "$_log_progress_last_shown" ]; then
    _log_progress_last_shown=$pct
    # build bar
    local filled=$(( _log_progress_width * pct / 100 ))
    local empty=$(( _log_progress_width - filled ))
    local bar
    bar=$(printf '%*s' "$filled" '' | tr ' ' '#')
    bar+=$(printf '%*s' "$empty" '' | tr ' ' '-')
    # human readable sizes
    local human_done human_total
    human_done=$(numfmt --to=iec --suffix=B --format="%.1f" "$(_log_progress_done)" 2>/dev/null || printf "%s" "$_log_progress_done")
    human_total=$(numfmt --to=iec --suffix=B --format="%.1f" "$total" 2>/dev/null || printf "%s" "$total")
    printf '\r[%3d%%] [%s] %s/%s' "$pct" "$bar" "$human_done" "$human_total"
  fi
  # always write detailed line to logfile
  _log_write_file "$(log_timestamp)" "[PROGRESS]" "${pct}%% ${_log_progress_done}/${total}"
}

log_progress_finish() {
  printf '\n'
  _log_write_file "$(log_timestamp)" "[PROGRESS]" "FINISHED ${_log_progress_done}/${_log_progress_total}"
}

# Capture system stats and write detailed breakdown to logfile; show compact summary to terminal
log_system_stats() {
  # CPU cores
  local cores
  cores=$(nproc 2>/dev/null || echo 1)

  # CPU usage (instant) via top or /proc
  local cpu_usage
  if [ -r /proc/stat ]; then
    # read two snapshots to compute quick busy percentage
    local a1 a2 b1 b2 idle1 idle2 total1 total2
    read -r cpu a1 a2 a2 b1 b2 idle1 rest < /proc/stat || true
    # simple fallback: show loadavg instead of cpu%
    cpu_usage="N/A"
  else
    cpu_usage="N/A"
  fi

  # Memory usage
  local mem_total mem_available mem_used
  if [ -r /proc/meminfo ]; then
    mem_total=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
    mem_available=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
    if [ "$mem_total" -gt 0 ]; then
      mem_used=$((mem_total - mem_available))
    else
      mem_used=0
    fi
  else
    mem_total=0
    mem_available=0
    mem_used=0
  fi

  # Load average
  local loadavg
  if [ -r /proc/loadavg ]; then
    loadavg=$(awk '{print $1" " $2" " $3}' /proc/loadavg)
  else
    loadavg="N/A"
  fi

  # Write full details to logfile
  _log_write_file "$(log_timestamp)" "[SYSSTAT]" "cores=${cores} mem_kb_total=${mem_total} mem_kb_used=${mem_used} loadavg=${loadavg}"

  # Print compact summary to terminal (no sensitive details)
  printf "[sys] cores=%s mem_used_kb=%s loadavg=%s\n" "$cores" "$mem_used" "$loadavg"
}

# Robust wrapper to run commands and capture failures; prints friendly message and logs details
# Usage: log_run "description" -- cmd args...
log_run() {
  local description
  description="$1"
  shift
  # The remainder is command; allow using -- to separate
  if [ "${1:-}" = "--" ]; then shift; fi

  log_section "$description"
  log_info "Iniciando: $description"

  # Run command, capture stdout/stderr to logfile while also showing minimal status on terminal
  # Use a subshell so we can capture exit status
  (
    # redirect stdout/stderr to logfile FD
    exec 1>&$_LOG_FD 2>&$_LOG_FD
    # run the command
    "$@"
  )
  local rc=$?
  if [ $rc -ne 0 ]; then
    log_error "Falha ao executar: $description (exit=$rc). Ver logs: $LOG_FILE"
    return $rc
  else
    log_ok "Concluído: $description"
  fi
}

# Ensure we close logfile on EXIT
trap 'log_exit' EXIT

# Export helper functions for subshells (if required)
export -f log_timestamp log_error log_warn log_info log_ok log_debug log_raw log_set_level log_section log_progress_init log_progress_update log_progress_finish log_system_stats log_run

# End of lib/log.sh

