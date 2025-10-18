#!/usr/bin/env bash
# lib/logging.sh
# Advanced logging module for LFS tooling
# Implements: colored output, file logging, per-package logs, rotation, JSON NDJSON output,
# atomic writes, concurrency-safe aggregation, traps, masking of secrets, quiet/verbose modes,
# log_cmd/log_pipe helpers, and many fallbacks for portable environments.
#
# Note: Designed to be `source`d by other scripts. It detects environment and adapts.
# Written to be mostly POSIX-friendly but uses some bash features when available.
#
# Usage:
#   source /opt/lfs-tool/lib/logging.sh
#   export PKG_NAME="zlib"; export STAGE="build"
#   log_info "Starting build"
#
# Config via env or /opt/lfs-tool/etc/lfs.conf (sourced if present).
# Key environment variables:
#   LOG_DIR        - base log directory (default: /var/log/lfs)
#   LOG_LEVEL      - 0:silent 1:normal 2:verbose 3:trace (default:1)
#   QUIET          - if 1, terminal output limited to errors & summary
#   JSON_LOGS      - if 1, write ndjson per-event to ${LOG_DIR}/json/
#   ROTATE_MAX     - how many rotated files to keep (default:5)
#   MIN_FREE_KB    - minimum free KB to keep in filesystem (default: 102400 -> 100MB)
#   MASK_PATTERNS  - optional regex patterns (separated by ||) to mask in logs
#   DEBUG_TRACE    - if 1, enable set -x tracing recorded to trace file
#
# This file attempts to be self-contained and safe to source multiple times.
#
########################################

# Avoid double-sourcing
if [ -n "${__LFS_LOGGING_SH_LOADED:-}" ]; then
    return 0 2>/dev/null || exit 0
fi
__LFS_LOGGING_SH_LOADED=1

# Ensure we have bash-like behavior for some constructs; fallback to POSIX where possible
SHELL_NAME="$(ps -p $$ -o comm= 2>/dev/null || echo sh)"

# Load optional config file
if [ -f "/opt/lfs-tool/etc/lfs.conf" ]; then
    # shellcheck disable=SC1090
    . /opt/lfs-tool/etc/lfs.conf
fi

# Defaults
: "${LOG_DIR:=/var/log/lfs}"
: "${LOG_LEVEL:=1}"
: "${QUIET:=0}"
: "${JSON_LOGS:=0}"
: "${ROTATE_MAX:=5}"
: "${MIN_FREE_KB:=102400}"  # 100 MB
: "${MASK_PATTERNS:=}"
: "${DEBUG_TRACE:=0}"
: "${LOG_CACHE_LINES:=100}"  # circular buffer size
: "${NO_COLOR:=${NO_COLOR:-0}}"

# Internal state
LOG_PID=$$
: "${PKG_NAME:=unknown}"
: "${STAGE:=main}"
TMPDIR="${TMPDIR:-/tmp}"
__LOG_CURRENT_TMP=""
__LOG_ERRORS=0
__LOG_WARNINGS=0
__LOG_INFO_COUNT=0
__LOG_DEBUG_COUNT=0
__LOG_START_TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
: "${LOG_FILE:=$LOG_DIR/${PKG_NAME}.log}"
: "${GLOBAL_LOG_FILE:=$LOG_DIR/global.log}"
JSON_DIR="$LOG_DIR/json"
__LOG_TRAP_RUNNING=0
__LOG_BUFFER_FILE=""
__LOG_FLUSH_INTERVAL=5  # seconds
__LOG_LAST_FLUSH=0

# Ensure LC for consistent timestamps
export LC_ALL=C

# Utilities detection
_have() { command -v "$1" >/dev/null 2>&1; }

# Ensure paths exist, fallbacks if not writable
_init_log_dir() {
    umask 022
    if mkdir -p "$LOG_DIR" 2>/dev/null; then
        :
    else
        # fallback to user home
        if mkdir -p "$HOME/.lfs/logs" 2>/dev/null; then
            LOG_DIR="$HOME/.lfs/logs"
            LOG_FILE="$LOG_DIR/${PKG_NAME}.log"
            GLOBAL_LOG_FILE="$LOG_DIR/global.log"
            JSON_DIR="$LOG_DIR/json"
            echo "WARNING: cannot create /var/log/lfs - falling back to $LOG_DIR" >&2
        else
            # fallback to /tmp
            LOG_DIR="/tmp/.lfs-logs-$USER"
            mkdir -p "$LOG_DIR"
            LOG_FILE="$LOG_DIR/${PKG_NAME}.log"
            GLOBAL_LOG_FILE="$LOG_DIR/global.log"
            JSON_DIR="$LOG_DIR/json"
            echo "WARNING: falling back to $LOG_DIR" >&2
        fi
    fi
    mkdir -p "$JSON_DIR" 2>/dev/null || true
    # create files if not present
    : > "$GLOBAL_LOG_FILE" 2>/dev/null || true
    : > "$LOG_FILE" 2>/dev/null || true
}

_init_log_dir

# Detect color support
__supports_color() {
    if [ "${NO_COLOR:-0}" = "1" ]; then
        return 1
    fi
    if [ -t 1 ]; then
        if _have tput; then
            ncolors=$(tput colors 2>/dev/null || echo 0)
            [ -n "$ncolors" ] && [ "$ncolors" -ge 8 ] && return 0
        else
            return 0
        fi
    fi
    return 1
}

if __supports_color; then
    _C_RESET="$(tput sgr0 2>/dev/null || printf '\033[0m')"
    _C_INFO="$(tput setaf 4 2>/dev/null || printf '\033[34m')"   # blue
    _C_WARN="$(tput setaf 3 2>/dev/null || printf '\033[33m')"   # yellow
    _C_ERROR="$(tput setaf 1 2>/dev/null || printf '\033[31m')"  # red
    _C_SUCCESS="$(tput setaf 2 2>/dev/null || printf '\033[32m')"# green
    _C_DEBUG="$(tput setaf 7 2>/dev/null || printf '\033[37m')"  # grey/white
else
    _C_RESET="" _C_INFO="" _C_WARN="" _C_ERROR="" _C_SUCCESS="" _C_DEBUG=""
fi

# Masking function: masks sensitive patterns configured in MASK_PATTERNS
_mask_line() {
    local line="$1"
    if [ -n "$MASK_PATTERNS" ]; then
        IFS='||' read -r -a pats <<< "$MASK_PATTERNS"
        for p in "${pats[@]}"; do
            # use sed to mask groups; user provides regex with one capture group for secret
            # replace captured group with ****
            # attempt to use perl for robust regex if available
            if _have perl; then
                line=$(printf '%s' "$line" | perl -pe "s/$p/****/g")
            else
                # limited sed fallback: mask anything after key= up to space
                line=$(printf '%s' "$line" | sed -E "s/$p/****/g")
            fi
        done
    fi
    printf '%s' "$line"
}

# JSON escape helper - prefer python3 or perl; fallback to basic escaping
_json_escape() {
    local s="$1"
    if _have python3; then
        python3 - <<'PY' 2>/dev/null
import sys, json
s = sys.stdin.read()
sys.stdout.write(json.dumps(s))
PY
    elif _have perl; then
        perl -MJSON::XS -0777 -ne 'print JSON::XS->new->encode($_)' <<<"$s"
    else
        # minimal escape: replace backslash and quotes and control chars
        printf '%s' "$s" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a;N;s/\n/\\n/g;ta'
    fi
}

# timestamp
_log_ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# Atomic write: write a line to target file using temp + mv with flock if available
_atomic_append() {
    local target="$1"; shift
    local content="$*"
    local tmp
    tmp=$(mktemp "${LOG_DIR}/.tmp.XXXXXX") || tmp="/tmp/.lfs.tmp.$$"
    printf '%s\n' "$content" > "$tmp"
    if _have flock; then
        # use lock on target during append to avoid races
        exec 9>"$target.lock" 2>/dev/null || true
        flock 9 || true
        cat "$tmp" >> "$target"
        flock -u 9 || true
        exec 9>&- || true
    else
        cat "$tmp" >> "$target"
    fi
    rm -f "$tmp" 2>/dev/null || true
}

# Core log writer
_log_write() {
    # args: level, message
    local level="$1"; shift
    local msg="$*"
    local ts
    ts=$(_log_ts)
    local pid="$$"
    local pkg="${PKG_NAME:-unknown}"
    local stage="${STAGE:-main}"
    # mask line if required
    msg=$(_mask_line "$msg")
    # build plain text and JSON
    local plain="[$ts][$stage][$pkg][$pid][$level] $msg"
    local color_prefix=""
    local color_suffix="$_C_RESET"
    case "$level" in
        INFO) color_prefix="$_C_INFO" ;;
        WARN) color_prefix="$_C_WARN" ;;
        ERROR) color_prefix="$_C_ERROR" ;;
        SUCCESS) color_prefix="$_C_SUCCESS" ;;
        DEBUG) color_prefix="$_C_DEBUG" ;;
        *) color_prefix="" ;;
    esac

    # Terminal output policy
    if [ "$QUIET" -ne 1 ]; then
        if [ "$LOG_LEVEL" -ge 2 ] || [ "$level" != "DEBUG" ]; then
            if [ -t 1 ]; then
                # colored to terminal only
                printf '%b\n' "${color_prefix}${plain}${color_suffix}"
            else
                printf '%s\n' "$plain"
            fi
        fi
    else
        # quiet mode: only show ERRORS and summary
        if [ "$level" = "ERROR" ] || [ "$level" = "WARN" ]; then
            printf '%b\n' "${color_prefix}${plain}${color_suffix}"
        fi
    fi

    # Write to global log and per-package log atomically (use per-PID temp then aggregate)
    local per_pid_log="${LOG_DIR}/${pkg}.${pid}.log"
    _atomic_append "$per_pid_log" "$plain"
    _atomic_append "$GLOBAL_LOG_FILE" "$plain"

    # JSON output if enabled - use ndjson (one object per line)
    if [ "${JSON_LOGS:-0}" -eq 1 ]; then
        local json_line
        # create JSON safely
        # fields: timestamp, pkg, stage, pid, level, message
        if _have python3; then
            json_line=$(python3 - <<PY
import json,sys
obj={"timestamp":"$ts","pkg":"$pkg","stage":"$stage","pid":$pid,"level":"$level","message":sys.stdin.read()}
print(json.dumps(obj, ensure_ascii=False))
PY
<<<"$msg")
        elif _have perl; then
            json_line=$(perl -MJSON::XS -0777 -ne 'print JSON::XS->new->encode({timestamp=>shift, pkg=>shift, stage=>shift, pid=>shift, level=>shift, message=>$_})' "$ts" "$pkg" "$stage" "$pid" "$level" <<<"$msg")
        else
            # fallback minimal, ensure quotes escaped
            esc=$(printf '%s' "$msg" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a;N;s/\n/\\n/g;ta')
            json_line="{\"timestamp\":\"$ts\",\"pkg\":\"$pkg\",\"stage\":\"$stage\",\"pid\":$pid,\"level\":\"$level\",\"message\":\"$esc\"}"
        fi
        # atomic append to file
        _atomic_append "$JSON_DIR/${pkg}.jsonl" "$json_line"
    fi

    # counters
    case "$level" in
        ERROR) __LOG_ERRORS=$((__LOG_ERRORS+1)) ;;
        WARN) __LOG_WARNINGS=$((__LOG_WARNINGS+1)) ;;
        INFO) __LOG_INFO_COUNT=$((__LOG_INFO_COUNT+1)) ;;
        DEBUG) __LOG_DEBUG_COUNT=$((__LOG_DEBUG_COUNT+1)) ;;
    esac

    # periodic flush/aggregate small files into consolidated logs to avoid many small files
    _log_maybe_aggregate
}

# Aggregation: combine per-PID logs to main log safely (acquire flock)
_log_maybe_aggregate() {
    # aggregate if more than X per-pid files or older than a threshold
    local pattern="${LOG_DIR}/${PKG_NAME}.*.log"
    local count
    count=$(ls ${pattern} 2>/dev/null | wc -l || echo 0)
    if [ "$count" -gt 8 ]; then
        _log_aggregate
    else
        # also aggregate periodically based on time
        now=$(date +%s)
        if [ $((now - __LOG_LAST_FLUSH)) -ge "$__LOG_FLUSH_INTERVAL" ]; then
            _log_aggregate
        fi
    fi
}

_log_aggregate() {
    # prevent concurrent aggregation
    if _have flock; then
        exec 200>"$LOG_DIR/aggregate.lock" 2>/dev/null || true
        flock -n 200 || return 0
    fi
    # concatenate per-pid logs into main pkg log
    for f in "$LOG_DIR"/${PKG_NAME}.*.log; do
        [ -f "$f" ] || continue
        # skip final main file
        if [ "$f" = "$LOG_FILE" ] || [ "$f" = "$GLOBAL_LOG_FILE" ]; then
            continue
        fi
        cat "$f" >> "$LOG_FILE" 2>/dev/null || true
        rm -f "$f" 2>/dev/null || true
    done
    __LOG_LAST_FLUSH=$(date +%s)
    if _have flock; then
        flock -u 200 || true
        exec 200>&- || true
    fi
}

# rotation: rotate a given file safely
_log_rotate_file() {
    local target="$1"
    local max="${ROTATE_MAX:-5}"
    [ -f "$target" ] || return 0
    # ensure lock
    if _have flock; then
        exec 201>"$target.rotate.lock" 2>/dev/null || true
        flock -x 201 || return 1
    fi
    # rotate
    for i in $(seq "$max" -1 1); do
        if [ -f "${target}.$i" ]; then
            mv "${target}.$i" "${target}.$((i+1))" 2>/dev/null || true
        fi
    done
    mv "$target" "${target}.1" 2>/dev/null || true
    : > "$target"
    # compress older than 2
    if _have gzip; then
        for f in "${target}."*; do
            [ -f "$f" ] || continue
            # compress in background
            gzip -9 "$f" >/dev/null 2>&1 &
        done
    fi
    if _have flock; then
        flock -u 201 || true
        exec 201>&- || true
    fi
}

# ensure space - purge oldest rotated compressed logs if needed
_ensure_space() {
    if _have df; then
        local avail
        avail=$(df --output=avail "$LOG_DIR" 2>/dev/null | tail -1 || echo 0)
        if [ -z "$avail" ]; then avail=0; fi
        if [ "$avail" -lt "${MIN_FREE_KB:-102400}" ]; then
            # delete oldest compressed logs (gzip files)
            find "$LOG_DIR" -type f -name '*.gz' -print0 | xargs -0 rm -f -- 2>/dev/null || true
            log_warn "Low disk space in $LOG_DIR - purged oldest compressed logs"
        fi
    fi
}

# trap handlers
__log_on_err() {
    if [ "$__LOG_TRAP_RUNNING" -eq 1 ]; then
        return 0
    fi
    __LOG_TRAP_RUNNING=1
    local rc=$?
    local cmd="${BASH_COMMAND:-unknown}"
    # report
    _log_write "ERROR" "Unexpected error (rc=$rc) at command: $cmd"
    # attempt flush and aggregation
    _log_aggregate
    __LOG_TRAP_RUNNING=0
}

__log_on_exit() {
    local rc=$?
    _log_aggregate
    # rotate logs if big
    _log_rotate_file "$LOG_FILE"
    _log_rotate_file "$GLOBAL_LOG_FILE"
    # summary
    local end_ts
    end_ts=$(_log_ts)
    local duration="unknown"
    # attempt to calculate duration if start present
    if date -d >/dev/null 2>&1; then
        start_epoch=$(date -d "$__LOG_START_TS" +%s 2>/dev/null || echo 0)
        end_epoch=$(date -d "$end_ts" +%s 2>/dev/null || echo 0)
    else
        start_epoch=0; end_epoch=0
    fi
    if [ "$start_epoch" -gt 0 ] && [ "$end_epoch" -gt "$start_epoch" ]; then
        duration=$((end_epoch - start_epoch))
    fi
    _log_write "INFO" "Run summary: errors=$__LOG_ERRORS warnings=$__LOG_WARNINGS info=$__LOG_INFO_COUNT debug=$__LOG_DEBUG_COUNT duration=${duration}s"
    # If exit code non-zero, surface
    if [ "$rc" -ne 0 ]; then
        _log_write "ERROR" "Process exited with code $rc"
    fi
}

# set traps: ERR and EXIT
# Use bash-specific features if available
if [ -n "${BASH_VERSION:-}" ]; then
    trap '__log_on_err' ERR
    trap '__log_on_exit' EXIT
else
    # POSIX sh fallback: trap EXIT only
    trap '__log_on_exit' EXIT
fi

# Public API

log_info()    { _log_write "INFO" "$*"; }
log_warn()    { _log_write "WARN" "$*"; }
log_error()   { _log_write "ERROR" "$*"; }
log_success() { _log_write "SUCCESS" "$*"; }
log_debug()   {
    if [ "${LOG_LEVEL:-1}" -ge 2 ]; then
        _log_write "DEBUG" "$*"
    fi
}

# silent error: log but do not print to terminal unless QUIET=0? we still record
log_silent_error() {
    local msg="$*"
    # always write into files, but only show on terminal if VERBOSE
    local prev_quiet="$QUIET"
    QUIET=1
    _log_write "ERROR" "$msg"
    QUIET="$prev_quiet"
}

# log section headers
log_section() {
    local title="$*"
    local sep="========================================"
    _log_write "INFO" "$sep"
    _log_write "INFO" "=== $title ==="
    _log_write "INFO" "$sep"
}

# log step with progress
log_step() {
    local cur="$1"; shift
    local total="$1"; shift
    local msg="$*"
    _log_write "INFO" "[$cur/$total] $msg"
}

# Execute a command and capture output; writes to per-pid temp log and global log.
# Returns command exit code.
log_cmd() {
    if [ $# -eq 0 ]; then
        _log_write "ERROR" "log_cmd invoked with no arguments"
        return 2
    fi
    local cmd="$*"
    local tlog
    tlog=$(mktemp "${LOG_DIR}/cmd.XXXXXX") || tlog="/tmp/cmd.$$"
    # Use bash -c to preserve pipes; capture exit code
    if [ -n "${BASH_VERSION:-}" ]; then
        bash -c "$cmd" >"$tlog" 2>&1
        rc=$?
    else
        sh -c "$cmd" >"$tlog" 2>&1
        rc=$?
    fi
    # prefix output and append to logs
    if [ -s "$tlog" ]; then
        while IFS= read -r line; do
            _log_write "INFO" "[CMD] $line"
        done < "$tlog"
    fi
    rm -f "$tlog" 2>/dev/null || true
    return $rc
}

# log_pipe: wrapper to capture a pipeline's stdout and stderr preserving exit code
# Usage: somecmd | log_pipe
log_pipe() {
    # read from stdin and write each line prefixed
    local tlog
    tlog=$(mktemp "${LOG_DIR}/pipe.XXXXXX") || tlog="/tmp/pipe.$$"
    while IFS= read -r line; do
        _log_write "INFO" "[PIPE] $line"
    done
    rm -f "$tlog" 2>/dev/null || true
}

# helper to run hooks: capture their output and prefix
run_hook() {
    local hook="$1"
    shift || true
    if [ ! -x "$hook" ]; then
        _log_write "WARN" "Hook $hook not executable or missing"
        return 0
    fi
    local tmpf
    tmpf=$(mktemp "${LOG_DIR}/hook.XXXXXX") || tmpf="/tmp/hook.$$"
    # run hook in subshell with environment PKG_NAME/STAGE
    ( PKG_NAME="$PKG_NAME" STAGE="$STAGE" "$hook" "$@" ) >"$tmpf" 2>&1 || true
    while IFS= read -r l; do
        _log_write "INFO" "[HOOK:${hook##*/}] $l"
    done < "$tmpf"
    rm -f "$tmpf" 2>/dev/null || true
}

# Mask patterns setter helper
set_mask_patterns() {
    MASK_PATTERNS="$*"
}

# rotate all logs (public)
log_rotate_all() {
    _log_rotate_file "$LOG_FILE"
    _log_rotate_file "$GLOBAL_LOG_FILE"
    for f in "$JSON_DIR"/*.jsonl; do
        [ -f "$f" ] || continue
        _log_rotate_file "$f"
    done
}

# small in-memory circular buffer for recent messages (for quick debugging)
__LOG_CIRC_BUFFER=()
__LOG_CIRC_INDEX=0
__LOG_CIRC_MAX="$LOG_CACHE_LINES"
_log_circ_push() {
    local msg="$*"
    __LOG_CIRC_BUFFER[$__LOG_CIRC_INDEX]="$msg"
    __LOG_CIRC_INDEX=$(( (__LOG_CIRC_INDEX + 1) % __LOG_CIRC_MAX ))
}

# Wrapper that pushes to circular buffer and writes
_log_write_and_cache() {
    __log_msg="$*"
    _log_circ_push "$__log_msg"
    _log_write "$__log_msg"
}

# expose a dump function for buffer
log_dump_recent() {
    local n="${1:-50}"
    local count=${#__LOG_CIRC_BUFFER[@]}
    [ "$count" -eq 0 ] && return 0
    local i=0
    echo "Last $n messages:"
    for ((i=0;i<count && i<n;i++)); do
        idx=$(( ( __LOG_CIRC_INDEX + i ) % __LOG_CIRC_MAX ))
        printf '%s\n' "${__LOG_CIRC_BUFFER[$idx]}"
    done
}

# Doctor checks for dependencies / environment
log_doctor() {
    _log_write "INFO" "Running doctor checks"
    for cmd in flock mktemp gzip zstd python3 perl jq; do
        if _have "$cmd"; then
            _log_write "INFO" "Found $cmd"
        else
            _log_write "WARN" "Missing $cmd - some features may be degraded"
        fi
    done
    # check disk space
    if _have df; then
        local avail
        avail=$(df --output=avail "$LOG_DIR" 2>/dev/null | tail -1 || echo 0)
        _log_write "INFO" "Available KB on $(df -P "$LOG_DIR" | tail -1 | awk '{print $1}') : $avail"
    fi
}

# Initialize debug trace if requested
if [ "${DEBUG_TRACE:-0}" -eq 1 ]; then
    if _have bash; then
        PS4='+[$BASH_SOURCE:$LINENO:$FUNCNAME] '
        set -x
        _log_write "DEBUG" "DEBUG_TRACE enabled"
    else
        _log_write "WARN" "DEBUG_TRACE requested but bash not available"
    fi
fi

# Finalization: ensure aggregation on source exit if this file sourced in subshells
# Provide explicit flush function
log_flush() {
    _log_aggregate
    _ensure_space
}

# Provide exported convenience env var to be used by other scripts
export LOG_DIR GLOBAL_LOG_FILE LOG_FILE JSON_DIR LOG_LEVEL QUIET JSON_LOGS ROTATE_MAX MIN_FREE_KB MASK_PATTERNS

# End of logging.sh
