#!/usr/bin/env bash
# depends.sh - dependency manager for lfsctl
# Features:
#  - resolve dependency graph, detect cycles, topological sort (Kahn)
#  - cache resolution with checksum invalidation
#  - reverse dependency queries
#  - check integrity of depends DB and packages DB
#  - detect rebuild-needed when dependencies change (watcher mode support)
#  - watch mode (inotify or polling) to trigger rebuild analysis on changes
#  - integration with uninstall.sh for orphan cleanup (optional, controlled)
#  - robust error handling, traps, logging, and recovery strategies
#
# Assumptions:
#  - lib/log.sh and lib/utils.sh exist and provide logging and utilities
#  - package metadata and depends files under pkgs/<pkg>/depends or INSTALLED manifests
#  - simple text DBs: $PACKAGES_DB and $DEPENDS_DB
#
# Usage:
#   depends.sh resolve <pkg>
#   depends.sh check
#   depends.sh graph [--dot outfile.dot]
#   depends.sh reverse <pkg>
#   depends.sh rebuild-needed <pkg>
#   depends.sh watch [--dir pkgs] [--cmd "depends.sh resolve ..."]
#
set -Eeuo pipefail
IFS=$'\n\t'

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

# minimal logger fallback
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
  log_error "lib/utils.sh not found; depends.sh requires it."
  exit 1
fi

# ---- defaults and globals ----
: "${LFS_DB:=${LFS_ROOT:-.}/var/lib/lfsctl}"
: "${PKGS_DIR:=pkgs}"
: "${CACHE_DIR:=${LFS_DB}/cache}"
: "${PACKAGES_DB:=${LFS_DB}/packages.db}"
: "${DEPENDS_DB:=${LFS_DB}/depends.db}"
: "${CACHE_FILE:=${CACHE_DIR}/depends.cache}"
: "${WATCH_POLL_INTERVAL:=5}"
: "${INOTIFY_CMD:=$(command -v inotifywait || true)}"

ensure_dir "$CACHE_DIR" || true
ensure_dir "$LFS_DB" || true

# runtime
declare -A GRAPH      # adjacency list: GRAPH["pkg"]="dep1 dep2 ..."
declare -A REVERSE    # reverse adjacency: REVERSE["pkg"]="parent1 parent2 ..."
declare -A HASHES     # checksum of pkgs/<pkg>/depends or manifest for cache invalidation
CACHE_LOADED=0
LOCK_FILE="${LFS_DB}/depends.lock"

# error handling
_on_error() {
  local lineno=${1:-0} rc=${2:-1}
  log_error "depends.sh error at line ${lineno} (rc=${rc})"
  # attempt to release lock
  rm -f "$LOCK_FILE" 2>/dev/null || true
  exit "$rc"
}
trap ' _on_error ${LINENO} $?' ERR

# locking simple file lock with retries/backoff
_acquire_lock() {
  local i=0 backoff=0.1
  while ! ( set -o noclobber; > "$LOCK_FILE" ) 2>/dev/null; do
    i=$((i+1))
    sleep "$backoff"
    backoff=$(awk "BEGIN{print $backoff*1.5}")
    [ $i -gt 200 ] && { log_error "Timeout acquiring lock"; return 1; }
  done
  printf "%s\n" "$$" > "$LOCK_FILE"
  return 0
}
_release_lock() {
  rm -f "$LOCK_FILE" 2>/dev/null || true
  return 0
}

# compute sha256 of a file if exists, normalize before hashing (strip comments/whitespace)
_file_hash() {
  local f="$1"
  if [ ! -f "$f" ]; then printf ""; return 0; fi
  if command -v sha256sum >/dev/null 2>&1; then
    # normalize: remove blank lines and comments starting with #
    awk '!/^[[:space:]]*#/ && NF' "$f" | sha256sum | awk '{print $1}'
  else
    # fallback to md5sum
    awk '!/^[[:space:]]*#/ && NF' "$f" | md5sum | awk '{print $1}'
  fi
}

# load package depends file (pkgs/<pkg>/depends) or manifest field DEPENDENCIES
_load_dep_for_pkg() {
  local pkg="$1"
  local f1="${PKGS_DIR}/${pkg}/depends"
  local f2="${PKGS_DIR}/${pkg}/metadata"
  local deps=()
  if [ -f "$f1" ]; then
    # read space/newline-separated package names, ignore comments
    while IFS= read -r line; do
      line="${line%%#*}"
      line=$(echo "$line" | awk '{$1=$1;print}')
      [ -z "$line" ] && continue
      for d in $line; do deps+=("$d"); done
    done < "$f1"
    HASHES["$pkg"]=$(_file_hash "$f1")
  elif [ -f "$f2" ]; then
    # source metadata in subshell to avoid pollution
    local depsline
    depsline=$(awk '/^DEPENDENCIES=/ {print; exit}' "$f2" || true)
    if [ -n "$depsline" ]; then
      # evaluate array-ish line safely
      # shellcheck disable=SC2086
      eval "$depsline"
      if [ "${#DEPENDENCIES[@]-}" -gt 0 ]; then
        for d in "${DEPENDENCIES[@]}"; do deps+=("$d"); done
      fi
    fi
    HASHES["$pkg"]=$(_file_hash "$f2")
  else
    # no depends declared; empty
    HASHES["$pkg"]=""
  fi
  printf "%s\n" "${deps[@]:-}"
}

# build full graph from pkgs dir or PACKAGES_DB installed list
_build_graph() {
  GRAPH=()
  REVERSE=()
  local pkg list
  # prefer scanning pkgs/ directory for all known packages
  if [ -d "$PKGS_DIR" ]; then
    list=($(find "$PKGS_DIR" -maxdepth 1 -mindepth 1 -type d -printf "%f\n" 2>/dev/null || true))
  else
    list=($(awk -F'\t' '{print $1}' "$PACKAGES_DB" 2>/dev/null || true))
  fi
  # load deps for each
  for pkg in "${list[@]:-}"; do
    mapfile -t deps < <( _load_dep_for_pkg "$pkg" )
    GRAPH["$pkg"]="${deps[*]}"
    for d in "${deps[@]:-}"; do
      REVERSE["$d"]="${REVERSE["$d"]} $pkg"
    done
  done
}

# detect cycles using DFS (returns 0 if no cycles, 1 if cycles found and prints them)
_detect_cycles() {
  local -A state visited stack parent
  # state: 0=unvisited,1=visiting,2=done
  local pkg
  for pkg in "${!GRAPH[@]}"; do state["$pkg"]=0; done
  local found=0
  _dfs() {
    local u="$1"
    state["$u"]=1
    local deps=(${GRAPH["$u"]})
    for v in "${deps[@]:-}"; do
      [ -z "$v" ] && continue
      if [ -z "${state["$v"]+x}" ]; then
        # unknown dependency - mark as unresolved but not a cycle
        continue
      fi
      if [ "${state["$v"]}" -eq 0 ]; then
        parent["$v"]="$u"
        _dfs "$v" || true
      elif [ "${state["$v"]}" -eq 1 ]; then
        # found cycle: backtrack
        found=1
        log_error "Dependency cycle detected involving $v and $u"
        # print cycle path
        local cur="$u"
        printf "Cycle: %s" "$v"
        while [ "$cur" != "$v" ] && [ -n "$cur" ]; do
          printf " -> %s" "$cur"
          cur="${parent["$cur"]}"
        done
        printf "\n"
      fi
    done
    state["$u"]=2
  }
  for pkg in "${!GRAPH[@]}"; do
    if [ "${state["$pkg"]}" -eq 0 ]; then
      _dfs "$pkg"
    fi
  done
  return $found
}

# topological sort (Kahn). Outputs ordered list or returns non-zero on cycles/unresolved deps
_topo_sort() {
  local -A indeg tmpgraph
  local u v
  # build indegree for nodes present in GRAPH
  for u in "${!GRAPH[@]}"; do
    indeg["$u"]=0
  done
  for u in "${!GRAPH[@]}"; do
    for v in ${GRAPH["$u"]}; do
      # only consider edges to known nodes
      if [ -n "${indeg["$v"]+x}" ]; then
        indeg["$v"]=$((indeg["$v"]+1))
      fi
    done
  done
  # queue nodes with indeg 0
  local -a queue result
  for u in "${!indeg[@]}"; do
    if [ "${indeg["$u"]}" -eq 0 ]; then queue+=("$u"); fi
  done
  while [ "${#queue[@]}" -gt 0 ]; do
    u="${queue[0]}"
    queue=("${queue[@]:1}")
    result+=("$u")
    for v in ${GRAPH["$u"]}; do
      if [ -n "${indeg["$v"]+x}" ]; then
        indeg["$v"]=$((indeg["$v"]-1))
        if [ "${indeg["$v"]}" -eq 0 ]; then queue+=("$v"); fi
      fi
    done
  done
  # check if all nodes included
  if [ "${#result[@]}" -ne "${#GRAPH[@]}" ]; then
    log_error "Topological sort failed: graph may have cycles or unresolved deps"
    return 1
  fi
  printf "%s\n" "${result[@]}"
  return 0
}

# resolve dependencies for a package (recursive BFS) - returns list in build order (deps first)
_resolve_for_pkg() {
  local pkg="$1"
  # perform BFS to collect reachable nodes, then topo-sort induced subgraph
  # collect nodes
  local -A seen
  local -a queue nodes
  queue=("$pkg")
  while [ "${#queue[@]}" -gt 0 ]; do
    local cur="${queue[0]}"; queue=("${queue[@]:1}")
    [ -z "$cur" ] && continue
    if [ -n "${seen["$cur"]+x}" ]; then continue; fi
    seen["$cur"]=1
    nodes+=("$cur")
    for d in ${GRAPH["$cur"]}; do
      queue+=("$d")
    done
  done
  # build induced subgraph into temporary arrays
  local -A saved_graph
  local n
  for n in "${nodes[@]}"; do
    saved_graph["$n"]="${GRAPH["$n"]}"
  done
  # temporarily replace GRAPH with induced subgraph for topo sort
  local backup_keys backup_vals
  backup_keys=("${!GRAPH[@]}")
  # copy GRAPH to tmp and then set GRAPH to saved_graph
  declare -A GRAPH_BACKUP
  for k in "${backup_keys[@]}"; do GRAPH_BACKUP["$k"]="${GRAPH["$k"]}"; unset GRAPH["$k"]; done
  for k in "${!saved_graph[@]}"; do GRAPH["$k"]="${saved_graph["$k"]}"; done
  # topo sort
  local ordered
  if ordered=$(_topo_sort 2>/dev/null); then
    # restore original GRAPH
    for k in "${!GRAPH_BACKUP[@]}"; do GRAPH["$k"]="${GRAPH_BACKUP["$k"]}"; done
    printf "%s\n" "$ordered"
    return 0
  else
    # restore and return error
    for k in "${!GRAPH_BACKUP[@]}"; do GRAPH["$k"]="${GRAPH_BACKUP["$k"]}"; done
    return 1
  fi
}

# reverse deps for pkg
_reverse_deps_for_pkg() {
  local pkg="$1"
  # BFS on REVERSE graph
  local -A seen
  local -a queue result
  queue=("$pkg")
  while [ "${#queue[@]}" -gt 0 ]; do
    local cur="${queue[0]}"; queue=("${queue[@]:1}")
    for p in ${REVERSE["$cur"]}; do
      if [ -z "${seen["$p"]+x}" ]; then seen["$p"]=1; result+=("$p"); queue+=("$p"); fi
    done
  done
  printf "%s\n" "${result[@]:-}"
  return 0
}

# cache functions
_save_cache() {
  local tmp="${CACHE_FILE}.tmp.$$"
  {
    echo "# depends cache - autogenerated"
    for pkg in "${!HASHES[@]}"; do
      printf "%s\t%s\n" "$pkg" "${HASHES["$pkg"]}"
    done
    # store graph lines
    echo "##GRAPH##"
    for pkg in "${!GRAPH[@]}"; do
      printf "%s:%s\n" "$pkg" "${GRAPH["$pkg"]}"
    done
  } > "$tmp" || return 1
  mv -f "$tmp" "$CACHE_FILE"
  return 0
}

_load_cache() {
  [ -f "$CACHE_FILE" ] || return 1
  local mode=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    if [ "$line" = "##GRAPH##" ]; then mode=1; continue; fi
    if [ "$mode" -eq 0 ]; then
      # hash lines
      local pkg h
      pkg=$(printf "%s" "$line" | awk -F'\t' '{print $1}')
      h=$(printf "%s" "$line" | awk -F'\t' '{print $2}')
      HASHES["$pkg"]="$h"
    else
      local pkg rest
      pkg=$(printf "%s" "$line" | awk -F: '{print $1}')
      rest=$(printf "%s" "$line" | awk -F: '{print $2}')
      GRAPH["$pkg"]="$rest"
    fi
  done < "$CACHE_FILE"
  CACHE_LOADED=1
  return 0
}

# check whether cache is valid by recomputing file hashes and comparing
_cache_valid() {
  if [ "$CACHE_LOADED" -ne 1 ]; then return 1; fi
  local pkg
  for pkg in "${!HASHES[@]}"; do
    local recorded="${HASHES["$pkg"]}"
    # recompute current
    local cur
    cur=$(_file_hash "${PKGS_DIR}/${pkg}/depends" || true)
    if [ "$cur" != "$recorded" ]; then
      log_debug "Cache invalid for $pkg (hash changed)"
      return 1
    fi
  done
  return 0
}

# perform full build of graph (load cache if possible)
_build_or_load_graph() {
  if _load_cache >/dev/null 2>&1; then
    if _cache_valid; then
      log_info "Loaded valid depends cache"
      # rebuild REVERSE
      REVERSE=()
      for k in "${!GRAPH[@]}"; do
        for d in ${GRAPH["$k"]}; do REVERSE["$d"]="${REVERSE["$d"]} $k"; done
      done
      return 0
    else
      log_info "Depends cache stale; rebuilding"
    fi
  fi
  _build_graph
  _save_cache || log_warn "Failed to write depends cache"
  return 0
}

# check db integrity
_check_integrity() {
  log_section "check_integrity"
  local ok=0
  if [ ! -f "$PACKAGES_DB" ]; then log_warn "Packages DB missing: $PACKAGES_DB"; ok=1; fi
  if [ ! -f "$DEPENDS_DB" ]; then log_warn "Depends DB missing: $DEPENDS_DB"; ok=1; fi
  _build_or_load_graph || return 1
  if _detect_cycles; then log_error "Cycles detected"; return 1; fi
  log_ok "Integrity check passed (no cycles found)"
  return 0
}

# determine rebuild-needed: if any dependency's hash changed since last build (uses PACKAGES_DB timestamps/hashes)
_rebuild_needed() {
  local pkg="$1"
  # simplistic heuristic: if any dependency's depends file hash differs from cached HASHES (or manifest changed), mark rebuild
  _build_or_load_graph
  local deps
  if ! deps=$(_resolve_for_pkg "$pkg" 2>/dev/null); then
    log_warn "Cannot fully resolve dependencies for $pkg"
    return 2
  fi
  local d
  for d in $deps; do
    # compare current hash vs cache
    local cur=$(_file_hash "${PKGS_DIR}/${d}/depends" || true)
    local recorded="${HASHES["$d"]-}"
    if [ -z "$recorded" ] || [ "$cur" != "$recorded" ]; then
      log_info "Rebuild needed: dependency changed: $d"
      printf "%s\n" "$d"
      return 0
    fi
  done
  log_info "No rebuild needed for $pkg"
  return 1
}

# watch mode - monitor pkgs dir for changes to depends files and trigger action
_watch_loop() {
  local dir="${1:-$PKGS_DIR}"
  local action="${2:-}"
  if [ -n "$INOTIFY_CMD" ]; then
    log_info "Using inotifywait for watch on $dir"
    while true; do
      # monitor modify/create/delete events on depends files
      $INOTIFY_CMD -e modify,create,delete -r --format '%w%f %e' "$dir" | while read -r path ev; do
        case "$path" in
          *.depends|*/depends)
            log_info "Change detected: $path ($ev)"
            $action || log_warn "Action returned non-zero"
            ;;
        esac
      done
      sleep 1
    done
  else
    log_warn "inotifywait not available; falling back to polling every ${WATCH_POLL_INTERVAL}s"
    local -A last_mod
    while true; do
      local file
      for file in $(find "$dir" -name depends -o -name '*.depends' 2>/dev/null); do
        local m; m=$(stat -c %Y "$file" 2>/dev/null || echo 0)
        if [ "${last_mod["$file"]-0}" -ne "$m" ]; then
          last_mod["$file"]=$m
          log_info "Change detected via polling: $file"
          $action || log_warn "Action returned non-zero"
        fi
      done
      sleep "$WATCH_POLL_INTERVAL"
    done
  fi
}

# integration helper: call uninstall.sh for orphan package removal if enabled
_remove_orphan_with_uninstall() {
  local orphan="$1"
  if [ -x "./uninstall.sh" ]; then
    log_info "Removing orphan package $orphan via uninstall.sh --force --keep-logs"
    ./uninstall.sh "$orphan" --force --keep-logs || log_warn "uninstall.sh failed for $orphan"
  else
    log_warn "uninstall.sh not found or not executable; cannot auto-remove $orphan"
  fi
}

# CLI dispatch
_print_help() {
  cat <<EOF
depends.sh - dependency utilities

Commands:
  resolve <pkg>            - print ordered list of packages to build (deps first)
  check                    - run integrity checks (cycles, missing)
  graph [--dot FILE]       - print graph or write Graphviz dot to FILE
  reverse <pkg>            - list packages that (transitively) depend on <pkg>
  rebuild-needed <pkg>     - print which dependency changed and requires rebuild
  watch [--dir DIR] --cmd "<command>" - watch pkgs dir and run command on changes
  --help                   - show this help
EOF
}

# main dispatch functions
cmd_resolve() {
  local pkg="$1"
  _build_or_load_graph
  if ! _resolve_for_pkg "$pkg"; then
    log_error "Failed to resolve dependencies for $pkg"
    return 1
  fi
  return 0
}

cmd_check() {
  _check_integrity || return 1
  # check for missing dependencies referenced in GRAPH
  local missing=0
  for u in "${!GRAPH[@]}"; do
    for v in ${GRAPH["$u"]}; do
      if [ -z "${GRAPH["$v"]+x}" ]; then
        log_warn "Unresolved dependency: $v (referenced by $u)"
        missing=1
      fi
    done
  done
  if [ "$missing" -eq 1 ]; then
    log_warn "Some dependencies unresolved. Use --ignore-missing to proceed in other commands"
    return 2
  fi
  log_ok "Dependency check complete"
  return 0
}

cmd_graph() {
  local dotfile=""
  if [ "${1:-}" = "--dot" ]; then dotfile="$2"; fi
  _build_or_load_graph
  if [ -n "$dotfile" ]; then
    {
      echo "digraph depends {"
      for u in "${!GRAPH[@]}"; do
        for v in ${GRAPH["$u"]}; do
          printf '  "%s" -> "%s";\n' "$v" "$u"
        done
      done
      echo "}"
    } > "$dotfile"
    log_info "Wrote Graphviz DOT to $dotfile"
  else
    for u in "${!GRAPH[@]}"; do
      printf "%s: %s\n" "$u" "${GRAPH["$u"]}"
    done
  fi
}

cmd_reverse() {
  local pkg="$1"
  _build_or_load_graph
  _reverse_deps_for_pkg "$pkg"
}

cmd_rebuild_needed() {
  local pkg="$1"
  _rebuild_needed "$pkg"
}

cmd_watch() {
  local dir="$PKGS_DIR"
  local action_cmd=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --dir) dir="$2"; shift 2 ;;
      --cmd) action_cmd="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  if [ -z "$action_cmd" ]; then log_error "watch requires --cmd \"<command>\""; return 1; fi
  # wrap action into a callable function for safety
  _watch_loop "$dir" "$action_cmd"
}

# parse top-level args
if [ $# -lt 1 ]; then _print_help; exit 1; fi
cmd="$1"; shift || true

case "$cmd" in
  resolve) [ $# -ge 1 ] || { log_error "resolve requires <pkg>"; exit 1; } ; cmd_resolve "$1" ;;
  check) cmd_check ;;
  graph) cmd_graph "$@" ;;
  reverse) [ $# -ge 1 ] || { log_error "reverse requires <pkg>"; exit 1; } ; cmd_reverse "$1" ;;
  rebuild-needed) [ $# -ge 1 ] || { log_error "rebuild-needed requires <pkg>"; exit 1; } ; cmd_rebuild_needed "$1" ;;
  watch) cmd_watch "$@" ;;
  --help|-h) _print_help ;;
  *) log_error "Unknown command: $cmd"; _print_help; exit 1 ;;
esac
