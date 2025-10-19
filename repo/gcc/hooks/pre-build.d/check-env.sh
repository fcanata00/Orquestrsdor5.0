#!/usr/bin/env bash
set -e
echo '[HOOK pre-build] Checking environment...'
[[ -n "$LFS" ]] || { echo 'LFS not set!'; exit 1; }
