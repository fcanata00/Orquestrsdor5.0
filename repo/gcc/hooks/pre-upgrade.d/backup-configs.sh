#!/usr/bin/env bash
set -e
echo '[HOOK pre-upgrade] Backing up old configurations...'
tar -cf "/var/backups/gcc-configs-$(date +%F).tar" /etc/gcc || true
