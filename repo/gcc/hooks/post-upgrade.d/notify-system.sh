#!/usr/bin/env bash
set -e
echo '[HOOK post-upgrade] Notifying system services...'
systemctl reload build-daemon || true
