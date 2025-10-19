#!/usr/bin/env bash
set -e
echo '[HOOK post-build] Verifying binaries...'
find "$DESTDIR/usr/bin" -type f -exec file {} \;
