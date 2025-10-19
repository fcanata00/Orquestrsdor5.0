#!/usr/bin/env bash
set -euo pipefail
log_section "Preparing GCC build environment"
mkdir -p "$BUILD_DIR" && cd "$BUILD_DIR"
"$SRC_DIR/configure"   --prefix=/usr   --enable-languages=c,c++   --disable-multilib   --enable-shared   --enable-threads=posix
make -j"$(nproc)"
make DESTDIR="$DESTDIR" install
log_section "Stripping binaries and cleaning"
strip --strip-unneeded "$DESTDIR/usr/bin/"* || true
