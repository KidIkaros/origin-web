#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Build the origin-web WASM module and stage it into www/pkg/ so the static
# site is self-contained and ready to serve (locally or via GitHub Pages).
#
# Usage:
#   ./build.sh            # release build (opt-level=s, lto, wasm-opt)
#   ./build.sh --dev      # debug build, no wasm-opt (fast iteration)
#
# The built .wasm is NOT committed — it's a build artifact. CI regenerates it
# on every push to main and deploys to Pages (see .github/workflows/deploy.yml).

set -euo pipefail
cd "$(dirname "$0")"

MODE="${1:---release}"
CRATE_DIR="crate"
WWW_DIR="www"

echo "▸ Building WASM module ($MODE)…"
if [ "$MODE" = "--dev" ]; then
  (cd "$CRATE_DIR" && wasm-pack build --target web --dev)
else
  (cd "$CRATE_DIR" && wasm-pack build --target web --release)
fi

echo "▸ Staging pkg/ → $WWW_DIR/pkg/…"
rm -rf "$WWW_DIR/pkg"
cp -R "$CRATE_DIR/pkg" "$WWW_DIR/pkg"

SIZE=$(du -h "$WWW_DIR/pkg/origin_web_bg.wasm" | cut -f1)
echo "▸ Done. origin_web_bg.wasm = $SIZE"
echo "▸ Serve locally:  (cd $WWW_DIR && python3 -m http.server 8080)"
