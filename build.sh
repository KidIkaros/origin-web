#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Build the origin-web WASM module and stage a fully self-contained static
# site in www/. Everything the page needs is local: wasm, JS glue, fonts,
# and a build-info.json the page uses to prove its own provenance.
set -euo pipefail
cd "$(dirname "$0")"

echo "▸ Building WASM module (--release)…"
(cd crate && wasm-pack build --target web --release --out-dir pkg)

echo "▸ Staging pkg/ → www/pkg/…"
mkdir -p www/pkg
cp crate/pkg/origin_web.js www/pkg/
cp crate/pkg/origin_web_bg.wasm www/pkg/

echo "▸ Writing build-info.json (provenance manifest)…"
WASM_SHA256=$(sha256sum www/pkg/origin_web_bg.wasm | awk '{print $1}')
WASM_BYTES=$(stat -c%s www/pkg/origin_web_bg.wasm)
GIT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
GIT_COMMIT_SHORT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_DIRTY=$(git status --porcelain 2>/dev/null | grep -q . && echo true || echo false)
SDK_VERSION=$(grep -A1 'name = "origin-crypto-sdk"' crate/Cargo.lock 2>/dev/null | grep version | head -1 | sed 's/.*"\(.*\)"/\1/' || echo "unknown")
# In CI: set by GitHub Actions. Locally: empty.
CI_RUN="${GITHUB_RUN_ID:-}"
CI_RUN_URL=""
if [ -n "$CI_RUN" ]; then
  CI_RUN_URL="https://github.com/${GITHUB_REPOSITORY:-KidIkaros/origin-web}/actions/runs/${CI_RUN}"
fi
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

cat > www/build-info.json <<EOF
{
  "built_at": "${BUILD_TIME}",
  "git_commit": "${GIT_COMMIT}",
  "git_commit_short": "${GIT_COMMIT_SHORT}",
  "git_dirty": ${GIT_DIRTY},
  "ci_run_id": "${CI_RUN}",
  "ci_run_url": "${CI_RUN_URL}",
  "wasm_sha256": "${WASM_SHA256}",
  "wasm_bytes": ${WASM_BYTES},
  "sdk_version": "${SDK_VERSION}",
  "sdk_source": "crates.io"
}
EOF

echo "▸ Done. origin_web_bg.wasm = ${WASM_BYTES} bytes"
echo "  sha256: ${WASM_SHA256}"
echo "▸ Serve locally:  (cd www && python3 -m http.server 8080)"
