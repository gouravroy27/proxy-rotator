#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUT="${ROOT}/dist"

mkdir -p "${OUT}"
cd "${ROOT}"

# Local binary
echo "Building local proxy_rotator..."
go build -trimpath -ldflags="-s -w" -o proxy_rotator main.go

# Cross-compilation targets
export CGO_ENABLED=0
for os in linux windows darwin; do
  for arch in amd64 arm64; do
    ext=""
    [[ "$os" == "windows" ]] && ext=".exe"
    echo "Compiling ${os}/${arch}..."
    GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags="-s -w" -o "${OUT}/proxy-rotator-${os}-${arch}${ext}" main.go
  done
done

echo "Done. Binaries built in dist/"
