#!/bin/bash
# Builds a release into dist/: the panel and the helper for Linux amd64 and
# arm64, Debian packages, third-party licenses and, with the release key,
# the signed manifest of dist/release-V (the files that go on GitHub).
#   bash tools/release/build.sh 0.8.0 [release-notes.md]
set -euo pipefail
V=${1:?version}
NOTES=${2:-}
KEY=${HOSTZIT_RELEASE_KEY:-/c/Users/Mili/Ai/release-keys/hostzit-release.key}
cd "$(dirname "$0")/../.."
export GOTMPDIR=$(cygpath -m "$PWD/.gotmp" 2>/dev/null || echo "$PWD/.gotmp") CGO_ENABLED=0
mkdir -p dist
for arch in amd64 arm64; do
  for p in hostzit-server hostzit-helper; do
    GOOS=linux GOARCH=$arch go build -trimpath -ldflags "-s -w -X main.version=$V" -o "dist/$p-$V-linux-$arch" ./cmd/$p
  done
done
# Licenses of everything linked into the programs (fails on an unknown license).
go run ./tools/licenses -out THIRD_PARTY_LICENSES.md "dist/hostzit-server-$V-linux-amd64" "dist/hostzit-helper-$V-linux-amd64"
cp THIRD_PARTY_LICENSES.md "dist/THIRD_PARTY_LICENSES-$V.md"
NFPM="go run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.43.0"
for arch in amd64 arm64; do
  rm -rf bin/pkg && mkdir -p bin/pkg
  cp "dist/hostzit-server-$V-linux-$arch" bin/pkg/hostzit-server
  cp "dist/hostzit-helper-$V-linux-$arch" bin/pkg/hostzit-helper
  rm -f "dist/hostzit_${V}_$arch.deb"
  VERSION=$V ARCH=$arch $NFPM package --config packaging/linux/nfpm.yaml --packager deb --target dist/ >/dev/null
done
R="dist/release-$V"
rm -rf "$R" && mkdir -p "$R"
cp "dist/hostzit_${V}_amd64.deb" "dist/hostzit_${V}_arm64.deb" "dist/THIRD_PARTY_LICENSES-$V.md" packaging/install.sh "$R/"
(cd "$R" && sha256sum $(ls | grep -v '^SHA256SUMS') > SHA256SUMS)
if [ -f "$KEY" ]; then
  go run ./tools/relsign sign -key "$KEY" -version "$V" -dir "$R" ${NOTES:+-notes "$NOTES"}
else
  echo "note: no release key at $KEY; the release is not signed"
fi
echo "built $V"
