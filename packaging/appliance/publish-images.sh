#!/bin/sh
# Uploads the appliance ISO and VM images of VERSION to the GitHub release
# vVERSION under fixed names, so the documentation can link to
#   https://github.com/Max-Zit/hostzit/releases/latest/download/<name>
#
#   ./publish-images.sh 0.3.0 /root/appliance/out
#
# Files: hostzit-appliance.iso, .ova, .qcow2, hostzit-appliance-vhdx.zip
# (GitHub limits release files to 2 GiB, the VHDX is larger) and SHA256SUMS-appliance (the release's own SHA256SUMS covers the programs).
# Afterwards prune-images.sh removes the images from releases older than the
# newest 8 (KEEP=n to change it).
# Needs the GitHub CLI (gh), logged in with rights to the repository.
set -eu
VERSION=${1:?usage: publish-images.sh <version> <directory with the build output>}
DIR=$(readlink -f "${2:?directory}")
SRC="hostzit-appliance-$VERSION"
# PREPARE=dir only prepares the files there (upload them elsewhere with
#   gh release upload vVERSION --repo Max-Zit/hostzit dir/*).
if [ -n "${PREPARE:-}" ]; then
    WORK=$PREPARE
    mkdir -p "$WORK"
else
    WORK=$(mktemp -d "$DIR/publish.XXXXXX")
    trap 'rm -rf "$WORK"' EXIT
fi
for ext in iso ova qcow2; do
    [ -f "$DIR/$SRC.$ext" ] || { echo "missing $DIR/$SRC.$ext" >&2; exit 1; }
    ln "$DIR/$SRC.$ext" "$WORK/hostzit-appliance.$ext" 2>/dev/null || cp "$DIR/$SRC.$ext" "$WORK/hostzit-appliance.$ext"
done
[ -f "$DIR/$SRC.vhdx" ] || { echo "missing $DIR/$SRC.vhdx" >&2; exit 1; }
ln "$DIR/$SRC.vhdx" "$WORK/hostzit-appliance.vhdx" 2>/dev/null || cp "$DIR/$SRC.vhdx" "$WORK/hostzit-appliance.vhdx"
(cd "$WORK" && zip -q -1 hostzit-appliance-vhdx.zip hostzit-appliance.vhdx && rm hostzit-appliance.vhdx)
(cd "$WORK" && sha256sum hostzit-appliance.iso hostzit-appliance.ova hostzit-appliance.qcow2 hostzit-appliance-vhdx.zip > SHA256SUMS-appliance)
for f in "$WORK"/*; do
    size=$(stat -c %s "$f")
    [ "$size" -lt 2147483648 ] || { echo "$f is larger than 2 GiB" >&2; exit 1; }
done
if [ -n "${PREPARE:-}" ]; then
    echo "prepared the images of $VERSION in $WORK"
    exit 0
fi
gh release upload "v$VERSION" --repo Max-Zit/hostzit --clobber "$WORK"/*
# The asset list shows a label: the VHDX is for generation 1 VMs.
id=$(gh api "repos/Max-Zit/hostzit/releases/tags/v$VERSION" --jq '.assets[] | select(.name == "hostzit-appliance-vhdx.zip") | .id')
[ -n "$id" ] && gh api -X PATCH "repos/Max-Zit/hostzit/releases/assets/$id" -f name=hostzit-appliance-vhdx.zip \
    -f "label=hostzit-appliance-vhdx.zip (Hyper-V, generation 1)" >/dev/null
echo "uploaded the images of $VERSION"
# Keep the images only in the newest releases (KEEP, default 8): about 5 GB
# per release would otherwise pile up on GitHub.
sh "$(dirname "$0")/prune-images.sh"
