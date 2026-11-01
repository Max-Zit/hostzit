#!/bin/sh
# Makes the HostZit appliance installer: the official Debian netinst ISO
# with an unattended installation (preseed.cfg) that installs Debian with
# everything HostZit drives and the given HostZit package (set up at the
# first start by hostzit-firstboot).
#
#   ./build-iso.sh hostzit_X_amd64.deb [debian-netinst.iso]
#
# OUT=file chooses the output, IMAGE=1 makes the variant build-images.sh
# installs into a VM (it powers off at the end instead of restarting).
# Needs xorriso, isolinux, cpio, gzip and wget (Debian / Proxmox host).
set -eu

pkg=$(readlink -f "${1:?usage: build-iso.sh hostzit_X_amd64.deb [debian-netinst.iso]}")
ver=$(basename "$pkg" | sed -n 's/^hostzit_\([0-9.]*\)_.*/\1/p')
[ -n "$ver" ] || { echo "not a HostZit package: $pkg" >&2; exit 1; }
src=$(cd "$(dirname "$0")" && pwd)
out=${OUT:-$PWD/hostzit-appliance-$ver.iso}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# fetch_netinst downloads the current Debian netinst ISO once (cached) and
# checks it against Debian's SHA256SUMS.
fetch_netinst() {
    cache=/var/cache/hostzit-appliance/debian-netinst.iso
    if [ ! -f "$cache" ]; then
        mkdir -p "$(dirname "$cache")"
        mirror=https://cdimage.debian.org/debian-cd/current/amd64/iso-cd
        wget -q -O "$tmp/sums" "$mirror/SHA256SUMS"
        name=$(awk '$2 ~ /netinst\.iso$/ && $2 !~ /edu|mac/ { print $2; exit }' "$tmp/sums")
        wget -q -O "$cache.part" "$mirror/$name"
        (cd "$(dirname "$cache")" && awk -v n="$name" -v f="$(basename "$cache").part" '$2 == n { print $1 "  " f }' "$tmp/sums" | sha256sum -c - >/dev/null)
        mv "$cache.part" "$cache"
    fi
    echo "$cache"
}

netinst=${2:-$(fetch_netinst)}
xorriso -osirrox on -indev "$netinst" -extract / "$tmp/cd" >/dev/null 2>&1
chmod -R u+w "$tmp/cd"

# Our files on the CD; the preseed copies them into the new system.
mkdir "$tmp/cd/hostzit"
cp "$pkg" "$src/../install.sh" "$src/appliance-install.sh" "$src/hostzit-firstboot" "$src/hostzit-firstboot.service" "$src/hostzit-appliance-boot" "$src/hostzit-appliance-boot.service" \
    "$src/hostzit-setup" "$src/hostzit-menu.sh" "$src/sudoers-hostzit-setup" "$src/sshd-hostzit-appliance.conf" "$src/SOURCE-CODE.txt" "$tmp/cd/hostzit/"
# WP-CLI, so the appliance needs no download at its first start.
wget -q -O "$tmp/cd/hostzit/wp-cli.phar" https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
cp "$src/SOURCE-CODE.txt" "$tmp/cd/"
cp "$src/preseed.cfg" "$tmp/preseed.cfg"
if [ "${IMAGE:-0}" = 1 ]; then
    touch "$tmp/cd/hostzit/IMAGE"
    sed -i 's#^d-i debian-installer/exit/poweroff boolean false#d-i debian-installer/exit/poweroff boolean true#' "$tmp/preseed.cfg"
fi

# The preseed goes into the installer's initrd, so no question is asked.
mkdir "$tmp/initrd"
(cd "$tmp/initrd" && gzip -dc "$tmp/cd/install.amd/initrd.gz" | cpio -id --quiet)
cp "$tmp/preseed.cfg" "$tmp/initrd/preseed.cfg"
(cd "$tmp/initrd" && find . | cpio -o -H newc --quiet | gzip -9) > "$tmp/cd/install.amd/initrd.gz"

# Boot menus for BIOS (isolinux) and UEFI (grub): the installation starts
# by itself after 5 seconds.
# (the BIOS menu cuts labels after about 46 characters)
title="HostZit $ver (erases the first disk)"
printf 'path\ninclude menu.cfg\ndefault vesamenu.c32\nprompt 0\ntimeout 50\n' > "$tmp/cd/isolinux/isolinux.cfg"
cat > "$tmp/cd/isolinux/menu.cfg" <<EOF
menu hshift 4
menu width 70
menu title HostZit appliance installer
include stdmenu.cfg
default hostzit
label hostzit
	menu label ^Install $title
	menu default
	kernel /install.amd/vmlinuz
	append auto=true priority=critical vga=788 initrd=/install.amd/initrd.gz --- quiet
EOF
cat > "$tmp/cd/boot/grub/grub.cfg" <<EOF
set timeout=5
set default=0
insmod all_video
menuentry "Install $title" {
	linux /install.amd/vmlinuz auto=true priority=critical --- quiet
	initrd /install.amd/initrd.gz
}
EOF

(cd "$tmp/cd" && find . -type f ! -name md5sum.txt ! -path './isolinux/*' -print0 | xargs -0 md5sum > md5sum.txt)
xorriso -as mkisofs -r -V "HostZit $ver" -o "$out" -J -joliet-long -cache-inodes \
    -isohybrid-mbr /usr/lib/ISOLINUX/isohdpfx.bin \
    -b isolinux/isolinux.bin -c isolinux/boot.cat -boot-load-size 4 -boot-info-table -no-emul-boot \
    -eltorito-alt-boot -e boot/grub/efi.img -no-emul-boot -isohybrid-gpt-basdat \
    "$tmp/cd" >/dev/null 2>&1
echo "built $out"
