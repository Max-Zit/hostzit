#!/bin/sh
# Runs inside the newly installed system (preseed late_command). Services
# cannot run here, so the HostZit setup itself (install.sh) happens at the
# first start (hostzit-firstboot).
set -e
cd /root/hostzit-install
mkdir -p /var/lib/hostzit
touch /var/lib/hostzit/.appliance
for f in hostzit-firstboot hostzit-appliance-boot hostzit-setup; do
    install -m 0755 "$f" "/usr/local/sbin/$f"
done
install -m 0644 hostzit-firstboot.service hostzit-appliance-boot.service /etc/systemd/system/
systemctl enable hostzit-firstboot.service hostzit-appliance-boot.service
# The setup menu on the server's own screen for hzadmin.
install -m 0644 hostzit-menu.sh /etc/profile.d/hostzit-menu.sh
install -m 0440 sudoers-hostzit-setup /etc/sudoers.d/hostzit-setup
# WP-CLI from the ISO (no download needed at the first start).
[ -f wp-cli.phar ] && install -m 0755 wp-cli.phar /usr/local/bin/wp
# SSH: no root sign-in, strong ciphers only. Hosting accounts keep using
# SSH/SFTP (HostZit's own drop-in adds their chroot).
install -m 0644 sshd-hostzit-appliance.conf /etc/ssh/sshd_config.d/10-hostzit-appliance.conf
# Automatic security updates of Debian.
printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > /etc/apt/apt.conf.d/20auto-upgrades
# Where to get the source code of the GPL software, and the exact Debian
# packages of this installation.
mkdir -p /usr/share/doc/hostzit-appliance
install -m 0644 SOURCE-CODE.txt /usr/share/doc/hostzit-appliance/SOURCE-CODE.txt
dpkg-query -W -f '${Package} ${Version}\n' > /usr/share/doc/hostzit-appliance/debian-packages.txt
# The administrator chooses its own password at the first sign-in.
chage -d 0 hzadmin
usermod -aG sudo hzadmin
# systemd-networkd with DHCP on whatever adapter the machine has (the same
# on a server and in every copy of a VM image). Settings → System changes it.
mkdir -p /etc/systemd/network
printf '# Written by HostZit (Settings -> System).\n[Match]\nName=en* eth*\n\n[Network]\nDHCP=ipv4\n' > /etc/systemd/network/50-hostzit.network
printf 'auto lo\niface lo inet loopback\n' > /etc/network/interfaces
systemctl enable systemd-networkd systemd-networkd-wait-online systemd-resolved
# PowerDNS answers on port 53: no stub resolver there, the server itself
# uses the DNS servers from DHCP or the static settings.
mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNSStubListener=no\nLLMNR=no\nMulticastDNS=no\n' > /etc/systemd/resolved.conf.d/hostzit.conf
ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
# The PHP of Debian runs as one master per account, started by HostZit.
for u in $(systemctl list-unit-files 'php*-fpm.service' --no-legend | awk '{print $1}'); do systemctl disable "$u" >/dev/null 2>&1 || true; done
if [ -f IMAGE ]; then
    # A VM image is copied many times: no host identity baked in (SSH keys
    # and the machine ID are created at the first start).
    rm -f /etc/ssh/ssh_host_*
    truncate -s 0 /etc/machine-id
    rm -f /var/lib/dbus/machine-id
    apt-get clean
fi
