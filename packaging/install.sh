#!/bin/bash
# HostZit installer for Debian 12/13.
#
#   install.sh [--mode shared|dedicated] [--local DIR] [--no-dns] [--php "8.3 8.4"]
#
# Installs the server software HostZit drives (nginx, PHP-FPM, MariaDB,
# PowerDNS, PostgreSQL, OpenSSH, quota tools, WP-CLI), creates the hostzit
# user and database, configures PowerDNS with its API on loopback only, and
# installs hostzit-server + hostzit-helper (from a release, or from DIR with
# freshly built binaries). Run it as root on a fresh server.
set -euo pipefail

MODE=shared LOCAL="" DNS=1 PHPS=""
while [ $# -gt 0 ]; do
	case "$1" in
	--mode) MODE=$2; shift 2 ;;
	--local) LOCAL=$2; shift 2 ;;
	--no-dns) DNS=0; shift ;;
	--php) PHPS=$2; shift 2 ;;
	*) echo "unknown option $1" >&2; exit 2 ;;
	esac
done
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
. /etc/os-release
case "$VERSION_ID" in 12|13) ;; *) echo "Debian 12 or 13 is required (found $PRETTY_NAME)" >&2; exit 1 ;; esac
export DEBIAN_FRONTEND=noninteractive
say() { printf '\n==> %s\n' "$*"; }

say "Installing server software"
apt-get update -q
pkgs="nginx libnginx-mod-http-modsecurity modsecurity-crs mariadb-server postgresql openssh-server quota curl ca-certificates unzip nftables fail2ban"
[ "$DNS" = 1 ] && pkgs="$pkgs pdns-server pdns-backend-sqlite3 sqlite3"
if [ -z "$PHPS" ]; then
	PHPS=$(apt-cache search --names-only '^php[0-9.]+-fpm$' | sed -E 's/^php([0-9.]+)-fpm.*/\1/' | sort -V | tail -1)
fi
for v in $PHPS; do
	for e in fpm cli mysql xml mbstring curl gd zip intl opcache imagick bcmath; do pkgs="$pkgs php$v-$e"; done
done
apt-get -y -q install $pkgs
for v in $PHPS; do systemctl disable --now "php$v-fpm" >/dev/null 2>&1 || true; done

say "HostZit user and database"
id hostzit >/dev/null 2>&1 || useradd --system --home-dir /var/lib/hostzit/panel --shell /usr/sbin/nologin hostzit
install -d -m 0711 /var/lib/hostzit
install -d -m 0700 -o hostzit -g hostzit /var/lib/hostzit/panel
install -d -m 0750 -o root -g hostzit /etc/hostzit
if [ ! -f /etc/hostzit/server.env ]; then
	pw=$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 30)
	runuser -u postgres -- psql -q -c "CREATE ROLE hostzit LOGIN PASSWORD '$pw'" 2>/dev/null || runuser -u postgres -- psql -q -c "ALTER ROLE hostzit PASSWORD '$pw'"
	runuser -u postgres -- psql -q -tc "SELECT 1 FROM pg_database WHERE datname='hostzit'" | grep -q 1 || runuser -u postgres -- createdb -O hostzit hostzit
	umask 027
	printf 'HOSTZIT_DB=postgres://hostzit:%s@127.0.0.1/hostzit?sslmode=disable\n' "$pw" > /etc/hostzit/server.env
	chgrp hostzit /etc/hostzit/server.env
	umask 022
fi

if [ "$DNS" = 1 ]; then
	say "PowerDNS (authoritative, API on loopback)"
	db=/var/lib/powerdns/pdns.sqlite3
	if [ ! -f "$db" ]; then
		install -d -o pdns -g pdns /var/lib/powerdns
		sqlite3 "$db" < /usr/share/pdns-backend-sqlite3/schema/schema.sqlite3.sql
		chown pdns:pdns "$db"; chmod 640 "$db"
	fi
	[ -f /etc/hostzit/pdns-api.key ] || { head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' > /etc/hostzit/pdns-api.key; chmod 600 /etc/hostzit/pdns-api.key; }
	rm -f /etc/powerdns/pdns.d/bind.conf
	cat > /etc/powerdns/pdns.d/hostzit.conf <<EOF
# HostZit (generated)
launch=gsqlite3
gsqlite3-database=$db
gsqlite3-dnssec=yes
api=yes
api-key=$(cat /etc/hostzit/pdns-api.key)
webserver=yes
webserver-address=127.0.0.1
webserver-port=8081
webserver-allow-from=127.0.0.1,::1
local-address=0.0.0.0, ::
EOF
	chmod 640 /etc/powerdns/pdns.d/hostzit.conf; chgrp pdns /etc/powerdns/pdns.d/hostzit.conf
	# systemd-resolved's stub listener holds 127.0.0.53:53; the server's own
	# lookups keep working through /run/systemd/resolve/resolv.conf.
	if systemctl is-active -q systemd-resolved; then
		install -d /etc/systemd/resolved.conf.d
		printf '[Resolve]\nDNSStubListener=no\n' > /etc/systemd/resolved.conf.d/hostzit.conf
		ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
		systemctl restart systemd-resolved
	fi
	systemctl enable pdns >/dev/null 2>&1
	systemctl restart pdns
fi

say "Disk quotas"
if (quotaon -p -u / 2>&1 || true) | grep -q " is on"; then
	echo "user quotas are active on /"
else
	fstype=$(findmnt -no FSTYPE /)
	if [ "$fstype" = ext4 ] && ! grep -Eq '^\S+\s+/\s+\S+\s+\S*usrjquota' /etc/fstab; then
		sed -i -E 's#^(\S+\s+/\s+ext4\s+)(\S+)#\1\2,usrjquota=aquota.user,jqfmt=vfsv1#' /etc/fstab
		mount -o remount / && quotacheck -cum / && quotaon -u / || echo "WARNING: quotas could not be switched on; disk limits are not enforced"
	else
		echo "WARNING: switch on user quotas for the file system of /home ($fstype) to enforce disk limits"
	fi
fi

say "WP-CLI"
if [ ! -x /usr/local/bin/wp ]; then
	curl -fsSL -o /usr/local/bin/wp https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && chmod 755 /usr/local/bin/wp || echo "WARNING: WP-CLI could not be downloaded"
fi

say "HostZit programs"
install -d /usr/lib/hostzit
if [ -n "$LOCAL" ]; then
	install -m 0755 "$LOCAL/hostzit-server" /usr/bin/hostzit-server
	install -m 0755 "$LOCAL/hostzit-helper" /usr/lib/hostzit/hostzit-helper
	install -m 0644 "$LOCAL/hostzit-server.service" "$LOCAL/hostzit-helper.service" "$LOCAL/hostzit-firewall.service" /etc/systemd/system/
else
	echo "release downloads come with 0.8; use --local DIR" >&2; exit 1
fi
systemctl daemon-reload
systemctl enable --now hostzit-helper
sleep 1
/usr/lib/hostzit/hostzit-helper setup >/dev/null
systemctl enable hostzit-server hostzit-firewall >/dev/null 2>&1
systemctl restart hostzit-server
sleep 3
say "Done"
tok=/var/lib/hostzit/panel/setup-token.txt
ip=$(hostname -I | awk '{print $1}')
echo "Admin panel:    https://$ip:8442/  (only from private networks at first)"
echo "Customer panel: https://$ip:8443/"
[ -f "$tok" ] && echo "Setup token:    $(cat $tok)"
echo "Mode: $MODE (set it in Settings → Hosting)"
