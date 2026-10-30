#!/bin/sh
# HostZit package: start or restart the services after an install or update.
set -e
id hostzit >/dev/null 2>&1 || useradd --system --home-dir /var/lib/hostzit/panel --shell /usr/sbin/nologin hostzit
install -d -m 0711 /var/lib/hostzit
install -d -m 0700 -o hostzit -g hostzit /var/lib/hostzit/panel
systemctl daemon-reload
systemctl enable hostzit-helper hostzit-firewall >/dev/null 2>&1 || true
if [ -f /etc/hostzit/server.env ]; then
	# setup first (groups, folders), so the helper starts with the groups known
	/usr/lib/hostzit/hostzit-helper setup >/dev/null 2>&1 || true
	systemctl restart hostzit-helper
	sleep 1
	systemctl enable hostzit-server >/dev/null 2>&1 || true
	systemctl restart hostzit-server
else
	echo "HostZit: run /usr/share/hostzit/install.sh to set up the server software and the database."
fi
