#!/bin/sh
# HostZit package: start or restart the services after an install or update.
set -e
id hostzit >/dev/null 2>&1 || useradd --system --home-dir /var/lib/hostzit/panel --shell /usr/sbin/nologin hostzit
install -d -m 0711 /var/lib/hostzit
install -d -m 0700 -o hostzit -g hostzit /var/lib/hostzit/panel
systemctl daemon-reload
systemctl enable hostzit-helper hostzit-firewall >/dev/null 2>&1 || true
# packages up to 0.9.4 (built on Windows) had group-writable files; logrotate
# refuses such a file, so the logs of the websites were never rotated. dpkg
# keeps an unchanged configuration file as it is, so its mode is fixed here.
if [ -f /etc/logrotate.d/hostzit ]; then chmod go-w /etc/logrotate.d/hostzit; fi
# servers set up before 0.9.2: also no LLMNR / multicast DNS (port 5355 was open)
r=/etc/systemd/resolved.conf.d/hostzit.conf
if [ -f "$r" ] && ! grep -q '^LLMNR=' "$r"; then
	printf 'LLMNR=no\nMulticastDNS=no\n' >> "$r"
	systemctl try-restart systemd-resolved >/dev/null 2>&1 || true
fi
if [ -f /var/lib/hostzit/.appliance ]; then
	# appliance: no SSH password sign-in for hzadmin until its first password is changed
	systemctl enable --now hostzit-ssh-guard.path >/dev/null 2>&1 || true
	/usr/lib/hostzit/appliance-ssh-guard || true
	# the appliance's SSH algorithms follow the package (kept only if sshd accepts them)
	n=/usr/lib/hostzit/sshd-hostzit-appliance.conf o=/etc/ssh/sshd_config.d/10-hostzit-appliance.conf
	if [ -f "$n" ] && ! cmp -s "$n" "$o"; then
		[ -f "$o" ] && cp -p "$o" "$o.old"
		install -m 0644 "$n" "$o"
		if sshd -t >/dev/null 2>&1; then
			systemctl reload ssh >/dev/null 2>&1 || true
			rm -f "$o.old"
		elif [ -f "$o.old" ]; then
			mv "$o.old" "$o"
		else
			rm -f "$o"
		fi
	fi
fi
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
