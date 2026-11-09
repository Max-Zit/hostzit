#!/bin/bash
# Upgrade test (CI): the newest release installed with its own install.sh
# on Debian 13 (systemd in a privileged container), then the package of
# this commit installed the way Settings → Updates does it, then the
# services, the panel and the database are checked.
#   bash tools/ci/upgrade-test.sh <new deb>
set -euo pipefail
DEB=$(readlink -f "${1:?new deb}")
NAME=hz-upgrade
step() { echo "::group::$*"; }
end() { echo "::endgroup::"; }
cx() { docker exec "$NAME" bash -c "$*"; }
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

step "Debian 13 with systemd"
cat > /tmp/Dockerfile.hz <<'EOF'
FROM debian:trixie
ENV container=docker
RUN apt-get update -q && apt-get install -y -q systemd systemd-sysv dbus curl ca-certificates iproute2 procps && apt-get clean && rm -f /usr/sbin/policy-rc.d
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF
docker build -q -t hz-trixie -f /tmp/Dockerfile.hz /tmp >/dev/null
docker run -d --name "$NAME" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock -h hz-upgrade hz-trixie >/dev/null
for i in $(seq 60); do
	st=$(cx "systemctl is-system-running 2>/dev/null" || true)
	case "$st" in running|degraded) break ;; esac
	sleep 2
done
echo "systemd: $st"
end

step "Install the newest release (install.sh from GitHub)"
cx "curl -fsSL https://github.com/Max-Zit/hostzit/releases/latest/download/install.sh -o /root/install.sh && bash /root/install.sh" > /tmp/install.log 2>&1 || { tail -60 /tmp/install.log; exit 1; }
tail -15 /tmp/install.log
OLD=$(cx "dpkg-query -W -f='\${Version}' hostzit")
echo "installed: $OLD"
cx "systemctl is-active hostzit-server hostzit-helper"
end

step "Update to this commit (as Settings → Updates does)"
docker cp "$DEB" "$NAME:/var/tmp/hostzit-new.deb"
cx "DEBIAN_FRONTEND=noninteractive apt-get -y -q --allow-downgrades -o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install /var/tmp/hostzit-new.deb" | tail -5
NEW=$(cx "dpkg-query -W -f='\${Version} \${Status}' hostzit")
echo "now: $NEW"
case "$NEW" in *"install ok installed") ;; *) echo "the package is not set up completely"; exit 1 ;; esac
end

step "Services, panels and database after the update"
ok=1
for i in $(seq 30); do
	if cx "systemctl is-active -q hostzit-server hostzit-helper && curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8442/setup | grep -qE '^(200|303)$'"; then ok=0; break; fi
	sleep 2
done
cx "systemctl --no-pager --lines=20 status hostzit-server hostzit-helper" || true
[ $ok = 0 ] || { echo "the panel does not answer after the update"; cx "journalctl -u hostzit-server -u hostzit-helper --no-pager -n 80" || true; exit 1; }
echo "admin panel: $(cx "curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8442/setup")"
echo "customer panel: $(cx "curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/login")"
# the database migrations of the new version ran (no error in the log)
if cx "journalctl -u hostzit-server --no-pager | grep -iE 'migration.*(fail|error)'"; then echo "a migration failed"; exit 1; fi
cx "nginx -t" 2>&1 | tail -2
for u in nginx postgresql mariadb pdns; do printf '%s %s\n' "$u" "$(cx "systemctl is-active $u" || true)"; done
end
echo "upgrade $OLD → ${NEW%% *}: ok"
