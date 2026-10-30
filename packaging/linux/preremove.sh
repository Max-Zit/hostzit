#!/bin/sh
# HostZit package: stop the panel on removal (websites keep running).
set -e
if [ "$1" = remove ] || [ "$1" = 0 ]; then
	systemctl disable --now hostzit-server >/dev/null 2>&1 || true
	systemctl disable --now hostzit-helper >/dev/null 2>&1 || true
fi
