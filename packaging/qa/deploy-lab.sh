#!/bin/bash
# Builds HostZit for Linux and installs it on a lab server (default hz-test).
#   bash packaging/qa/deploy-lab.sh [IP]
set -e
IP=${1:-192.168.101.170}
cd "$(dirname "$0")/../.."
export GOTMPDIR=$(cygpath -m "$PWD/.gotmp" 2>/dev/null || echo "$PWD/.gotmp") GOOS=linux GOARCH=amd64
V=${HZ_VERSION:-"0.1.0-dev+$(git rev-parse --short HEAD)"}
mkdir -p .gotmp/lin
go build -ldflags "-X main.version=$V" -o .gotmp/lin/hostzit-server ./cmd/hostzit-server
go build -ldflags "-X main.version=$V" -o .gotmp/lin/hostzit-helper ./cmd/hostzit-helper
K=/c/Users/Mili/Ai/vm/keys/lab_ed25519
scp -q -i $K .gotmp/lin/hostzit-server .gotmp/lin/hostzit-helper packaging/linux/*.service packaging/qa/isolation.sh root@$IP:/root/hz/
ssh -i $K root@$IP 'install -m755 /root/hz/hostzit-helper /usr/lib/hostzit/ && install -m755 /root/hz/hostzit-server /usr/bin/ && install -m644 /root/hz/hostzit-*.service /usr/lib/systemd/system/ && rm -f /etc/systemd/system/hostzit-*.service && systemctl daemon-reload && systemctl restart hostzit-helper && sleep 1 && /usr/lib/hostzit/hostzit-helper setup >/dev/null && systemctl restart hostzit-server && sleep 2 && systemctl is-active hostzit-helper hostzit-server'
echo "deployed $V to $IP"
