package hosting

import (
	"fmt"
	"strings"
)

// Redis of an account: one redis-server in the account's cage and slice,
// reachable only through the Unix socket /.sock/redis.sock (no TCP port),
// without persistence, as an object cache (WordPress "Redis Object Cache").

// RedisSocket is the socket inside the cage.
const RedisSocket = "/.sock/redis.sock"

// RedisConfPath is the configuration inside the cage.
const RedisConfPath = "/.hz/redis.conf"

// RedisUnitName names the systemd unit.
func RedisUnitName(account string) string { return "hz-redis-" + account + ".service" }

// RedisSocketHost is the socket's path on the host.
func RedisSocketHost(account string) string { return CageDir(account) + RedisSocket }

// RedisConf renders redis.conf.
func RedisConf(a Account) string {
	mb := a.Limits.RedisMB
	return fmt.Sprintf(`# HostZit Redis of account %s (generated, do not edit)
port 0
unixsocket %s
unixsocketperm 770
daemonize no
supervised systemd
dir /tmp
save ""
appendonly no
maxmemory %dmb
maxmemory-policy allkeys-lru
databases 16
loglevel warning
logfile ""
rename-command CONFIG ""
rename-command DEBUG ""
rename-command MODULE ""
rename-command SLAVEOF ""
rename-command REPLICAOF ""
rename-command SAVE ""
rename-command BGSAVE ""
rename-command BGREWRITEAOF ""
`, a.Name, RedisSocket, mb)
}

// RedisUnit renders the systemd unit.
func RedisUnit(a Account) (string, error) {
	if err := a.Validate(); err != nil {
		return "", err
	}
	return cagedService(a, "Redis of hosting account "+a.Name, "notify", "/usr/bin/redis-server "+RedisConfPath, ""), nil
}

// cagedService renders a service that runs as the account in its cage and
// slice with the sandboxing of the PHP masters.
func cagedService(a Account, desc, typ, exec, extra string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `# HostZit (generated, do not edit)
[Unit]
Description=%[2]s
After=network.target %[3]s
Requires=%[3]s
PartOf=%[3]s

[Service]
Type=%[6]s
User=%[1]s
Group=%[1]s
Slice=%[4]s
RootDirectory=%[5]s
MountAPIVFS=yes
BindPaths=-/run/mysqld
ProtectProc=invisible
ProcSubset=pid
PrivateDevices=yes
NoNewPrivileges=yes
RestrictSUIDSGID=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictNamespaces=yes
SystemCallArchitectures=native
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
UMask=0007
ExecStart=%[7]s
Restart=on-failure
RestartSec=5s
%[8]s
[Install]
WantedBy=multi-user.target
`, a.Name, desc, CageUnitName(a.Name), SliceName(a.Name), CageDir(a.Name), typ, exec, extra)
	return b.String()
}
