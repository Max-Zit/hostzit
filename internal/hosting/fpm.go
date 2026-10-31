package hosting

import (
	"errors"
	"fmt"
	"strings"
)

// PHP-FPM runs one master per account and PHP version, as the account
// user, inside the account's cage and cgroup (systemd unit FPMUnit). The
// master needs no root, so a hole in PHP gives an attacker only the
// account itself.

// FPMUnitName is the systemd unit of an account's PHP version.
func FPMUnitName(account, version string) string {
	return "hz-php-" + account + "-" + strings.ReplaceAll(version, ".", "") + ".service"
}

// SliceName is the cgroup of everything an account runs.
func SliceName(account string) string { return "hz-" + account + ".slice" }

// CageUnitName prepares the cage mounts before anything of the account runs.
func CageUnitName(account string) string { return "hz-cage-" + account + ".service" }

// FPMConfPath is the pool file inside the cage (root-owned, read-only for
// the account).
func FPMConfPath(version string) string {
	return "/.hz/php-fpm-" + strings.ReplaceAll(version, ".", "") + ".conf"
}

// disabledFunctions are switched off unless the package allows running
// programs.
const disabledFunctions = "exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,dl"

// FPMConf renders the PHP-FPM configuration of an account for a version.
func FPMConf(a Account, version string) (string, error) {
	if err := a.Validate(); err != nil {
		return "", err
	}
	if !ValidPHPVersion(version) {
		return "", errors.New("invalid PHP version")
	}
	l := a.Limits
	home := HomeDir(a.Name)
	var b strings.Builder
	w := func(format string, x ...any) { fmt.Fprintf(&b, format, x...) }
	w("; HostZit PHP %s of account %s (generated, do not edit)\n[global]\nerror_log = %s/logs/php%s-fpm.log\ndaemonize = no\nprocess_control_timeout = 10s\n\n", version, a.Name, home, strings.ReplaceAll(version, ".", ""))
	w("[%s]\n", a.Name)
	w("listen = /.sock/php%s.sock\nlisten.mode = 0666\n", strings.ReplaceAll(version, ".", ""))
	w("pm = ondemand\npm.max_children = %d\npm.process_idle_timeout = 30s\npm.max_requests = 1000\n", l.PHPWorkers)
	w("request_terminate_timeout = 300s\ncatch_workers_output = yes\ndecorate_workers_output = no\nclear_env = yes\n")
	w("env[TMPDIR] = /tmp\nenv[HOME] = %s\nenv[PATH] = /usr/local/bin:/usr/bin:/bin\n", home)
	w("php_admin_value[open_basedir] = %s/:/tmp/:/usr/share/php/:/dev/urandom\n", home)
	w("php_admin_value[upload_tmp_dir] = /tmp\nphp_admin_value[session.save_path] = /tmp\nphp_admin_value[sys_temp_dir] = /tmp\n")
	w("php_admin_value[memory_limit] = %dM\n", l.PHPMemoryMB)
	w("php_admin_value[upload_max_filesize] = %dM\nphp_admin_value[post_max_size] = %dM\n", l.UploadMB, l.UploadMB)
	w("php_admin_value[max_execution_time] = 300\nphp_admin_flag[allow_url_include] = off\nphp_admin_flag[expose_php] = off\nphp_admin_flag[log_errors] = on\n")
	w("php_admin_value[error_log] = %s/logs/php-error.log\n", home)
	sm := "/usr/lib/hostzit/hostzit-helper sendmail"
	if a.Sendmail == "/usr/sbin/emailzit-sendmail" {
		sm = a.Sendmail
	}
	w("php_admin_value[sendmail_path] = %s -t -i\n", sm)
	if !l.AllowExec {
		w("php_admin_value[disable_functions] = %s\n", disabledFunctions)
	}
	w("php_admin_value[opcache.memory_consumption] = 128\nphp_admin_flag[opcache.validate_timestamps] = on\nphp_admin_value[opcache.revalidate_freq] = 2\n")
	// The account's own php.ini values replace the defaults: PHP-FPM keeps
	// the first value of a key given twice.
	o := a.PHP[version]
	var out strings.Builder
	for _, line := range strings.SplitAfter(b.String(), "\n") {
		if _, rest, ok := strings.Cut(line, "["); ok && strings.HasPrefix(line, "php_") {
			if k, _, ok := strings.Cut(rest, "]"); ok && o.INI[k] != "" {
				continue
			}
		}
		out.WriteString(line)
	}
	out.WriteString(o.iniLines())
	return out.String(), nil
}

// FPMUnit renders the systemd unit of an account's PHP version. The master
// runs as the account user with the cage as its root directory, in the
// account's slice, with the usual systemd sandboxing.
func FPMUnit(a Account, version string) (string, error) {
	if err := a.Validate(); err != nil {
		return "", err
	}
	if !ValidPHPVersion(version) {
		return "", errors.New("invalid PHP version")
	}
	return fmt.Sprintf(`# HostZit (generated, do not edit)
[Unit]
Description=PHP %[2]s of hosting account %[1]s
After=network.target mariadb.service %[3]s
Requires=%[3]s
PartOf=%[3]s

[Service]
Type=notify
User=%[1]s
Group=%[1]s
Slice=%[4]s
RootDirectory=%[5]s
MountAPIVFS=yes
BindPaths=-/run/mysqld -/run/emailzit/submit.sock
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
UMask=0022
Environment=PHP_INI_SCAN_DIR=%[7]s
ExecStart=/usr/sbin/php-fpm%[2]s --nodaemonize --fpm-config %[6]s
ExecReload=/bin/kill -USR2 $MAINPID
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
`, a.Name, version, CageUnitName(a.Name), SliceName(a.Name), CageDir(a.Name), FPMConfPath(version), PHPScanDir(version)), nil
}

// SliceUnit renders the cgroup limits of an account.
func SliceUnit(a Account) (string, error) {
	if err := a.Validate(); err != nil {
		return "", err
	}
	return "# HostZit (generated, do not edit)\n[Unit]\nDescription=Hosting account " + a.Name + "\nBefore=slices.target\n\n[Slice]\n" + cgroupLines(a.Limits), nil
}

// UserSliceDropIn renders the same limits for the account's login sessions
// (SSH lands in user-<uid>.slice through pam_systemd).
func UserSliceDropIn(a Account) (string, error) {
	if err := a.Validate(); err != nil {
		return "", err
	}
	return "# HostZit (generated, do not edit)\n[Slice]\n" + cgroupLines(a.Limits), nil
}

func cgroupLines(l Limits) string {
	var b strings.Builder
	if l.CPUPercent > 0 {
		fmt.Fprintf(&b, "CPUQuota=%d%%\n", l.CPUPercent)
	}
	if l.MemoryMB > 0 {
		// High throttles first; Max is the hard stop (OOM inside the account only).
		fmt.Fprintf(&b, "MemoryHigh=%dM\nMemoryMax=%dM\nMemorySwapMax=0\n", l.MemoryMB*9/10, l.MemoryMB)
	}
	if l.IOWeight > 0 {
		fmt.Fprintf(&b, "IOWeight=%d\n", l.IOWeight)
	}
	if l.Processes > 0 {
		fmt.Fprintf(&b, "TasksMax=%d\n", l.Processes)
	}
	b.WriteString("CPUAccounting=yes\nMemoryAccounting=yes\nIOAccounting=yes\nTasksAccounting=yes\n")
	return b.String()
}

// CageUnit renders the oneshot unit that mounts the cage at boot.
func CageUnit(a Account) (string, error) {
	if err := a.Validate(); err != nil {
		return "", err
	}
	return fmt.Sprintf(`# HostZit (generated, do not edit)
[Unit]
Description=File system view (cage) of hosting account %[1]s
After=local-fs.target
Before=ssh.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/lib/hostzit/hostzit-helper cage-mount %[1]s
ExecStop=/usr/lib/hostzit/hostzit-helper cage-umount %[1]s

[Install]
WantedBy=multi-user.target
`, a.Name), nil
}

// FPMConfPathHost is the host path of the pool file of an account.
func FPMConfPathHost(account, version string) string {
	return CageDir(account) + FPMConfPath(version)
}
