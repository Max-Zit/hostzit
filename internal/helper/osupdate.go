package helper

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Updates of the operating system (Debian and the packages.sury.org PHP
// versions): the admin panel shows what waits, installs it now and can
// switch on nightly security updates. After every package change the PHP
// masters of the accounts that still run a replaced binary are restarted
// (an apt hook), so a patched PHP is really in use.

const (
	autoUpgradesConf = "/etc/apt/apt.conf.d/52hostzit-auto-upgrades"
	phpRestartHook   = "/etc/apt/apt.conf.d/53hostzit-php-restart"
	osUpgradeLog     = "/var/log/hostzit/os-upgrade.log"
	osUpgradeUnit    = "hostzit-os-upgrade"
)

const phpRestartHookConf = `// HostZit (generated): after every package change, restart the PHP
// processes of hosting accounts that still run a replaced PHP binary.
DPkg::Post-Invoke { "if [ -x /usr/lib/hostzit/hostzit-helper ]; then /usr/lib/hostzit/hostzit-helper php-restart-stale || true; fi"; };
`

const autoUpgradesText = `// HostZit (generated): nightly security updates of Debian and the PHP
// versions from packages.sury.org.
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
Unattended-Upgrade::Origins-Pattern {
	"origin=Debian,codename=${distro_codename},label=Debian-Security";
	"origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
	"origin=deb.sury.org";
};
Unattended-Upgrade::Automatic-Reboot "false";
`

// OSPackage is an update that waits.
type OSPackage struct {
	Name     string `json:"name"`
	From     string `json:"from"`
	To       string `json:"to"`
	Security bool   `json:"security"`
}

// OSStatus is what Settings → System shows.
type OSStatus struct {
	Packages       []OSPackage `json:"packages"`
	Running        bool        `json:"running"`
	Auto           bool        `json:"auto"`
	RebootRequired bool        `json:"reboot_required"`
	RebootPackages []string    `json:"reboot_packages"`
	LastRun        time.Time   `json:"last_run"`
	LastLog        string      `json:"last_log"`
}

type osStatusArgs struct {
	Refresh bool `json:"refresh"`
}

func (h *Helper) osRunning(ctx context.Context) bool {
	out, _ := h.Sys.Run(ctx, nil, "systemctl", "is-active", osUpgradeUnit)
	s := strings.TrimSpace(string(out))
	return s == "active" || s == "activating"
}

func (h *Helper) osStatus(ctx context.Context, a osStatusArgs) (any, error) {
	st := OSStatus{Running: h.osRunning(ctx), Auto: h.Sys.Exists(autoUpgradesConf), RebootRequired: h.Sys.Exists("/run/reboot-required")}
	if a.Refresh && !st.Running {
		ctx2, cancel := context.WithTimeout(ctx, 3*time.Minute)
		_, _ = h.apt(ctx2, "update")
		cancel()
	}
	if b, err := h.Sys.ReadFile("/run/reboot-required.pkgs"); err == nil {
		st.RebootPackages = strings.Fields(string(b))
	}
	out, _ := h.Sys.Run(ctx, nil, "apt", "list", "--upgradable")
	for _, l := range strings.Split(string(out), "\n") {
		// name/suite version arch [upgradable from: old]
		f := strings.Fields(l)
		if len(f) < 6 || !strings.Contains(f[0], "/") || f[3] != "[upgradable" {
			continue
		}
		name, suite, _ := strings.Cut(f[0], "/")
		st.Packages = append(st.Packages, OSPackage{Name: name, To: f[1], From: strings.TrimSuffix(f[5], "]"),
			Security: strings.Contains(suite, "-security")})
	}
	if b, err := h.Sys.ReadFile(osUpgradeLog); err == nil {
		st.LastLog = tail(string(b), 2000)
		if fi, err := os.Stat(osUpgradeLog); err == nil {
			st.LastRun = fi.ModTime()
		}
	}
	return st, nil
}

// osUpgrade installs all waiting updates in a unit of its own (the helper
// may be restarted by a package meanwhile).
func (h *Helper) osUpgrade(ctx context.Context, _ struct{}) (any, error) {
	if h.osRunning(ctx) {
		return nil, userErr("the updates are already being installed")
	}
	_, _ = h.Sys.Run(ctx, nil, "systemctl", "reset-failed", osUpgradeUnit)
	if out, err := h.Sys.Run(ctx, nil, "systemd-run", "--unit="+osUpgradeUnit, "--collect", "--setenv=DEBIAN_FRONTEND=noninteractive",
		h.HelperBin, "os-upgrade"); err != nil {
		return nil, userErr("could not start: " + tail(string(out)+" "+err.Error(), 300))
	}
	return nil, nil
}

type osAutoArgs struct {
	On bool `json:"on"`
}

func (h *Helper) osAuto(ctx context.Context, a osAutoArgs) (any, error) {
	if !a.On {
		return nil, h.Sys.Remove(autoUpgradesConf)
	}
	if !h.Sys.Exists("/usr/bin/unattended-upgrade") {
		if out, err := h.apt(ctx, "install", "unattended-upgrades"); err != nil {
			return nil, userErr("unattended-upgrades could not be installed: " + tail(string(out), 300))
		}
	}
	return nil, h.Sys.WriteFile(autoUpgradesConf, []byte(autoUpgradesText), 0o644, 0, 0)
}

// RunOSUpgrade is "hostzit-helper os-upgrade" (run by osUpgrade's unit).
func RunOSUpgrade(ctx context.Context) error {
	_ = os.MkdirAll(filepath.Dir(osUpgradeLog), 0o750)
	logf, err := os.OpenFile(osUpgradeLog, os.O_CREATE|os.O_TRUNC|os.O_WRONLY|noFollowFile, 0o600) // #nosec G304 -- fixed root-owned log
	if err != nil {
		return err
	}
	defer logf.Close()
	run := func(args ...string) error {
		cmd := exec.CommandContext(ctx, "apt-get", append([]string{"-y", "-q", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}, args...)...) // #nosec G204 -- fixed program and arguments
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "DEBIAN_FRONTEND=noninteractive"}
		cmd.Stdout, cmd.Stderr = logf, logf
		return cmd.Run()
	}
	_, _ = logf.WriteString("== " + time.Now().UTC().Format(time.RFC3339) + " apt-get update\n")
	if err := run("update"); err != nil {
		_, _ = logf.WriteString("apt-get update failed: " + err.Error() + "\n")
	}
	_, _ = logf.WriteString("== apt-get dist-upgrade\n")
	err = run("dist-upgrade")
	if err != nil {
		_, _ = logf.WriteString("FAILED: " + err.Error() + "\n")
	} else {
		_, _ = logf.WriteString("== done\n")
	}
	RestartStalePHP(ctx, logf)
	return err
}

// RestartStalePHP restarts the accounts' PHP masters whose binary was
// replaced by an update ("hostzit-helper php-restart-stale").
func RestartStalePHP(ctx context.Context, logf *os.File) {
	out, _ := exec.CommandContext(ctx, "systemctl", "list-units", "--no-legend", "--plain", "--state=running", "hz-php-*").Output() // #nosec G204 -- fixed
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) == 0 || !strings.HasPrefix(f[0], "hz-php-") || !strings.HasSuffix(f[0], ".service") {
			continue
		}
		pid, _ := exec.CommandContext(ctx, "systemctl", "show", "-p", "MainPID", "--value", f[0]).Output() // #nosec G204 -- unit name from systemd
		n, err := strconv.Atoi(strings.TrimSpace(string(pid)))
		if err != nil || n <= 0 {
			continue
		}
		exe, err := os.Readlink("/proc/" + strconv.Itoa(n) + "/exe")
		if err != nil || !strings.HasSuffix(exe, " (deleted)") {
			continue
		}
		_ = exec.CommandContext(ctx, "systemctl", "restart", f[0]).Run() // #nosec G204 -- unit name from systemd
		if logf != nil {
			_, _ = logf.WriteString("restarted " + f[0] + " (PHP was updated)\n")
		}
	}
}

func init() {
	moreOps = append(moreOps, func(h *Helper) {
		h.ops["os.status"] = op{handle(h.osStatus), false}
		h.ops["os.upgrade"] = op{handle(h.osUpgrade), false}
		h.ops["os.auto"] = op{handle(h.osAuto), true}
	})
}
