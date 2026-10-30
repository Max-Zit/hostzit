package helper

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/hosting"
)

// Several PHP versions side by side (like cPanel's MultiPHP): Debian has
// one; the others come from the packages.sury.org repository (the
// maintainer of Debian's PHP packages). Every account runs its own PHP-FPM
// master per version, so a version is usable by all sites once installed.

// PHPVersionsOffered are the versions the admin panel offers to install.
var PHPVersionsOffered = []string{"5.6", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0", "8.1", "8.2", "8.3", "8.4", "8.5", "8.6"}

// phpExtensions are installed with every version (when the version has them).
var phpExtensions = []string{"fpm", "cli", "mysql", "xml", "mbstring", "curl", "gd", "zip", "intl", "opcache", "imagick", "bcmath"}

const surySources = "/etc/apt/sources.list.d/hostzit-php-sury.list"

type phpArgs struct {
	Version string `json:"version"`
}

func (a phpArgs) check() error {
	if !hosting.ValidPHPVersion(a.Version) || !slices.Contains(PHPVersionsOffered, a.Version) {
		return userErr("unknown PHP version")
	}
	return nil
}

// apt runs apt-get without questions.
func (h *Helper) apt(ctx context.Context, args ...string) ([]byte, error) {
	return h.Sys.Run(ctx, nil, "env", append([]string{"DEBIAN_FRONTEND=noninteractive", "apt-get", "-y", "-q",
		"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}, args...)...)
}

func (h *Helper) aptHas(ctx context.Context, pkg string) bool {
	out, err := h.Sys.Run(ctx, nil, "apt-cache", "policy", pkg)
	return err == nil && strings.Contains(string(out), "Candidate:") && !strings.Contains(string(out), "Candidate: (none)")
}

// addSury adds the packages.sury.org repository with its signing key.
func (h *Helper) addSury(ctx context.Context) error {
	if h.Sys.Exists(surySources) {
		return nil
	}
	codename := ""
	if b, err := h.Sys.ReadFile("/etc/os-release"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "VERSION_CODENAME="); ok {
				codename = strings.Trim(v, `"`)
			}
		}
	}
	if codename != "bookworm" && codename != "trixie" {
		return userErr("other PHP versions are available on Debian 12 and 13 only")
	}
	_ = h.Sys.Mkdir("/var/lib/hostzit/tmp", 0o700, 0, 0)
	key := "/var/lib/hostzit/tmp/debsuryorg-archive-keyring.deb"
	if _, err := h.Sys.Run(ctx, nil, "curl", "-fsSL", "--proto", "=https", "-o", key, "https://packages.sury.org/debsuryorg-archive-keyring.deb"); err != nil {
		return userErr("the repository key could not be downloaded: " + err.Error())
	}
	defer h.Sys.Remove(key) //nolint:errcheck
	if _, err := h.Sys.Run(ctx, nil, "dpkg", "-i", key); err != nil {
		return err
	}
	line := "# HostZit: PHP versions from packages.sury.org\ndeb [signed-by=/usr/share/keyrings/debsuryorg-archive-keyring.gpg] https://packages.sury.org/php/ " + codename + " main\n"
	if err := h.Sys.WriteFile(surySources, []byte(line), 0o644, 0, 0); err != nil {
		return err
	}
	_, err := h.apt(ctx, "update")
	return err
}

func (h *Helper) phpInstall(ctx context.Context, a phpArgs) (any, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	if !h.aptHas(ctx, "php"+a.Version+"-fpm") {
		if err := h.addSury(ctx); err != nil {
			return nil, err
		}
		if !h.aptHas(ctx, "php"+a.Version+"-fpm") {
			return nil, userErr("PHP " + a.Version + " is not available for this Debian")
		}
	}
	var pkgs []string
	for _, e := range phpExtensions {
		if p := "php" + a.Version + "-" + e; h.aptHas(ctx, p) {
			pkgs = append(pkgs, p)
		}
	}
	if out, err := h.apt(ctx, append([]string{"install", "--no-install-recommends"}, pkgs...)...); err != nil {
		return nil, userErr("installation failed: " + tail(string(out)+" "+err.Error(), 400))
	}
	// HostZit starts one PHP-FPM master per account; Debian's own one stays off.
	_, _ = h.Sys.Run(ctx, nil, "systemctl", "disable", "--now", "php"+a.Version+"-fpm")
	return map[string]any{"packages": pkgs}, nil
}

func (h *Helper) phpRemove(ctx context.Context, a phpArgs) (any, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	out, _ := h.Sys.Run(ctx, nil, "dpkg-query", "-W", "-f", "${Package} ${Status}\n", "php"+a.Version+"-*")
	var pkgs []string
	for _, l := range strings.Split(string(out), "\n") {
		if f := strings.Fields(l); len(f) >= 2 && strings.HasSuffix(l, "installed") && strings.HasPrefix(f[0], "php"+a.Version+"-") {
			pkgs = append(pkgs, f[0])
		}
	}
	if len(pkgs) == 0 {
		return nil, nil
	}
	if out, err := h.apt(ctx, append([]string{"purge"}, pkgs...)...); err != nil {
		return nil, userErr("removing failed: " + tail(string(out)+" "+err.Error(), 400))
	}
	_, _ = h.apt(ctx, "autoremove", "--purge")
	return nil, nil
}

func init() {
	moreOps = append(moreOps, func(h *Helper) {
		h.ops["php.install"] = op{handle(h.phpInstall), true}
		h.ops["php.remove"] = op{handle(h.phpRemove), true}
	})
}
