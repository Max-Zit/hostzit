package helper

import (
	"context"
	"regexp"
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
	_ = h.Sys.Mkdir("/var/lib/hostzit/private", 0o700, 0, 0)
	key := "/var/lib/hostzit/private/debsuryorg-archive-keyring.deb"
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

// phpModules are the extensions Debian loads for PHP-FPM of a version:
// conf.d entries such as 20-mbstring.ini → mbstring.
func (h *Helper) phpModules(version string) []string {
	ents, _ := h.Sys.ReadDir("/etc/php/" + version + "/fpm/conf.d")
	var mods []string
	for _, e := range ents {
		n := strings.TrimSuffix(e.Name(), ".ini")
		if i := strings.Index(n, "-"); i >= 0 {
			n = n[i+1:]
		}
		if n != "" && n != e.Name() && extNameRE.MatchString(n) {
			mods = append(mods, n)
		}
	}
	slices.Sort(mods)
	return slices.Compact(mods)
}

var extNameRE = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)

// phpScanDir writes the account's extension folder for a version (inside
// the cage): links to mods-available for every module the server loads,
// except those the account switched off.
func (h *Helper) phpScanDir(a hosting.Account, version string) error {
	dir := hosting.CageDir(a.Name) + hosting.PHPScanDir(version)
	_ = h.Sys.RemoveAll(dir)
	if err := h.Sys.Mkdir(dir, 0o755, 0, 0); err != nil {
		return err
	}
	off := a.PHP[version].Disabled
	ents, _ := h.Sys.ReadDir("/etc/php/" + version + "/fpm/conf.d")
	for _, e := range ents {
		n := strings.TrimSuffix(e.Name(), ".ini")
		mod := n
		if i := strings.Index(n, "-"); i >= 0 {
			mod = n[i+1:]
		}
		if !strings.HasSuffix(e.Name(), ".ini") || !extNameRE.MatchString(mod) || slices.Contains(off, mod) {
			continue
		}
		if err := h.Sys.Symlink("/etc/php/"+version+"/mods-available/"+mod+".ini", dir+"/"+e.Name()); err != nil {
			return err
		}
	}
	return nil
}

// phpExtProtected cannot be removed from the server.
var phpExtProtected = []string{"fpm", "cli", "common", "opcache", "readline"}

// phpNotExt are php<v>-* packages that are no extensions (other SAPIs,
// headers).
var phpNotExt = []string{"dev", "cgi", "phpdbg", "litespeed", "embed", "xsl"}

type phpExtArgs struct {
	Version string   `json:"version"`
	Install []string `json:"install"`
	Remove  []string `json:"remove"`
}

// PHPExtensions lists the extension packages of a version.
type PHPExtensions struct {
	Available []string `json:"available"` // package suffixes (php8.4-<x>)
	Installed []string `json:"installed"`
	Loaded    []string `json:"loaded"` // modules PHP-FPM loads
}

func (h *Helper) phpExtList(ctx context.Context, a phpArgs) (any, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	res := PHPExtensions{Loaded: h.phpModules(a.Version)}
	pre := "php" + a.Version + "-"
	out, _ := h.Sys.Run(ctx, nil, "apt-cache", "pkgnames", pre)
	for _, l := range strings.Split(string(out), "\n") {
		if x, ok := strings.CutPrefix(strings.TrimSpace(l), pre); ok && extNameRE.MatchString(x) && !strings.HasSuffix(x, "dbgsym") && !slices.Contains(phpNotExt, x) {
			res.Available = append(res.Available, x)
		}
	}
	slices.Sort(res.Available)
	res.Available = slices.Compact(res.Available)
	out, _ = h.Sys.Run(ctx, nil, "dpkg-query", "-W", "-f", "${Package} ${Status}\n", pre+"*")
	for _, l := range strings.Split(string(out), "\n") {
		if f := strings.Fields(l); len(f) >= 2 && strings.HasSuffix(l, " installed") {
			if x, ok := strings.CutPrefix(f[0], pre); ok {
				res.Installed = append(res.Installed, x)
			}
		}
	}
	slices.Sort(res.Installed)
	return res, nil
}

// phpExtSet installs and removes extension packages of a version; the
// panel then applies the accounts again (their extension folders).
func (h *Helper) phpExtSet(ctx context.Context, a phpExtArgs) (any, error) {
	if err := (phpArgs{Version: a.Version}).check(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	pre := "php" + a.Version + "-"
	var inst, rem []string
	for _, x := range a.Install {
		if !extNameRE.MatchString(x) {
			return nil, userErr("invalid extension name")
		}
		inst = append(inst, pre+x)
	}
	for _, x := range a.Remove {
		if !extNameRE.MatchString(x) || slices.Contains(phpExtProtected, x) {
			return nil, userErr(x + " cannot be removed")
		}
		rem = append(rem, pre+x)
	}
	if len(inst) > 0 {
		if out, err := h.apt(ctx, append([]string{"install", "--no-install-recommends"}, inst...)...); err != nil {
			return nil, userErr("installation failed: " + tail(string(out)+" "+err.Error(), 400))
		}
	}
	if len(rem) > 0 {
		if out, err := h.apt(ctx, append([]string{"purge"}, rem...)...); err != nil {
			return nil, userErr("removing failed: " + tail(string(out)+" "+err.Error(), 400))
		}
	}
	_, _ = h.Sys.Run(ctx, nil, "systemctl", "disable", "--now", "php"+a.Version+"-fpm")
	return map[string]any{"loaded": h.phpModules(a.Version)}, nil
}

type phpModsArgs struct {
	Version string `json:"version"`
}

func (h *Helper) phpMods(_ context.Context, a phpModsArgs) (any, error) {
	if !hosting.ValidPHPVersion(a.Version) {
		return nil, userErr("unknown PHP version")
	}
	return h.phpModules(a.Version), nil
}

func init() {
	moreOps = append(moreOps, func(h *Helper) {
		h.ops["php.ext.list"] = op{handle(h.phpExtList), false}
		h.ops["php.ext.set"] = op{handle(h.phpExtSet), true}
		h.ops["php.modules"] = op{handle(h.phpMods), false}
	})
}
