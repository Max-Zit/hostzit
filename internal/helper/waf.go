package helper

import (
	"context"
	"strings"

	"github.com/max-zit/hostzit/internal/hosting"
)

// wafInstall installs ModSecurity for nginx with the OWASP Core Rule Set;
// the sites switch the firewall on one by one.
func (h *Helper) wafInstall(ctx context.Context, _ struct{}) (any, error) {
	if out, err := h.apt(ctx, "install", "--no-install-recommends", "libnginx-mod-http-modsecurity", "modsecurity-crs"); err != nil {
		return nil, userErr("ModSecurity could not be installed: " + tail(string(out), 300))
	}
	if !h.Sys.Exists("/usr/share/modsecurity-crs/rules") || !h.Sys.Exists("/etc/modsecurity/crs/crs-setup.conf") {
		return nil, userErr("the OWASP Core Rule Set is missing after the installation")
	}
	if err := h.writeModSec(); err != nil {
		return nil, err
	}
	return nil, h.systemctl(ctx, "reload", "nginx")
}

func init() {
	moreOps = append(moreOps, func(h *Helper) {
		h.ops["waf.install"] = op{handle(h.wafInstall), true}
	})
}

// writeModSec writes the blocking and the logging-only rule files.
func (h *Helper) writeModSec() error {
	if err := h.Sys.WriteFile(hosting.ModSecConf, []byte(modsecConf), 0o644, 0, 0); err != nil {
		return err
	}
	detect := strings.Replace(modsecConf, "SecRuleEngine On\n", "SecRuleEngine DetectionOnly\n", 1)
	return h.Sys.WriteFile(hosting.ModSecDetectConf, []byte(detect), 0o644, 0, 0)
}
