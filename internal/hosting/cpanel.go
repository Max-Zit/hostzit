package hosting

import (
	"regexp"
	"strings"
)

// cpanelBackupRE matches the folder (and file) name of a backup made with
// cPanel's Backup → Download a Full Account Backup:
// backup-MM.DD.YYYY_HH-MM-SS_USER.
var cpanelBackupRE = regexp.MustCompile(`^backup-\d{1,2}\.\d{1,2}\.\d{4}_\d{1,2}-\d{1,2}-\d{1,2}_([a-z][a-z0-9_]*)$`)

// CPanelUser returns the cPanel account name of a backup folder or file:
// cpmove-USER (pkgacct) or backup-…_USER (Download a Full Account Backup).
func CPanelUser(name string) (string, bool) {
	name = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(name, ".tar.gz"), ".tgz"), ".tar")
	if u, ok := strings.CutPrefix(name, "cpmove-"); ok && cpanelUserRE.MatchString(u) {
		return u, true
	}
	if m := cpanelBackupRE.FindStringSubmatch(name); m != nil {
		return m[1], true
	}
	return "", false
}

var cpanelUserRE = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// CPanelPHP maps cPanel's PHP handler name (ea-php81, alt-php74 …) to a
// version like 8.1; "" when it is not one.
func CPanelPHP(v string) string {
	v = strings.TrimSpace(v)
	for _, p := range []string{"ea-php", "alt-php"} {
		if d, ok := strings.CutPrefix(v, p); ok && len(d) == 2 && d[0] >= '5' && d[0] <= '9' && d[1] >= '0' && d[1] <= '9' {
			return d[:1] + "." + d[1:]
		}
	}
	return ""
}
