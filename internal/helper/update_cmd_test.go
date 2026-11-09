package helper

import (
	"strings"
	"testing"
)

// The panel update must wait for the dpkg lock (Debian's automatic updates
// right after the first start held it in the 0.9.1 → 0.9.2 upgrade test),
// keep changed configuration files and install the downloaded file.
func TestUpdateCommandWaitsForTheLock(t *testing.T) {
	c := strings.Join(updateCommand("hostzit-update-0-9-3", "/var/cache/hostzit/update/hostzit_0.9.3_amd64.deb"), " ")
	for _, want := range []string{
		"--unit=hostzit-update-0-9-3",
		"--setenv=DEBIAN_FRONTEND=noninteractive",
		" apt-get -y ",
		"-o DPkg::Lock::Timeout=1800",
		"-o Dpkg::Options::=--force-confdef",
		"-o Dpkg::Options::=--force-confold",
		" install /var/cache/hostzit/update/hostzit_0.9.3_amd64.deb",
	} {
		if !strings.Contains(c, want) {
			t.Errorf("update command %q lacks %q", c, want)
		}
	}
	if strings.Contains(c, "dpkg -i") || strings.Contains(c, " dpkg ") {
		t.Errorf("update command still calls dpkg directly: %q", c)
	}
}
