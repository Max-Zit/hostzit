package hosting

import (
	"fmt"
	"sort"
	"strings"
)

// The cage is an account's private view of the file system, used as the
// root directory of its PHP, cron jobs, tools and SSH/SFTP sessions:
//
//	/usr, /etc/ssl, /etc/php …   read-only from the host
//	/home/<account>              the account's own home (nothing else in /home)
//	/tmp, /var/tmp               the account's private temporary folder
//	/etc/passwd, /etc/group      only root, the account and the web group
//	/run/php                     the account's PHP sockets (nginx reaches them)
//	/run/mysqld                  the database socket
//
// Host paths that list other accounts (/etc/nginx, /etc/hostzit, systemd
// units, other homes, /proc of others) are simply not there.

// Mount is one bind mount of a cage.
type Mount struct {
	Source   string // host path
	Target   string // path inside the cage
	ReadOnly bool
	File     bool // a single file, not a directory
	Optional bool // skip when the source does not exist
}

// CageMounts lists the bind mounts of an account's cage in mount order.
func CageMounts(account string) []Mount {
	home := HomeDir(account)
	m := []Mount{
		{Source: "/usr", Target: "/usr", ReadOnly: true},
		{Source: home, Target: home},
		{Source: TmpDir(account), Target: "/tmp"},
		{Source: TmpDir(account), Target: "/var/tmp"},
		{Source: "/run/mysqld", Target: "/run/mysqld", Optional: true},
		{Source: "/run/emailzit/submit", Target: "/run/emailzit/submit", Optional: true},
	}
	for _, d := range cageEtcDirs {
		m = append(m, Mount{Source: "/etc/" + d, Target: "/etc/" + d, ReadOnly: true, Optional: true})
	}
	return m
}

// cageEtcDirs are the /etc folders programs in the cage need.
var cageEtcDirs = []string{"ssl", "php", "alternatives", "ImageMagick-6", "ImageMagick-7", "fonts", "ca-certificates", "mysql/conf.d", "terminfo", "bash_completion.d", "profile.d", "vim", "git", "wgetrc.d", "ldap", "security/limits.d"}

// cageEtcFiles are copied (not mounted) from the host's /etc at every cage
// mount, so they keep up with the system but cannot be symlink targets.
var cageEtcFiles = []string{"hosts", "nsswitch.conf", "resolv.conf", "localtime", "ld.so.cache", "host.conf", "mime.types", "protocols", "services", "profile", "bash.bashrc", "inputrc", "environment", "mailcap", "magic", "gai.conf", "timezone", "debian_version", "os-release", "shells", "wgetrc"}

// CageEtcFiles lists the files copied into the cage's /etc.
func CageEtcFiles() []string { return append([]string(nil), cageEtcFiles...) }

// CageDirs are the directories created inside the cage (mode, path).
var CageDirs = []struct {
	Path string
	Mode uint32
}{
	{"/.hz", 0o755}, {"/etc", 0o755}, {"/etc/mysql", 0o755}, {"/etc/security", 0o755}, {"/home", 0o755}, {"/run", 0o755}, {"/run/emailzit", 0o755},
	{"/var", 0o755}, {"/dev", 0o755}, {"/dev/pts", 0o755}, {"/proc", 0o555}, {"/sys", 0o555},
}

// CageSymlinks are the merged-/usr links (Debian 12+).
var CageSymlinks = map[string]string{"/bin": "usr/bin", "/sbin": "usr/sbin", "/lib": "usr/lib", "/lib64": "usr/lib64"}

// CagePasswd renders the cage's /etc/passwd: root, the account, nobody.
func CagePasswd(a Account) (string, error) {
	uid, err := UID(a.Number)
	if err != nil {
		return "", err
	}
	if err := ValidAccount(a.Name); err != nil {
		return "", err
	}
	shell := "/usr/sbin/nologin"
	if a.Limits.SSH {
		shell = "/bin/bash"
	}
	return fmt.Sprintf("root:x:0:0:root:/root:/usr/sbin/nologin\n%s:x:%d:%d::%s:%s\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n", a.Name, uid, uid, HomeDir(a.Name), shell), nil
}

// CageGroup renders the cage's /etc/group.
func CageGroup(a Account, webGID int) (string, error) {
	uid, err := UID(a.Number)
	if err != nil {
		return "", err
	}
	if err := ValidAccount(a.Name); err != nil {
		return "", err
	}
	return fmt.Sprintf("root:x:0:\n%s:x:%d:\nhostzit-web:x:%d:\nnogroup:x:65534:\n", a.Name, uid, webGID), nil
}

// CageDevices are the device nodes of a cage (for SSH sessions; systemd
// units get their own private /dev).
var CageDevices = []struct {
	Name         string
	Major, Minor uint32
}{
	{"null", 1, 3}, {"zero", 1, 5}, {"full", 1, 7}, {"random", 1, 8}, {"urandom", 1, 9}, {"tty", 5, 0},
}

// HomeLayout are the folders of a new account's home: path relative to the
// home, mode, and whether the web server group owns it (nginx may read
// static files below it; other accounts may not).
var HomeLayout = []struct {
	Path  string
	Mode  uint32
	WebGr bool
}{
	{"", 0o711, false},
	{"sites", 0o750, true},
	{"logs", 0o700, false},
	{".ssh", 0o700, false},
	{"backups", 0o700, false},
}

// SortedNames returns the names of a map's keys in order (deterministic
// output for tests and config files).
func SortedNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SSHDConfig is the drop-in for OpenSSH (/etc/ssh/sshd_config.d/hostzit.conf):
// hosting accounts are locked into their cage; without shell access only
// SFTP works.
func SSHDConfig() string {
	return strings.TrimLeft(`
# HostZit (generated, do not edit)
Match Group hostzit-users
    ChrootDirectory /var/lib/hostzit/cages/%u
    AllowTcpForwarding no
    AllowAgentForwarding no
    AllowStreamLocalForwarding no
    PermitTunnel no
    X11Forwarding no
    PermitTTY yes
    PasswordAuthentication yes
Match Group hostzit-sftponly
    ForceCommand internal-sftp -d /home/%u
    PermitTTY no
`, "\n")
}
