package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/max-zit/hostzit/internal/hosting"
)

const systemdDir = "/etc/systemd/system/"

func (h *Helper) systemctl(ctx context.Context, args ...string) error {
	_, err := h.Sys.Run(ctx, nil, "systemctl", args...)
	return err
}

// lookupID runs getent and returns the numeric id of a user or group ("" = missing).
func (h *Helper) lookupID(ctx context.Context, db, name string) (int, bool) {
	out, err := h.Sys.Run(ctx, nil, "getent", db, name)
	if err != nil {
		return 0, false
	}
	f := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(f) < 3 {
		return 0, false
	}
	id, err := strconv.Atoi(f[2])
	return id, err == nil
}

// webGID is the id of the web server's group. The helper may have started
// before the package's setup created the group, so it is looked up again
// until known; root (0) is never used in its place.
func (h *Helper) webGID(ctx context.Context) (int, error) {
	if h.WebGID > 0 {
		return h.WebGID, nil
	}
	if id, ok := h.lookupID(ctx, "group", h.WebGroup); ok && id > 0 {
		return id, nil
	}
	return 0, fmt.Errorf("the group %s is missing: run hostzit-helper setup", h.WebGroup)
}

// accountApply creates or updates an account: user, groups, home layout,
// private tmp, cage, cgroup slice, PHP masters, quota, lock state.
func (h *Helper) accountApply(ctx context.Context, a hosting.Account) (any, error) {
	if err := a.Validate(); err != nil {
		return nil, userErr(err.Error())
	}
	uid, _ := hosting.UID(a.Number)
	webGID, err := h.webGID(ctx)
	if err != nil {
		return nil, err
	}
	if gid, ok := h.lookupID(ctx, "group", a.Name); ok && gid != uid {
		return nil, userErr(fmt.Sprintf("a group %s with another id already exists on the server", a.Name))
	} else if !ok {
		if _, err := h.Sys.Run(ctx, nil, "groupadd", "-g", strconv.Itoa(uid), a.Name); err != nil {
			return nil, err
		}
	}
	groups := "hostzit-users"
	if !a.Limits.SSH {
		groups += ",hostzit-sftponly"
	}
	newUser := false
	if id, ok := h.lookupID(ctx, "passwd", a.Name); ok && id != uid {
		return nil, userErr(fmt.Sprintf("a user %s with another id already exists on the server", a.Name))
	} else if !ok {
		// No subordinate ids: they could overlap the hosting uid range.
		if _, err := h.Sys.Run(ctx, nil, "useradd", "-u", strconv.Itoa(uid), "-g", strconv.Itoa(uid), "-G", groups, "-d", hosting.HomeDir(a.Name), "-M",
			"-s", "/bin/bash", "-K", "SUB_UID_COUNT=0", "-K", "SUB_GID_COUNT=0", "-c", "HostZit account", a.Name); err != nil {
			return nil, err
		}
		newUser = true
	} else if _, err := h.Sys.Run(ctx, nil, "usermod", "-G", groups, a.Name); err != nil {
		return nil, err
	}
	if a.Suspended {
		if _, err := h.Sys.Run(ctx, nil, "usermod", "-L", "-e", "1", a.Name); err != nil {
			return nil, err
		}
		_, _ = h.Sys.Run(ctx, nil, "pkill", "-KILL", "-u", a.Name)
	} else {
		_, _ = h.Sys.Run(ctx, nil, "usermod", "-e", "", a.Name)
		_, _ = h.Sys.Run(ctx, nil, "usermod", "-U", a.Name) // fails harmlessly while no password is set
	}

	// Home: only the top folders, owned by the account (the sites folder by
	// the web group so nginx can read static files; nobody else can).
	home := hosting.HomeDir(a.Name)
	if !newUser && !h.Sys.Exists(home) {
		newUser = true
	}
	for _, d := range hosting.HomeLayout {
		p := strings.TrimSuffix(home+"/"+d.Path, "/")
		gid := uid
		if d.WebGr {
			gid = webGID
		}
		if err := h.Sys.Mkdir(p, os.FileMode(d.Mode), uid, gid); err != nil {
			return nil, fmt.Errorf("home %s: %w", p, err)
		}
	}
	if err := h.Sys.Mkdir("/var/lib/hostzit/tmp", 0o711, 0, 0); err != nil {
		return nil, err
	}
	if err := h.Sys.Mkdir(hosting.TmpDir(a.Name), 0o700, uid, uid); err != nil {
		return nil, err
	}
	// mail spool (mounted as /.spool in the cage) and the limits the mailer reads
	if err := h.Sys.Mkdir(SpoolRoot, 0o711, 0, 0); err != nil {
		return nil, err
	}
	if err := h.Sys.Mkdir(SpoolRoot+"/"+a.Name, 0o700, uid, uid); err != nil {
		return nil, err
	}
	if lb, err := json.Marshal(a); err == nil {
		if err := h.Sys.WriteFile(accountsDir+"/"+a.Name+".json", lb, 0o600, 0, 0); err != nil {
			return nil, err
		}
	}
	if h.Sys.Exists("/usr/sbin/emailzit-sendmail") {
		a.Sendmail = "/usr/sbin/emailzit-sendmail"
	}
	if err := h.buildCage(ctx, a, uid, webGID); err != nil {
		return nil, fmt.Errorf("cage: %w", err)
	}

	// systemd: slice, cage mounts, PHP masters.
	files := map[string]string{}
	if files[systemdDir+hosting.SliceName(a.Name)], err = hosting.SliceUnit(a); err != nil {
		return nil, err
	}
	if files[systemdDir+"user-"+strconv.Itoa(uid)+".slice.d/50-hostzit.conf"], err = hosting.UserSliceDropIn(a); err != nil {
		return nil, err
	}
	if files[systemdDir+hosting.CageUnitName(a.Name)], err = hosting.CageUnit(a); err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, v := range a.PHPVersions {
		if !h.Sys.Exists("/usr/sbin/php-fpm" + v) {
			return nil, userErr("PHP " + v + " is not installed on this server")
		}
		u := hosting.FPMUnitName(a.Name, v)
		want[u] = true
		if files[systemdDir+u], err = hosting.FPMUnit(a, v); err != nil {
			return nil, err
		}
		conf, err := hosting.FPMConf(a, v)
		if err != nil {
			return nil, err
		}
		if err := h.Sys.WriteFile(hosting.CageDir(a.Name)+hosting.FPMConfPath(v), []byte(conf), 0o644, 0, 0); err != nil {
			return nil, err
		}
	}
	for _, name := range hosting.SortedNames(files) {
		if err := h.Sys.WriteFile(name, []byte(files[name]), 0o644, 0, 0); err != nil {
			return nil, err
		}
	}
	// PHP versions no longer used.
	old, _ := h.Sys.ReadDir(systemdDir)
	prefix := "hz-php-" + a.Name + "-"
	var stale []string
	for _, e := range old {
		n := e.Name()
		if strings.HasPrefix(n, prefix) && strings.HasSuffix(n, ".service") && !want[n] {
			stale = append(stale, n)
		}
	}
	for _, n := range stale {
		_ = h.systemctl(ctx, "disable", "--now", n)
		_ = h.Sys.Remove(systemdDir + n)
	}
	if err := h.systemctl(ctx, "daemon-reload"); err != nil {
		return nil, err
	}
	if err := h.systemctl(ctx, "enable", "--now", hosting.CageUnitName(a.Name)); err != nil {
		return nil, err
	}
	for u := range want {
		if a.Suspended {
			_ = h.systemctl(ctx, "disable", "--now", u)
			continue
		}
		if err := h.systemctl(ctx, "enable", u); err != nil {
			return nil, err
		}
		if err := h.systemctl(ctx, "restart", u); err != nil {
			return nil, err
		}
	}
	quota := h.setQuota(ctx, a)
	return map[string]any{"uid": uid, "created": newUser, "quota": quota}, nil
}

// setQuota applies the disk limits when quotas are active ("" = applied).
func (h *Helper) setQuota(ctx context.Context, a hosting.Account) string {
	if !h.Sys.Exists("/usr/sbin/setquota") {
		return "quota tools are not installed"
	}
	kb := strconv.Itoa(a.Limits.DiskMB * 1024)
	in := strconv.Itoa(a.Limits.Inodes)
	if _, err := h.Sys.Run(ctx, nil, "setquota", "-u", a.Name, kb, kb, in, in, "-a"); err != nil {
		return "disk quotas are not active: " + err.Error()
	}
	return ""
}

// buildCage creates the cage's directories, links, device nodes and the
// generated /etc files, then mounts it (again).
func (h *Helper) buildCage(ctx context.Context, a hosting.Account, uid, webGID int) error {
	root := hosting.CageDir(a.Name)
	if err := h.Sys.Mkdir("/var/lib/hostzit/cages", 0o711, 0, 0); err != nil {
		return err
	}
	if err := h.Sys.Mkdir(root, 0o755, 0, 0); err != nil {
		return err
	}
	for _, d := range hosting.CageDirs {
		if err := h.Sys.Mkdir(root+d.Path, os.FileMode(d.Mode), 0, 0); err != nil {
			return err
		}
	}
	if err := h.Sys.Mkdir(root+"/.sock", 0o750, uid, webGID); err != nil {
		return err
	}
	for _, l := range hosting.SortedNames(hosting.CageSymlinks) {
		if err := h.Sys.Symlink(hosting.CageSymlinks[l], root+l); err != nil {
			return err
		}
	}
	for _, d := range hosting.CageDevices {
		if err := h.Sys.Mknod(root+"/dev/"+d.Name, d.Major, d.Minor); err != nil {
			return err
		}
	}
	_ = h.Sys.Symlink("pts/ptmx", root+"/dev/ptmx")
	_ = h.Sys.Symlink("/proc/self/fd", root+"/dev/fd")
	passwd, err := hosting.CagePasswd(a)
	if err != nil {
		return err
	}
	group, err := hosting.CageGroup(a, webGID)
	if err != nil {
		return err
	}
	if err := h.Sys.WriteFile(root+"/etc/passwd", []byte(passwd), 0o644, 0, 0); err != nil {
		return err
	}
	if err := h.Sys.WriteFile(root+"/etc/group", []byte(group), 0o644, 0, 0); err != nil {
		return err
	}
	return h.cageMount(ctx, a.Name)
}

// cageMount copies the /etc files and makes the bind mounts (idempotent;
// also run at boot by hz-cage-<account>.service).
func (h *Helper) cageMount(_ context.Context, account string) error {
	if err := hosting.ValidAccount(account); err != nil {
		return err
	}
	root := hosting.CageDir(account)
	if !h.Sys.Exists(root + "/.hz") {
		return fmt.Errorf("no cage for %s", account)
	}
	for _, f := range hosting.CageEtcFiles() {
		b, err := h.Sys.ReadFile("/etc/" + f) // follows the host's symlink (resolv.conf): only the content is copied
		if err != nil {
			continue
		}
		if err := h.Sys.WriteFile(root+"/etc/"+f, b, 0o644, 0, 0); err != nil {
			return err
		}
	}
	for _, m := range hosting.CageMounts(account) {
		if !h.Sys.Exists(m.Source) {
			if m.Optional {
				continue
			}
			return fmt.Errorf("%s is missing", m.Source)
		}
		t := root + m.Target
		if h.Sys.Mounted(t) {
			continue
		}
		if m.File {
			if !h.Sys.Exists(t) {
				if err := h.Sys.WriteFile(t, nil, 0o644, 0, 0); err != nil {
					return err
				}
			}
		} else if err := h.Sys.Mkdir(t, 0o755, 0, 0); err != nil {
			return err
		}
		if err := h.Sys.Mount(MountReq{Source: m.Source, Target: t, ReadOnly: m.ReadOnly}); err != nil {
			return err
		}
	}
	if !h.Sys.Mounted(root + "/dev/pts") {
		if err := h.Sys.Mount(MountReq{Source: "/dev/pts", Target: root + "/dev/pts"}); err != nil {
			return err
		}
	}
	if !h.Sys.Mounted(root + "/proc") {
		if err := h.Sys.Mount(MountReq{Target: root + "/proc", Proc: true}); err != nil {
			return err
		}
	}
	return nil
}

// cageTargets lists every mount point of a cage, deepest first.
func cageTargets(account string) []string {
	root := hosting.CageDir(account)
	t := []string{root + "/proc", root + "/dev/pts"}
	ms := hosting.CageMounts(account)
	for i := len(ms) - 1; i >= 0; i-- {
		t = append(t, root+ms[i].Target)
	}
	return t
}

// cageUnmount removes the mounts; it reports an error when one is still
// there, so nothing ever deletes through a bind mount.
func (h *Helper) cageUnmount(_ context.Context, account string) error {
	if err := hosting.ValidAccount(account); err != nil {
		return err
	}
	for _, t := range cageTargets(account) {
		if h.Sys.Mounted(t) {
			if err := h.Sys.Unmount(t); err != nil {
				return err
			}
		}
	}
	for _, t := range cageTargets(account) {
		if h.Sys.Mounted(t) {
			return fmt.Errorf("%s is still mounted", t)
		}
	}
	return nil
}

type accountRef struct {
	Name   string `json:"name"`
	Number int    `json:"number"`
}

// accountDelete removes an account and all its files. The panel removes
// sites, databases and zones first.
func (h *Helper) accountDelete(ctx context.Context, a accountRef) (any, error) {
	if err := hosting.ValidAccount(a.Name); err != nil {
		return nil, userErr(err.Error())
	}
	uid, err := hosting.UID(a.Number)
	if err != nil {
		return nil, userErr(err.Error())
	}
	if id, ok := h.lookupID(ctx, "passwd", a.Name); ok && id != uid {
		return nil, userErr("the account number does not match the system user")
	}
	units, _ := h.Sys.ReadDir(systemdDir)
	for _, e := range units {
		n := e.Name()
		if strings.HasPrefix(n, "hz-php-"+a.Name+"-") || strings.HasPrefix(n, "hz-cron-"+a.Name+"-") {
			_ = h.systemctl(ctx, "disable", "--now", n)
			_ = h.Sys.Remove(systemdDir + n)
		}
	}
	_ = h.systemctl(ctx, "disable", "--now", hosting.CageUnitName(a.Name))
	_, _ = h.Sys.Run(ctx, nil, "pkill", "-KILL", "-u", a.Name)
	if err := h.cageUnmount(ctx, a.Name); err != nil {
		return nil, err
	}
	for _, f := range []string{systemdDir + hosting.CageUnitName(a.Name), systemdDir + hosting.SliceName(a.Name)} {
		_ = h.Sys.Remove(f)
	}
	_ = h.Sys.RemoveAll(systemdDir + "user-" + strconv.Itoa(uid) + ".slice.d")
	_ = h.systemctl(ctx, "daemon-reload")
	if _, ok := h.lookupID(ctx, "passwd", a.Name); ok {
		if _, err := h.Sys.Run(ctx, nil, "userdel", a.Name); err != nil {
			return nil, err
		}
	}
	if _, ok := h.lookupID(ctx, "group", a.Name); ok {
		_, _ = h.Sys.Run(ctx, nil, "groupdel", a.Name)
	}
	for _, p := range []string{hosting.CageDir(a.Name), hosting.TmpDir(a.Name), hosting.HomeDir(a.Name), hosting.NginxSitesDir + "/" + a.Name, SpoolRoot + "/" + a.Name} {
		if err := h.Sys.RemoveAll(p); err != nil {
			return nil, err
		}
	}
	return map[string]bool{"deleted": true}, nil
}

type passwordArgs struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

// accountPassword sets the SFTP/SSH password (chpasswd hashes it).
func (h *Helper) accountPassword(ctx context.Context, a passwordArgs) (any, error) {
	if err := hosting.ValidAccount(a.Name); err != nil {
		return nil, userErr(err.Error())
	}
	if len(a.Password) < 10 || len(a.Password) > 200 || strings.ContainsAny(a.Password, ":\r\n\x00") {
		return nil, userErr("the password must be 10–200 characters without ':' or line breaks")
	}
	if _, ok := h.lookupID(ctx, "passwd", a.Name); !ok {
		return nil, userErr("no such account")
	}
	if _, err := h.Sys.Run(ctx, []byte(a.Name+":"+a.Password+"\n"), "chpasswd", "-c", "YESCRYPT"); err != nil {
		return nil, errors.New("setting the password failed")
	}
	return nil, nil
}

// CageMount mounts an account's cage (boot unit).
func (h *Helper) CageMount(ctx context.Context, account string) error {
	return h.cageMount(ctx, account)
}

// CageUnmount removes the mounts of an account's cage.
func (h *Helper) CageUnmount(ctx context.Context, account string) error {
	return h.cageUnmount(ctx, account)
}
