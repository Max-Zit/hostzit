package helper

import (
	"context"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/hosting"
)

const suspendedHTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Site unavailable</title>
<style>body{font-family:system-ui,sans-serif;background:#f8fafc;color:#0f172a;display:grid;place-items:center;min-height:100vh;margin:0}main{max-width:32rem;padding:2rem;text-align:center}h1{font-size:1.4rem}</style></head>
<body><main><h1>This website is temporarily unavailable</h1><p>Please try again later. If this is your website, contact your hosting provider.</p></main></body></html>
`

// setup prepares the system once (and again after updates): groups,
// folders, the nginx base configuration and the SSH drop-in.
func (h *Helper) setup(ctx context.Context, _ struct{}) (any, error) {
	for _, g := range []string{"hostzit-web", "hostzit-users", "hostzit-sftponly", "zit-acme"} {
		if _, ok := h.lookupID(ctx, "group", g); !ok {
			if _, err := h.Sys.Run(ctx, nil, "groupadd", "--system", g); err != nil {
				return nil, err
			}
		}
	}
	_, _ = h.Sys.Run(ctx, nil, "usermod", "-a", "-G", "hostzit-web,zit-acme", "www-data")
	_, _ = h.Sys.Run(ctx, nil, "usermod", "-a", "-G", "zit-acme", "hostzit")
	if id, ok := h.lookupID(ctx, "group", h.WebGroup); ok {
		h.WebGID = id
	}
	acme, _ := h.lookupID(ctx, "group", "zit-acme")
	dirs := []struct {
		p        string
		mode     os.FileMode
		uid, gid int
	}{
		{"/var/lib/hostzit/cages", 0o711, 0, 0}, {"/var/lib/hostzit/tmp", 0o711, 0, 0}, {hosting.CertDir, 0o700, 0, 0},
		{"/var/cache/hostzit", 0o755, 0, 0}, {hosting.CacheDir, 0o755, 0, 0}, {"/var/log/hostzit", 0o755, 0, 0}, {hosting.SiteLogDir, 0o755, 0, 0},
		{"/var/lib/zit-acme", 0o755, 0, 0}, {hosting.ACMEChallengeDir, 0o2775, 0, acme},
		{hosting.SuspendedPage, 0o755, 0, 0}, {hosting.NginxSitesDir, 0o755, 0, 0}, {hosting.NginxCacheZones, 0o755, 0, 0}, {"/etc/nginx/zit.d/emailzit", 0o755, 0, 0},
	}
	for _, d := range dirs {
		if err := h.Sys.Mkdir(d.p, d.mode, d.uid, d.gid); err != nil {
			return nil, err
		}
	}
	// site log folders were 0750 before 0.9.1: nginx could not reopen the logs after a rotation
	if list, err := h.Sys.ReadDir(hosting.SiteLogDir); err == nil {
		for _, e := range list {
			if e.IsDir() {
				_ = h.Sys.Mkdir(hosting.SiteLogDir+"/"+e.Name(), 0o755, 0, h.admGID())
			}
		}
	}
	if err := h.Sys.Mkdir(SpoolRoot, 0o711, 0, 0); err != nil {
		return nil, err
	}
	if !h.Sys.Exists("/etc/hostzit/firewall.nft") && h.Sys.Exists("/usr/sbin/nft") {
		if _, err := h.firewall(ctx, firewallArgs{}); err != nil {
			h.logf("firewall: %v", err)
		}
	}
	if err := h.Sys.WriteFile(hosting.SuspendedPage+"/index.html", []byte(suspendedHTML), 0o644, 0, 0); err != nil {
		return nil, err
	}
	// restart PHP of the accounts after package updates (apt hook)
	if h.Sys.Exists("/etc/apt/apt.conf.d") {
		if err := h.Sys.WriteFile(phpRestartHook, []byte(phpRestartHookConf), 0o644, 0, 0); err != nil {
			return nil, err
		}
	}
	_ = h.Sys.Remove("/etc/nginx/sites-enabled/default") // its default_server would clash
	// ModSecurity + OWASP CRS, when the packages are installed: sites switch it on one by one.
	if h.Sys.Exists("/usr/share/modsecurity-crs/rules") && h.Sys.Exists("/etc/modsecurity/crs/crs-setup.conf") {
		if err := h.writeModSec(); err != nil {
			return nil, err
		}
	} else {
		_ = h.Sys.Remove(hosting.ModSecConf)
		_ = h.Sys.Remove(hosting.ModSecDetectConf)
	}
	if h.Sys.Exists("/usr/sbin/nginx") {
		if err := h.nginxApply(ctx, map[string][]byte{"/etc/nginx/conf.d/hostzit.conf": []byte(hosting.NginxBase())}, nil); err != nil {
			return nil, err
		}
	}
	if h.Sys.Exists("/usr/sbin/sshd") {
		if err := h.Sys.WriteFile("/etc/ssh/sshd_config.d/hostzit.conf", []byte(hosting.SSHDConfig()), 0o644, 0, 0); err != nil {
			return nil, err
		}
		if _, err := h.Sys.Run(ctx, nil, "sshd", "-t"); err != nil {
			_ = h.Sys.Remove("/etc/ssh/sshd_config.d/hostzit.conf")
			return nil, err
		}
		_ = h.systemctl(ctx, "reload", "ssh")
	}
	return h.info(ctx, struct{}{})
}

// Info describes the server for the admin panel.
type Info struct {
	PHPVersions []string          `json:"php_versions"`
	PHPFull     map[string]string `json:"php_full"` // "8.4" → "8.4.16" (the installed package)
	Programs    map[string]string `json:"programs"` // name → version ("" = missing)
	Quota       bool              `json:"quota"`
	CgroupV2    bool              `json:"cgroup_v2"`
	Kernel      string            `json:"kernel"`
	OS          string            `json:"os"`
	Uptime      string            `json:"uptime"`
	Load        string            `json:"load"`
	MemTotalMB  int64             `json:"mem_total_mb"`
	MemAvailMB  int64             `json:"mem_avail_mb"`
	Disks       []Disk            `json:"disks"`
	Services    map[string]string `json:"services"` // unit → active state
	WAF         bool              `json:"waf"`      // ModSecurity with the OWASP rules is ready
}

// Disk is the usage of a mounted file system.
type Disk struct {
	Mount  string `json:"mount"`
	SizeMB int64  `json:"size_mb"`
	UsedMB int64  `json:"used_mb"`
}

var verRE = regexp.MustCompile(`[0-9]+\.[0-9]+(\.[0-9]+)?`)

func (h *Helper) info(ctx context.Context, _ struct{}) (any, error) {
	in := Info{Programs: map[string]string{}, Services: map[string]string{}}
	in.WAF = h.Sys.Exists(hosting.ModSecConf)
	ents, _ := h.Sys.ReadDir("/usr/sbin")
	for _, e := range ents {
		if v, ok := strings.CutPrefix(e.Name(), "php-fpm"); ok && hosting.ValidPHPVersion(v) {
			in.PHPVersions = append(in.PHPVersions, v)
		}
	}
	sort.Strings(in.PHPVersions)
	in.PHPFull = map[string]string{}
	for _, v := range in.PHPVersions {
		out, _ := h.Sys.Run(ctx, nil, "dpkg-query", "-W", "-f=${source:Upstream-Version}", "php"+v+"-fpm")
		if full := phpUpstream(string(out), v); full != "" {
			in.PHPFull[v] = full
		}
	}
	// versions of the Debian packages from dpkg: nginx -v and pdns_server
	// --version print to stderr, so the panel showed them as not installed
	// (and never warned when they stopped)
	for name, pkg := range map[string]string{"nginx": "nginx", "mariadb": "mariadb-server", "pdns": "pdns-server"} {
		out, _ := h.Sys.Run(ctx, nil, "dpkg-query", "-W", "-f=${Status}|${source:Upstream-Version}", pkg)
		st, ver, _ := strings.Cut(string(out), "|")
		v := ""
		if strings.HasSuffix(st, " installed") {
			v = verRE.FindString(ver)
		}
		in.Programs[name] = v
	}
	probe := map[string][]string{"wp-cli": {"/usr/local/bin/wp", "--allow-root", "cli", "version"}}
	for name, argv := range probe {
		out, err := h.Sys.Run(ctx, nil, argv[0], argv[1:]...)
		v := verRE.FindString(string(out))
		if v == "" && err != nil {
			v = verRE.FindString(err.Error())
		}
		in.Programs[name] = v
	}
	// quotaon -p prints the state (and exits non-zero when quotas are on)
	if out, _ := h.Sys.Run(ctx, nil, "quotaon", "-p", "-u", "-a"); strings.Contains(string(out), " is on") {
		in.Quota = true
	}
	in.CgroupV2 = h.Sys.Exists("/sys/fs/cgroup/cgroup.controllers")
	if b, err := h.Sys.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		in.Kernel = strings.TrimSpace(string(b))
	}
	if b, err := h.Sys.ReadFile("/etc/os-release"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
				in.OS = strings.Trim(v, `"`)
			}
		}
	}
	if b, err := h.Sys.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			s, _ := strconv.ParseFloat(f[0], 64)
			in.Uptime = (time.Duration(s) * time.Second).Round(time.Minute).String()
		}
	}
	if b, err := h.Sys.ReadFile("/proc/loadavg"); err == nil {
		in.Load = strings.Join(strings.Fields(string(b))[:3], " ")
	}
	if b, err := h.Sys.ReadFile("/proc/meminfo"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if len(f) >= 2 {
				n, _ := strconv.ParseInt(f[1], 10, 64)
				switch f[0] {
				case "MemTotal:":
					in.MemTotalMB = n / 1024
				case "MemAvailable:":
					in.MemAvailMB = n / 1024
				}
			}
		}
	}
	if out, err := h.Sys.Run(ctx, nil, "df", "-P", "-m", "-x", "tmpfs", "-x", "devtmpfs", "-x", "overlay", "-x", "squashfs", "-x", "efivarfs"); err == nil {
		seen := map[string]bool{}
		for _, l := range strings.Split(string(out), "\n")[1:] {
			f := strings.Fields(l)
			if len(f) >= 6 && strings.HasPrefix(f[0], "/dev/") && !strings.HasPrefix(f[5], "/var/lib/hostzit/cages/") && !seen[f[0]] {
				seen[f[0]] = true
				s, _ := strconv.ParseInt(f[1], 10, 64)
				u, _ := strconv.ParseInt(f[2], 10, 64)
				in.Disks = append(in.Disks, Disk{Mount: f[5], SizeMB: s, UsedMB: u})
			}
		}
	}
	for _, u := range serviceList {
		out, _ := h.Sys.Run(ctx, nil, "systemctl", "is-active", u)
		in.Services[u] = strings.TrimSpace(string(out))
	}
	return in, nil
}

// serviceList are the services the admin sees and may restart.
var serviceList = []string{"nginx", "mariadb", "pdns", "ssh", "hostzit-server", "postgresql"}

type serviceArgs struct {
	Name   string `json:"name"`
	Action string `json:"action"` // restart or reload
}

func (h *Helper) service(ctx context.Context, a serviceArgs) (any, error) {
	if !contains(serviceList, a.Name) || a.Name == "hostzit-server" && a.Action != "restart" {
		return nil, userErr("unknown service")
	}
	if a.Action != "restart" && a.Action != "reload" {
		return nil, userErr("unknown action")
	}
	if a.Name == "nginx" {
		if _, err := h.Sys.Run(ctx, nil, "nginx", "-t", "-q"); err != nil {
			return nil, err
		}
	}
	return nil, h.systemctl(ctx, a.Action, a.Name)
}

// Usage is what an account uses right now.
type Usage struct {
	DiskKB    int64 `json:"disk_kb"`
	Inodes    int64 `json:"inodes"`
	QuotaOK   bool  `json:"quota_ok"` // numbers come from the quota system
	MemoryB   int64 `json:"memory_b"`
	CPUUsec   int64 `json:"cpu_usec"` // total CPU time since the slice started
	Tasks     int64 `json:"tasks"`
	IOReadB   int64 `json:"io_read_b"`
	IOWriteB  int64 `json:"io_write_b"`
	MemEvents int64 `json:"mem_oom"` // times the memory limit killed something
	Throttled int64 `json:"throttled_usec"`
}

func readInt(s System, p string) int64 {
	b, err := s.ReadFile(p)
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n
}

func (h *Helper) usage(ctx context.Context, a accountName) (any, error) {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return nil, userErr(err.Error())
	}
	var u Usage
	if out, err := h.Sys.Run(ctx, nil, "quota", "-u", "-w", "-p", "--no-wrap", a.Account); err == nil || len(out) > 0 {
		for _, l := range strings.Split(string(out), "\n") {
			f := strings.Fields(l)
			if len(f) >= 6 && strings.HasPrefix(f[0], "/dev/") {
				blocks, _ := strconv.ParseInt(strings.TrimSuffix(f[1], "*"), 10, 64)
				files, _ := strconv.ParseInt(strings.TrimSuffix(f[5], "*"), 10, 64)
				u.DiskKB += blocks
				u.Inodes += files
				u.QuotaOK = true
			}
		}
	}
	if !u.QuotaOK {
		if out, err := h.Sys.Run(ctx, nil, "du", "-s", "-k", "-x", hosting.HomeDir(a.Account)); err == nil {
			if f := strings.Fields(string(out)); len(f) > 0 {
				u.DiskKB, _ = strconv.ParseInt(f[0], 10, 64)
			}
		}
	}
	cg := "/sys/fs/cgroup/hz.slice/" + hosting.SliceName(a.Account)
	u.MemoryB = readInt(h.Sys, cg+"/memory.current")
	u.Tasks = readInt(h.Sys, cg+"/pids.current")
	if b, err := h.Sys.ReadFile(cg + "/cpu.stat"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if len(f) == 2 {
				n, _ := strconv.ParseInt(f[1], 10, 64)
				switch f[0] {
				case "usage_usec":
					u.CPUUsec = n
				case "throttled_usec":
					u.Throttled = n
				}
			}
		}
	}
	if b, err := h.Sys.ReadFile(cg + "/io.stat"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			for _, kv := range strings.Fields(l) {
				k, v, _ := strings.Cut(kv, "=")
				n, _ := strconv.ParseInt(v, 10, 64)
				switch k {
				case "rbytes":
					u.IOReadB += n
				case "wbytes":
					u.IOWriteB += n
				}
			}
		}
	}
	if b, err := h.Sys.ReadFile(cg + "/memory.events"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "oom_kill "); ok {
				u.MemEvents, _ = strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			}
		}
	}
	return u, nil
}

func (h *Helper) register() {
	h.ops["system.setup"] = op{handle(h.setup), true}
	h.ops["system.info"] = op{handle(h.info), false}
	h.ops["service"] = op{handle(h.service), true}
	h.ops["account.apply"] = op{handle(h.accountApply), true}
	h.ops["account.delete"] = op{handle(h.accountDelete), true}
	h.ops["account.password"] = op{handle(h.accountPassword), false}
	h.ops["account.usage"] = op{handle(h.usage), false}
	h.ops["site.apply"] = op{handle(h.siteApply), true}
	h.ops["site.delete"] = op{handle(h.siteDelete), true}
	h.ops["site.cache.purge"] = op{handle(h.cachePurge), false}
	h.ops["site.log"] = op{handle(h.siteLog), false}
	h.ops["cert.install"] = op{handle(h.certInstall), true}
	h.ops["files"] = op{handle(h.files), false}
	h.ops["db.create"] = op{handle(h.dbCreate), false}
	h.ops["db.drop"] = op{handle(h.dbDrop), false}
	h.ops["db.user"] = op{handle(h.dbUser), false}
	h.ops["db.user.drop"] = op{handle(h.dbUserDrop), false}
	h.ops["db.usage"] = op{handle(h.dbUsage), false}
	h.ops["dns.apply"] = op{handle(h.dnsApply), false}
	h.ops["dns.delete"] = op{handle(h.dnsDelete), false}
	h.ops["dns.dnssec"] = op{handle(h.dnsDNSSEC), false}
	h.registerMore()
}

// modsecConf turns the recommended ModSecurity settings into blocking mode
// with the OWASP Core Rule Set and its WordPress exclusions.
const modsecConf = `# HostZit (generated, do not edit)
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimitAction Reject
SecResponseBodyAccess Off
SecTmpDir /tmp
SecDataDir /tmp
SecArgumentSeparator &
SecCookieFormat 0
SecStatusEngine Off
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogType Serial
SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule REQBODY_ERROR "!@eq 0" "id:200002,phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.'"
SecRequestBodyLimit 268435456
SecRequestBodyNoFilesLimit 1048576
SecAuditEngine RelevantOnly
SecAuditLogParts ABHZ
SecAuditLog /var/log/hostzit/modsec_audit.log
SecAction "id:900130,phase:1,nolog,pass,t:none,setvar:tx.crs_exclusions_wordpress=1"
Include /etc/modsecurity/crs/crs-setup.conf
Include /usr/share/modsecurity-crs/rules/*.conf
`
