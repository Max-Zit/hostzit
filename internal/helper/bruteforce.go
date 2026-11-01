package helper

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Brute-force protection like cPanel's cPHulk: the panels block addresses
// themselves (web package); fail2ban blocks SSH/SFTP and WordPress sign-in
// floods with the same limits. The panel writes the jails here and lists
// and lifts fail2ban's bans.

const (
	f2bJail   = "/etc/fail2ban/jail.d/hostzit.conf"
	f2bFilter = "/etc/fail2ban/filter.d/hostzit-wordpress.conf"
	// WPJail is the fail2ban jail of the WordPress sign-in floods.
	WPJail = "hostzit-wordpress"
)

// f2bJails are the jails the panel shows, with the source it names.
var f2bJails = map[string]string{"sshd": "ssh", WPJail: "wordpress"}

// the WordPress sign-in page and XML-RPC answer 429 when nginx's limit
// (10 a minute per address) is reached; each 429 counts as a failure
const wpFilter = `# HostZit: requests over the sign-in limit of WordPress (written by the panel)
[Definition]
failregex = ^<HOST> - \[[^\]]*\] "(?:GET|POST) /(?:wp-login\.php|xmlrpc\.php)[^"]*" 429
datepattern = ^[^\[]*\[({DATE})
`

type bruteArgs struct {
	Allow       []string `json:"allow"`        // never blocked (addresses or networks)
	MaxRetry    int      `json:"max_retry"`    // failures …
	FindMinutes int      `json:"find_minutes"` // … within this many minutes
	BanMinutes  int      `json:"ban_minutes"`  // first block; doubles when repeated
}

func (a bruteArgs) jail() (string, error) {
	if a.MaxRetry < 1 || a.MaxRetry > 100 || a.FindMinutes < 1 || a.FindMinutes > 1440 || a.BanMinutes < 1 || a.BanMinutes > 10080 {
		return "", userErr("invalid limits")
	}
	ignore := []string{"127.0.0.1/8", "::1"}
	for _, s := range a.Allow {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			ad, err2 := netip.ParseAddr(s)
			if err2 != nil {
				return "", userErr(fmt.Sprintf("invalid address %q", s))
			}
			p = netip.PrefixFrom(ad, ad.BitLen())
		}
		ignore = append(ignore, p.Masked().String())
	}
	var b strings.Builder
	b.WriteString("# HostZit: brute-force protection (written by the panel, Settings → Brute-force protection)\n[DEFAULT]\n")
	fmt.Fprintf(&b, "ignoreip = %s\nmaxretry = %d\nfindtime = %dm\nbantime = %dm\n", strings.Join(ignore, " "), a.MaxRetry, a.FindMinutes, a.BanMinutes)
	b.WriteString("bantime.increment = true\nbantime.maxtime = 7d\n\n[sshd]\nenabled = true\n\n")
	fmt.Fprintf(&b, "[%s]\nenabled = true\nfilter = %s\nlogpath = /var/log/hostzit/sites/*/access.log\nbackend = polling\nport = http,https\n", WPJail, WPJail)
	return b.String(), nil
}

// bruteApply writes the jails and reloads fail2ban.
func (h *Helper) bruteApply(ctx context.Context, a bruteArgs) (any, error) {
	conf, err := a.jail()
	if err != nil {
		return nil, err
	}
	if !h.Sys.Exists("/usr/bin/fail2ban-client") {
		return nil, userErr("fail2ban is not installed")
	}
	if err := h.Sys.WriteFile(f2bFilter, []byte(wpFilter), 0o644, 0, 0); err != nil {
		return nil, err
	}
	if err := h.Sys.WriteFile(f2bJail, []byte(conf), 0o644, 0, 0); err != nil {
		return nil, err
	}
	if out, err := h.Sys.Run(ctx, nil, "systemctl", "reload-or-restart", "fail2ban"); err != nil {
		return nil, userErr("fail2ban did not accept the settings: " + tail(string(out)+" "+err.Error(), 300))
	}
	return nil, nil
}

// F2BBan is an address fail2ban blocks.
type F2BBan struct {
	IP     string    `json:"ip"`
	Source string    `json:"source"` // ssh | wordpress
	Since  time.Time `json:"since"`
	Until  time.Time `json:"until"`
}

// parseBanIPs reads "fail2ban-client get JAIL banip --with-time":
// "198.51.100.7 \t2026-11-01 22:00:00 + 600 = 2026-11-01 22:10:00".
func parseBanIPs(out, source string, loc *time.Location) []F2BBan {
	var res []F2BBan
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 8 || f[3] != "+" || f[5] != "=" {
			continue
		}
		if _, err := netip.ParseAddr(f[0]); err != nil {
			continue
		}
		since, err1 := time.ParseInLocation("2006-01-02 15:04:05", f[1]+" "+f[2], loc)
		until, err2 := time.ParseInLocation("2006-01-02 15:04:05", f[6]+" "+f[7], loc)
		if err1 != nil || err2 != nil {
			continue
		}
		res = append(res, F2BBan{IP: f[0], Source: source, Since: since, Until: until})
	}
	return res
}

// bruteList lists fail2ban's bans of the panel's jails.
func (h *Helper) bruteList(ctx context.Context, _ struct{}) (any, error) {
	res := []F2BBan{}
	if !h.Sys.Exists("/usr/bin/fail2ban-client") {
		return res, nil
	}
	jails := make([]string, 0, len(f2bJails))
	for j := range f2bJails {
		jails = append(jails, j)
	}
	sort.Strings(jails)
	for _, j := range jails {
		out, err := h.Sys.Run(ctx, nil, "fail2ban-client", "get", j, "banip", "--with-time")
		if err != nil {
			continue // jail not running
		}
		res = append(res, parseBanIPs(string(out), f2bJails[j], time.Local)...)
	}
	return res, nil
}

type unbanArgs struct {
	IP string `json:"ip"`
}

// bruteUnban lifts every fail2ban ban of an address.
func (h *Helper) bruteUnban(ctx context.Context, a unbanArgs) (any, error) {
	if _, err := netip.ParseAddr(a.IP); err != nil {
		return nil, userErr("not an IP address")
	}
	if _, err := h.Sys.Run(ctx, nil, "fail2ban-client", "unban", a.IP); err != nil {
		return nil, err
	}
	return nil, nil
}

// bruteNewLog lets the WordPress jail watch a site's new log (fail2ban
// expands the log path pattern only when the jail starts).
func (h *Helper) bruteNewLog(ctx context.Context) {
	if h.Sys.Exists(f2bJail) {
		_, _ = h.Sys.Run(ctx, nil, "fail2ban-client", "reload", WPJail)
	}
}

func init() {
	moreOps = append(moreOps, func(h *Helper) {
		h.ops["bruteforce.apply"] = op{handle(h.bruteApply), false}
		h.ops["bruteforce.list"] = op{handle(h.bruteList), false}
		h.ops["bruteforce.unban"] = op{handle(h.bruteUnban), false}
	})
}
