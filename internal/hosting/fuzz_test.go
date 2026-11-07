package hosting

import (
	"strings"
	"testing"
)

// Fuzz targets for the checks of everything customers, imported archives
// and other servers hand in: DNS records, web server settings, Git
// repositories, paths, cron jobs and PHP options. CI runs each for a short
// while (see .github/workflows/ci.yml).

func noControl(t *testing.T, what, s string) {
	t.Helper()
	if strings.ContainsAny(s, "\r\n\x00") {
		t.Fatalf("%s holds a line break or NUL: %q", what, s)
	}
}

func FuzzCleanRecord(f *testing.F) {
	for _, s := range [][3]string{
		{"www", "A", "192.0.2.1"}, {"@", "MX", "10 mail.example.com."}, {"_dmarc", "TXT", `"v=DMARC1; p=none"`},
		{"*.dev", "CNAME", "example.org."}, {"_sip._tcp", "SRV", "10 5 5060 sip.example.com."}, {"@", "CAA", `0 issue "letsencrypt.org"`},
		{"x", "AAAA", "2001:db8::1"}, {"a.example.com.", "TXT", "plain text"}, {"", "HTTPS", `1 . alpn="h2"`},
	} {
		f.Add(s[0], s[1], s[2], 3600)
	}
	f.Fuzz(func(t *testing.T, name, typ, content string, ttl int) {
		r, err := CleanRecord(Record{Name: name, Type: typ, TTL: ttl, Content: content}, "example.com")
		if err != nil {
			return
		}
		noControl(t, "name", r.Name)
		noControl(t, "content", r.Content)
		if r.TTL < 60 || r.TTL > 604800 {
			t.Fatalf("TTL %d accepted", r.TTL)
		}
		// stored records are cleaned again (restore, transfer): the result
		// must not change
		r2, err := CleanRecord(r, "example.com")
		if err != nil {
			t.Fatalf("clean record refused on the second pass: %v (%+v)", err, r)
		}
		if r2 != r {
			t.Fatalf("clean record not stable: %+v → %+v", r, r2)
		}
	})
}

func FuzzNginxSite(f *testing.F) {
	f.Add("example.com", "shop.example.com", "sites/example.com/public", "/old", "/new", 301, "192.0.2.0/24", "/private", "admin", "block", "RS @AS", 949110)
	f.Add("xn--bcher-kva.example", "", "sites/a", "/a", "https://example.org/b?x=1#y", 302, "", "", "", "", "", 0)
	f.Fuzz(func(t *testing.T, domain, alias, docroot, from, to string, code int, ipallow, protPath, user, geoMode, geoList string, waf int) {
		s := Site{Account: "shopuser", ID: 7, Domain: domain, DocRoot: docroot, PHPVersion: "8.4", UploadMB: 64,
			WWW: true, ForceHTTPS: true, HSTS: true, TLS: true, Cache: true, CacheMinutes: 60, WordPress: true, BlockXMLRPC: true,
			Hotlink: true, WAF: waf != 0, GeoMode: geoMode, GeoReady: true}
		if alias != "" {
			s.Aliases = []string{alias}
		}
		if from != "" || to != "" {
			s.Redirects = []Redirect{{From: from, To: to, Code: code}}
		}
		if ipallow != "" {
			s.IPAllow = []string{ipallow}
		}
		if waf != 0 {
			s.WAFExclude = []int{waf}
		}
		if protPath != "" {
			s.Protected = []Protected{{Path: protPath, Users: []HTUser{{Name: user, Hash: "$2a$10$" + strings.Repeat("a", 53)}}}}
		}
		if geoList != "" {
			s.GeoList = strings.Fields(geoList)
		}
		if s.Validate() != nil {
			return
		}
		conf, err := NginxSite(s)
		if err != nil {
			t.Fatalf("valid site not rendered: %v", err)
		}
		if strings.ContainsAny(conf, "\r\x00") {
			t.Fatal("config holds CR or NUL")
		}
		// a value of the site must never open or close a block or end a
		// directive early: the braces stay balanced
		if strings.Count(conf, "{") != strings.Count(conf, "}") {
			t.Fatalf("unbalanced braces in the config of %+v", s)
		}
		used := append([]string{s.Domain, s.DocRoot}, s.Aliases...)
		for _, r := range s.Redirects {
			used = append(used, r.From, r.To)
		}
		used = append(used, s.IPAllow...)
		for _, p := range s.Protected {
			used = append(used, p.Path, p.Users[0].Name)
		}
		for _, v := range used {
			noControl(t, "site value", v)
			if strings.ContainsAny(v, "{};\"'` \t") {
				t.Fatalf("value %q with nginx syntax characters was written into the config", v)
			}
		}
		if _, err := CacheZoneConf(s); err != nil {
			t.Fatalf("cache zone: %v", err)
		}
	})
}

func FuzzGitRepo(f *testing.F) {
	f.Add("site", "main", "sites/example.com/public", "https://github.com/acme/site.git")
	f.Add("app.v2", "release/1.0", "sites/a/b", "https://user:token@git.example.com/x.git")
	f.Fuzz(func(t *testing.T, name, branch, target, remote string) {
		g := GitRepo{Name: name, Branch: branch, Target: target, Remote: remote}
		if g.Validate() != nil {
			return
		}
		// the hook and the deploy script are shell scripts with the name,
		// branch and target written in: no shell syntax may get through
		for _, v := range []string{g.Name, g.Branch, g.Target} {
			if strings.ContainsAny(v, " \t\r\n\x00'\"`$;&|<>()\\*?[]{}~#") {
				t.Fatalf("shell character in %q", v)
			}
			if strings.HasPrefix(v, "-") {
				t.Fatalf("option-like value %q", v)
			}
		}
		if strings.Contains(g.Target, "..") || !strings.HasPrefix(g.Target, "sites/") {
			t.Fatalf("target %q outside sites/", g.Target)
		}
		if g.Remote != "" && (!strings.HasPrefix(g.Remote, "https://") || strings.ContainsAny(g.Remote, " \t\r\n\x00")) {
			t.Fatalf("remote %q", g.Remote)
		}
		_ = GitHook("shopuser", g)
		_ = GitDeployScript("shopuser", g)
	})
}

func FuzzCleanRelPath(f *testing.F) {
	for _, s := range []string{"sites/example.com/public", "../etc/passwd", "a/./b//c", `a\..\b`, "/abs", "a/\x00b", ".hz-import/x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		c, err := CleanRelPath(p)
		if err != nil {
			return
		}
		for _, seg := range strings.Split(c, "/") {
			if seg == ".." || (c != "" && seg == "") || seg == "." {
				t.Fatalf("%q → %q leaves the account", p, c)
			}
		}
		if strings.HasPrefix(c, "/") || strings.ContainsAny(c, "\\\x00\r\n") {
			t.Fatalf("%q → %q", p, c)
		}
		if c2, err := CleanRelPath(c); err != nil || c2 != c {
			t.Fatalf("not stable: %q → %q → %q (%v)", p, c, c2, err)
		}
	})
}

func FuzzCron(f *testing.F) {
	for _, s := range []string{"*/15 * * * *", "0 3 * * 1-5", "30 2 1,15 * *", "@daily", "0 0 31 2 7", "*/0 * * * *"} {
		f.Add(s, "php ~/sites/example.com/public/cron.php")
	}
	f.Fuzz(func(t *testing.T, sched, cmd string) {
		cal, err := OnCalendar(sched)
		if err == nil {
			noControl(t, "calendar", cal)
		}
		if CheckCommand(cmd) != nil || err != nil {
			return
		}
		svc, tmr, err := CronUnits("shopuser", CronJob{ID: 3, Schedule: sched, Command: cmd, Enabled: true})
		if err != nil {
			t.Fatalf("valid job not rendered: %v", err)
		}
		// the schedule must not add lines (directives) to the timer unit
		if n := strings.Count(tmr, "\n"); n != strings.Count(mustTimer(t), "\n") {
			t.Fatalf("schedule %q changed the timer unit:\n%s", sched, tmr)
		}
		_ = svc
	})
}

func mustTimer(t *testing.T) string {
	_, tmr, err := CronUnits("shopuser", CronJob{ID: 3, Schedule: "* * * * *", Command: "true", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	return tmr
}

func FuzzCleanINI(f *testing.F) {
	for _, k := range INIKeys {
		f.Add(k.Name, "256M")
		f.Add(k.Name, "On")
	}
	f.Add("date.timezone", "Europe/Belgrade\nauto_prepend_file=/etc/passwd")
	l := Limits{PHPMemoryMB: 512, UploadMB: 256}
	f.Fuzz(func(t *testing.T, name, v string) {
		c, err := CleanINI(name, v, l)
		if err != nil {
			return
		}
		noControl(t, "ini value", c)
		if strings.ContainsAny(c, "\"';") {
			t.Fatalf("%s = %q", name, c)
		}
		o := PHPOptions{INI: map[string]string{name: c}}
		if o.Validate(l) != nil {
			t.Fatalf("cleaned value %s=%q refused", name, c)
		}
	})
}

func FuzzDomainNames(f *testing.F) {
	for _, s := range []string{"example.com", "Bücher.example", "a..b", "-x.com", "x.com.", "localhost", strings.Repeat("a.", 130) + "com"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, d string) {
		n, err := NormalizeDomain(d)
		if err == nil {
			noControl(t, "domain", n)
			if strings.ContainsAny(n, " /\\{};'\"`$") {
				t.Fatalf("%q → %q", d, n)
			}
		}
		if ValidDomain(d) && strings.ContainsAny(d, " /\\{};'\"`$\r\n\x00") {
			t.Fatalf("ValidDomain(%q)", d)
		}
		_ = ValidAccount(d)
		_ = ValidDatabase("shopuser", d)
		_ = ValidGeo("block", strings.Fields(d))
		if nets, err := CleanNets(strings.Fields(d)); err == nil {
			for _, x := range nets {
				noControl(t, "net", x)
			}
		}
	})
}

// Found by FuzzCleanRecord: a quoted TXT with an escaped quote was escaped
// again on every save, and a long run of backslashes never got split.
func TestTXTStable(t *testing.T) {
	for _, in := range []string{`"a\"b"`, `"v=spf1 -all" "x"`, strings.Repeat(`\`, 300), `"` + strings.Repeat("x", 300) + `"`} {
		r, err := CleanRecord(Record{Name: "t", Type: "TXT", Content: in}, "example.com")
		if err != nil {
			t.Fatal(err)
		}
		r2, err := CleanRecord(r, "example.com")
		if err != nil || r2.Content != r.Content {
			t.Fatalf("%q → %q → %q (%v)", in, r.Content, r2.Content, err)
		}
		if !quotedChunks(r.Content) {
			t.Fatalf("%q → %q is not valid quoted text", in, r.Content)
		}
	}
	if _, err := CleanRecord(Record{Name: "t", Type: "CAA", Content: "0 issue \"x\x00\""}, "example.com"); err == nil {
		t.Fatal("NUL accepted")
	}
}
