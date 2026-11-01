package hosting

import (
	"fmt"
	"strings"
	"testing"
)

func TestValidAccount(t *testing.T) {
	for _, ok := range []string{"abc", "shop1", "a234567890123456"[:16]} {
		if err := ValidAccount(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "ab", "1abc", "Abc", "ab-c", "ab_c", "a2345678901234567", "root", "mysql", "abc\n", "abc ", "../x", "ab$c", "hostzit"} {
		if ValidAccount(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"Example.COM":      "example.com",
		"example.com.":     "example.com",
		" shop.example.rs": "shop.example.rs",
		"žurka.rs":         "xn--urka-kbb.rs",
		"xn--urka-kbb.rs":  "xn--urka-kbb.rs",
		"a-b.co.uk":        "a-b.co.uk",
	}
	for in, want := range cases {
		got, err := NormalizeDomain(in)
		if err != nil || got != want {
			t.Errorf("%q → %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "localhost", "example", "-a.com", "a-.com", "a..com", "*.example.com", "exa mple.com", "example.com;", "example.com\nserver_name x", "ex$ample.com",
		"example.c", "example.123", "a/b.com", "a\\b.com", "x.com{", "x'.com", "x\".com", strings.Repeat("a", 64) + ".com", "_dmarc.example.com", "example.com:80"} {
		if got, err := NormalizeDomain(bad); err == nil {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
}

func TestDatabaseName(t *testing.T) {
	if n, err := DatabaseName("shop", "wp"); err != nil || n != "shop_wp" {
		t.Fatal(n, err)
	}
	if n, err := DatabaseName("shop", "shop_wp"); err != nil || n != "shop_wp" {
		t.Fatal(n, err)
	}
	for _, bad := range []string{"", "wp-1", "wp;drop", "wp`", "wp'", "a b", strings.Repeat("x", 33)} {
		if _, err := DatabaseName("shop", bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if !ValidDatabase("shop", "shop_wp") || ValidDatabase("shop", "other_wp") || ValidDatabase("shop", "shop_") {
		t.Fatal("ValidDatabase")
	}
}

func TestCleanRelPath(t *testing.T) {
	good := map[string]string{"": "", "/": "", "sites/a.com/public": "sites/a.com/public", "/sites//x/./y/": "sites/x/y", "a\\b": "a/b", "My File (1).txt": "My File (1).txt"}
	for in, want := range good {
		if got, err := CleanRelPath(in); err != nil || got != want {
			t.Errorf("%q → %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"..", "a/../b", "../../etc/passwd", "a/\x00b", "a/\nb", "a/$(x)", "a/`x`", "a/b;c", "a/b|c", "a/*", "a/b'c", "a/b\"c"} {
		if got, err := CleanRelPath(bad); err == nil {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
}

func testSite() Site {
	return Site{ID: 7, Account: "shop", Domain: "shop.example.com", Aliases: []string{"shop2.example.com"}, DocRoot: "sites/shop.example.com/public",
		PHPVersion: "8.4", WWW: true, Canonical: "bare", WordPress: true, UploadMB: 64}
}

func TestSiteValidate(t *testing.T) {
	if err := testSite().Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []func(*Site){
		func(s *Site) { s.Domain = "a.com;evil" },
		func(s *Site) { s.Aliases = []string{"x.com\n}"} },
		func(s *Site) { s.Aliases = []string{"shop.example.com"} },
		func(s *Site) { s.DocRoot = "../other/sites" },
		func(s *Site) { s.DocRoot = "/home/other" },
		func(s *Site) { s.DocRoot = "public" },
		func(s *Site) { s.DocRoot = "sites/a;b" },
		func(s *Site) { s.PHPVersion = "8.4;" },
		func(s *Site) { s.Canonical = "www"; s.WWW = false },
		func(s *Site) { s.Cache = true; s.CacheMinutes = 0 },
		func(s *Site) { s.Redirects = []Redirect{{From: "/a;", To: "/b", Code: 301}} },
		func(s *Site) { s.Redirects = []Redirect{{From: "/a", To: "/b; return 200 x", Code: 301}} },
		func(s *Site) { s.Redirects = []Redirect{{From: "/a", To: "javascript:alert(1)", Code: 301}} },
		func(s *Site) { s.Redirects = []Redirect{{From: "/a", To: "/b", Code: 200}} },
		func(s *Site) { s.Redirects = []Redirect{{From: "/../x", To: "/b", Code: 301}} },
		func(s *Site) { s.Account = "Root" },
	}
	for i, f := range bad {
		s := testSite()
		f(&s)
		if s.Validate() == nil {
			t.Errorf("case %d accepted: %+v", i, s)
		}
		if _, err := NginxSite(s); err == nil {
			t.Errorf("case %d rendered", i)
		}
	}
}

func TestNginxSite(t *testing.T) {
	s := testSite()
	out, err := NginxSite(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"server_name shop.example.com www.shop.example.com shop2.example.com;", "root /home/shop/sites/shop.example.com/public;",
		"disable_symlinks if_not_owner", "fastcgi_pass unix:/var/lib/hostzit/cages/shop/.sock/php84.sock;", "/.well-known/acme-challenge/", "deny all;",
		"if ($host = www.shop.example.com)", "client_max_body_size 64m;"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "listen 443") || strings.Contains(out, "fastcgi_cache ") {
		t.Fatal("TLS or cache without being asked for")
	}
	s.TLS, s.ForceHTTPS, s.HSTS, s.Cache, s.CacheMinutes = true, true, true, true, 60
	s.Redirects = []Redirect{{From: "/old", To: "https://shop.example.com/new?a=1", Code: 301}}
	out, err = NginxSite(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"listen 443 ssl;", "listen 443 quic;", "http2 on;", "ssl_certificate /var/lib/hostzit/certs/7/fullchain.pem;", "return 301 https://$host$request_uri;",
		"Strict-Transport-Security", "fastcgi_cache hz7;", "fastcgi_cache_valid 200 301 302 60m;", "fastcgi_no_cache $hz_nocache;", "wordpress_logged_in", "location = /old {"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	// braces must balance (a broken file would stop nginx for everyone)
	if strings.Count(out, "{") != strings.Count(out, "}") {
		t.Fatal("unbalanced braces")
	}
	z, err := CacheZoneConf(s)
	if err != nil || !strings.Contains(z, "keys_zone=hz7:512k") || !strings.Contains(z, "/var/cache/hostzit/pages/7 ") {
		t.Fatal(z, err)
	}
	s.Suspended = true
	out, _ = NginxSite(s)
	if strings.Contains(out, "fastcgi_pass") || !strings.Contains(out, SuspendedPage) {
		t.Fatal("suspended site still runs PHP")
	}
}

func testAccount() Account {
	return Account{Name: "shop", Number: 12, PHPVersions: []string{"8.4"}, Limits: Limits{DiskMB: 5000, CPUPercent: 100, MemoryMB: 1024, IOWeight: 100, Processes: 100, PHPWorkers: 8, PHPMemoryMB: 256, UploadMB: 64}}
}

func TestFPM(t *testing.T) {
	a := testAccount()
	c, err := FPMConf(a, "8.4")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[shop]", "listen = /.sock/php84.sock", "pm.max_children = 8", "open_basedir] = /home/shop/:/tmp/", "disable_functions] = exec,", "memory_limit] = 256M"} {
		if !strings.Contains(c, want) {
			t.Errorf("missing %q", want)
		}
	}
	a.Limits.AllowExec = true
	c, _ = FPMConf(a, "8.4")
	if strings.Contains(c, "disable_functions") {
		t.Fatal("exec allowed but still disabled")
	}
	u, err := FPMUnit(a, "8.4")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"User=shop", "RootDirectory=/var/lib/hostzit/cages/shop", "Slice=hz-shop.slice", "ProtectProc=invisible", "NoNewPrivileges=yes", "CapabilityBoundingSet=\n", "ExecStart=/usr/sbin/php-fpm8.4 --nodaemonize --fpm-config /.hz/php-fpm-84.conf"} {
		if !strings.Contains(u, want) {
			t.Errorf("missing %q", want)
		}
	}
	sl, _ := SliceUnit(a)
	for _, want := range []string{"CPUQuota=100%", "MemoryMax=1024M", "MemoryHigh=921M", "TasksMax=100", "IOWeight=100"} {
		if !strings.Contains(sl, want) {
			t.Errorf("missing %q", want)
		}
	}
	if _, err := FPMConf(a, "8.4\n[x]"); err == nil {
		t.Fatal("bad version accepted")
	}
	a.Name = "x;y"
	if _, err := FPMUnit(a, "8.4"); err == nil {
		t.Fatal("bad account accepted")
	}
}

func TestLimits(t *testing.T) {
	if err := testAccount().Limits.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := DedicatedLimits().Validate(); err != nil {
		t.Fatal(err)
	}
	l := testAccount().Limits
	l.MemoryMB = 10
	if l.Validate() == nil {
		t.Fatal("10 MB memory accepted")
	}
}

func TestCageFiles(t *testing.T) {
	a := testAccount()
	p, err := CagePasswd(a)
	if err != nil || !strings.Contains(p, "shop:x:1000012:1000012::/home/shop:/usr/sbin/nologin") || strings.Count(p, "\n") != 3 {
		t.Fatal(p, err)
	}
	a.Limits.SSH = true
	p, _ = CagePasswd(a)
	if !strings.Contains(p, ":/bin/bash") {
		t.Fatal(p)
	}
	for _, m := range CageMounts("shop") {
		if m.Target == "/home" || strings.HasPrefix(m.Source, "/home/") && m.Source != "/home/shop" {
			t.Fatalf("cage exposes %s", m.Source)
		}
		if strings.HasPrefix(m.Source, "/etc/") && !m.ReadOnly {
			t.Fatalf("%s writable", m.Source)
		}
	}
}

func TestOnCalendar(t *testing.T) {
	cases := map[string]string{
		"*/15 * * * *":    "*-*-* *:0/15:00",
		"0 3 * * *":       "*-*-* 3:0:00",
		"30 2 * * 1-5":    "Mon..Fri *-*-* 2:30:00",
		"0 0 1 * *":       "*-*-1 0:0:00",
		"@daily":          "*-*-* 0:0:00",
		"5,35 8-18 * * *": "*-*-* 8..18:5,35:00",
		"0 4 * * 0":       "Sun *-*-* 4:0:00",
	}
	for in, want := range cases {
		if got, err := OnCalendar(in); err != nil || got != want {
			t.Errorf("%q → %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "* * * *", "61 * * * *", "* 24 * * *", "a b c d e", "* * * * 1/2", "*/0 * * * *", "* * * * *\nExecStart=/bin/sh", "0 0 32 * *"} {
		if got, err := OnCalendar(bad); err == nil {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
	s, tm, err := CronUnits("shop", CronJob{ID: 4, Schedule: "*/5 * * * *", Command: "php x.php"})
	if err != nil || !strings.Contains(s, "ExecStart=/bin/bash /home/shop/.hz-cron/4.sh") || !strings.Contains(s, "RootDirectory=/var/lib/hostzit/cages/shop") || !strings.Contains(tm, "OnCalendar=*-*-* *:0/5:00") {
		t.Fatal(s, tm, err)
	}
	if strings.Contains(s, "php x.php") {
		t.Fatal("the command reached the unit file")
	}
}

func TestNginxSecurity(t *testing.T) {
	s := testSite()
	s.IPAllow = []string{"192.0.2.0/24", "2001:db8::1"}
	s.IPDeny = []string{"192.0.2.66"}
	s.Hotlink, s.WAF, s.WAFDetect, s.WAFExclude = true, true, true, []int{942100, 949110}
	s.Protected = []Protected{{Path: "/private", Users: []HTUser{{Name: "ana", Hash: "$2a$10$abcdefghijklmnopqrstuuJ3Wq0x8m2Qe3OQ9cRkDuB6m4bkLQ8Wq"}}}}
	out, err := NginxSite(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"allow 192.0.2.0/24;", "allow 2001:db8::1;", "deny 192.0.2.66;", "deny all;", "modsecurity on;", "modsecurity_rules_file /etc/nginx/zit.d/hostzit/modsec-detect.conf;", "modsecurity_rules 'SecRuleRemoveById 942100 949110';", "valid_referers none blocked server_names;",
		"location = /wp-login.php {\n        limit_req zone=hz_login", "location ^~ /private/ {", "auth_basic_user_file /etc/nginx/zit.d/hostzit/auth/7-0.htpasswd;", "            fastcgi_pass unix:"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Count(out, "{") != strings.Count(out, "}") {
		t.Fatal("unbalanced braces")
	}
	for i, bad := range []func(*Site){
		func(s *Site) { s.IPAllow = []string{"1.2.3.4; allow all"} },
		func(s *Site) { s.IPDeny = []string{"10.0.0.0/33"} },
		func(s *Site) {
			s.Protected = []Protected{{Path: "/p", Users: []HTUser{{Name: "a:b", Hash: s.Protected[0].Users[0].Hash}}}}
		},
		func(s *Site) { s.Protected = []Protected{{Path: "/p {", Users: s.Protected[0].Users}} },
		func(s *Site) { s.Protected = []Protected{{Path: "/p", Users: []HTUser{{Name: "a", Hash: "plain"}}}} },
		func(s *Site) { s.Protected = []Protected{{Path: "/p"}} },
	} {
		x := s
		bad(&x)
		if x.Validate() == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if n, err := CleanNets([]string{" 10.1.2.3/8 ", "", "::1"}); err != nil || strings.Join(n, ",") != "10.0.0.0/8,::1" {
		t.Fatal(n, err)
	}
	if !strings.Contains(NginxBase(), "limit_req_zone $binary_remote_addr zone=hz_login") {
		t.Fatal("base without the login limit")
	}
}

func TestPHPOptions(t *testing.T) {
	l := Limits{PHPMemoryMB: 256, UploadMB: 64, PHPWorkers: 4, DiskMB: 100}
	if _, err := CleanINI("memory_limit", "512M", l); err == nil {
		t.Fatal("memory above the package accepted")
	}
	if _, err := CleanINI("disable_functions", "", l); err == nil {
		t.Fatal("a key outside the allow-list accepted")
	}
	if v, err := CleanINI("display_errors", "1", l); err != nil || v != "on" {
		t.Fatalf("bool: %q %v", v, err)
	}
	if v, err := CleanINI("upload_max_filesize", "32", l); err != nil || v != "32M" {
		t.Fatalf("size: %q %v", v, err)
	}
	a := Account{Name: "shop", Number: 5, PHPVersions: []string{"8.4"}, Limits: l,
		PHP: map[string]PHPOptions{"8.4": {Disabled: []string{"imagick"}, INI: map[string]string{"memory_limit": "128M", "display_errors": "on"}}}}
	conf, err := FPMConf(a, "8.4")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(conf, "php_flag[display_errors] = on\nphp_admin_value[memory_limit] = 128M\n") || strings.Count(conf, "[memory_limit]") != 1 {
		t.Fatalf("pool:\n%s", conf)
	}
	unit, _ := FPMUnit(a, "8.4")
	if !strings.Contains(unit, "Environment=PHP_INI_SCAN_DIR=/.hz/php84.d\n") {
		t.Fatal("no scan dir in the unit")
	}
	a.PHP["8.4"] = PHPOptions{Disabled: []string{"../x"}}
	if err := a.Validate(); err == nil {
		t.Fatal("bad extension name accepted")
	}
}

func TestGitRepo(t *testing.T) {
	ok := GitRepo{Name: "shop", Branch: "main", Target: "sites/shop.test/public", Remote: "https://u:tok@github.com/me/shop.git"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []GitRepo{
		{Name: "Shop", Branch: "main", Target: "sites/a"}, {Name: "a", Branch: "-x", Target: "sites/a"}, {Name: "a", Branch: "a..b", Target: "sites/a"},
		{Name: "a", Branch: "main", Target: "backups"}, {Name: "a", Branch: "main", Target: "sites/a b"}, {Name: "a", Branch: "main", Target: "sites/$(x)"},
		{Name: "a", Branch: "main", Target: "sites/a", Remote: "ext::sh -c x"}, {Name: "a", Branch: "main", Target: "sites/a", Remote: "file:///etc"},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if s := GitDeployScript("shop", ok); !strings.Contains(s, "checkout -f main") || !strings.Contains(s, "work=/home/shop/sites/shop.test/public") {
		t.Fatal(s)
	}
}

func TestApps(t *testing.T) {
	a := Account{Name: "shop", Number: 5, Limits: Limits{PHPWorkers: 4, PHPMemoryMB: 128, UploadMB: 32, Apps: 2},
		Apps: []App{{Name: "api", Kind: "node", Root: "apps/api", Command: `node server.js --name "x"`, Env: map[string]string{"DB_PASS": `p$a"s%s`}}}}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	u, err := AppUnit(a, a.Apps[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`ExecStart=/bin/sh -c "exec node server.js --name \"x\""`, `Environment="DB_PASS=p$$a\"s%%s"`, "PORT=/.sock/app-api.sock", "WorkingDirectory=/home/shop/apps/api",
		"SocketBindDeny=any", "RootDirectory=/var/lib/hostzit/cages/shop", "NODE_ENV=production"} {
		if !strings.Contains(u, want) {
			t.Errorf("missing %q in\n%s", want, u)
		}
	}
	for _, bad := range []App{{Name: "Api", Kind: "node", Root: "a", Command: "x"}, {Name: "a", Kind: "ruby", Root: "a", Command: "x"}, {Name: "a", Kind: "node", Root: "../x", Command: "x"},
		{Name: "a", Kind: "node", Root: "a", Command: "x\nrm"}, {Name: "a", Kind: "node", Root: "a", Command: "x", Env: map[string]string{"PATH": "/x"}}} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	s := testSite()
	s.App = "api"
	out, err := NginxSite(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "proxy_pass http://unix:/var/lib/hostzit/cages/"+s.Account+"/.sock/app-api.sock:;") || strings.Contains(out, "fastcgi_pass") {
		t.Fatal(out)
	}
}

func TestNginxSiteGeo(t *testing.T) {
	s := testSite()
	s.GeoMode, s.GeoList, s.GeoReady = "allow", []string{"RS", "@EU"}, true
	out, err := NginxSite(s)
	if err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprint(s.ID)
	for _, want := range []string{`map "$hz_ct:$hz_cc" $hz_geo_` + id + ` {`, "default 1;", `"~^--:--$" 0;`, `"~:RS$" 0;`, `"~^EU:" 0;`,
		"set $hz_geo $hz_geo_" + id + ";", "if ($hz_geo) {", `acme-challenge/") {`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	s.GeoReady = false
	if out, _ := NginxSite(s); strings.Contains(out, "hz_geo") {
		t.Error("country rule without the country database")
	}
	if ValidGeo("block", []string{"rs"}) == nil || ValidGeo("allow", nil) == nil || ValidGeo("x", []string{"RS"}) == nil || ValidGeo("block", []string{"@EU", "US"}) != nil {
		t.Error("ValidGeo")
	}
}
