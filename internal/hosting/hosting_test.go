package hosting

import (
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
