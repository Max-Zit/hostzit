package web

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/max-zit/hostzit/internal/hosting"
)

// Fuzz targets for what reaches the panel from outside: cPanel and HostZit
// archives (import, transfer between servers), forms (redirects,
// environment, firewall rules), redirects after sign-in and API bodies.
// They need no database (testdb skips PostgreSQL while fuzzing).

func FuzzCPanelMeta(f *testing.F) {
	f.Add("main_domain: example.com\naddon_domains:\n  shop.example: shop.example.com\nparked_domains:\n  - example.net\nsub_domains:\n  - blog.example.com\n",
		"GRANT USAGE ON *.* TO 'u'@'localhost' IDENTIFIED BY PASSWORD '*0123456789ABCDEF0123456789ABCDEF01234567';\nGRANT ALL PRIVILEGES ON `u\\_wp`.* TO 'u_wp'@'localhost';\nCREATE USER 'u_x'@'localhost' IDENTIFIED WITH 'mysql_native_password' AS '*0123456789ABCDEF0123456789ABCDEF01234567';")
	f.Add("---\n'main_domain': \"x\"\n- a\n", "GRANT ALL ON `a`.* TO 'b'@'%';")
	f.Fuzz(func(t *testing.T, userdata, grants string) {
		m := &cpMeta{Addons: map[string]string{}, DocRoots: map[string]string{}, DBUsers: map[string]cpDBUser{}, Zones: map[string]string{}}
		parseUserdataMain(userdata, m)
		parseGrants(grants, m)
		for name, u := range m.DBUsers {
			if strings.ContainsAny(name, "'") {
				t.Fatalf("user name %q with a quote", name)
			}
			for _, d := range u.DBs {
				if strings.ContainsAny(d, "`.") {
					t.Fatalf("database name %q", d)
				}
			}
		}
		// the import maps document roots into sites/ only
		for _, old := range []string{m.Main, "/home/u/" + m.Main} {
			if p, err := newDocRoot(old, "/home/u", "example.com"); err == nil {
				if !strings.HasPrefix(p, "sites/") || strings.Contains(p, "..") {
					t.Fatalf("document root %q → %q", old, p)
				}
			}
		}
	})
}

func FuzzCPanelZone(f *testing.F) {
	f.Add("$TTL 14400\n$ORIGIN example.com.\n@ IN SOA ns1 h 1 2 3 4 5\n@ 14400 IN A 192.0.2.10\nwww IN CNAME example.com.\n  IN MX 0 mail\n_dmarc IN TXT \"v=DMARC1; p=none\" ; comment\nftp.example.com. IN A 192.0.2.10\n", "192.0.2.10", "198.51.100.1")
	f.Add("x 0 IN TXT \"a;b\"\n\tIN AAAA ::1\n$INCLUDE /etc/passwd\n", "", "")
	f.Fuzz(func(t *testing.T, text, oldIP, newIP string) {
		for _, r := range parseZone(text, "example.com", oldIP, newIP) {
			if strings.ContainsAny(r.Name+r.Content, "\r\n\x00") {
				t.Fatalf("record %+v", r)
			}
			r2, err := hosting.CleanRecord(r, "example.com")
			if err != nil || r2 != r {
				t.Fatalf("imported record %+v not stable: %+v %v", r, r2, err)
			}
		}
	})
}

// FuzzHostZitManifest decodes the manifest of a HostZit archive (an import
// or an account moved from another server) and runs the checks the import
// relies on.
func FuzzHostZitManifest(f *testing.F) {
	f.Add(`{"product":"hostzit","customer":{"username":"shop"},"package":"basic","sites":[{"account":"shop","id":1,"domain":"example.com","doc_root":"sites/example.com/public","php_version":"8.4","upload_mb":64}],"zones":{"example.com":[{"name":"www","type":"A","ttl":3600,"content":"192.0.2.1","owner":"x"}]},"cron":[{"schedule":"*/5 * * * *","command":"php x.php"}],"git":[{"name":"site","branch":"main","target":"sites/example.com/public","remote":"https://example.org/r.git"}],"apps":[{"name":"api","kind":"node","root":"apps/api","command":"node server.js","enabled":true}],"php":{"8.4":{"ini":{"memory_limit":"256M"}}}}`)
	f.Add(`{"product":"hostzit","sites":[{"domain":"a b"}],"zones":{"":[{}]},"db_users":{"x":["y"]}}`)
	f.Fuzz(func(t *testing.T, raw string) {
		var m Manifest
		if json.Unmarshal([]byte(raw), &m) != nil {
			return
		}
		for _, x := range m.Sites {
			x.Account, x.ID = "shop", 1
			if x.Validate() == nil {
				if _, err := hosting.NginxSite(x); err != nil {
					t.Fatalf("valid imported site not rendered: %v", err)
				}
			}
		}
		for zone, recs := range m.Zones {
			if n, err := hosting.NormalizeDomain(zone); err == nil {
				for _, r := range recs {
					if c, err := hosting.CleanRecord(r, n); err == nil && strings.ContainsAny(c.Content, "\r\n\x00") {
						t.Fatalf("record %+v", c)
					}
				}
			}
		}
		for _, j := range m.Cron {
			if _, err := hosting.OnCalendar(j.Schedule); err == nil && hosting.CheckCommand(j.Command) == nil {
				j.ID = 1
				if _, _, err := hosting.CronUnits("shop", j); err != nil {
					t.Fatalf("valid imported job not rendered: %v", err)
				}
			}
		}
		for _, g := range m.Git {
			if g.Validate() == nil && !strings.HasPrefix(g.Target, "sites/") {
				t.Fatalf("git target %q", g.Target)
			}
		}
		for _, a := range m.Apps {
			_ = a.App.Validate()
		}
		for _, cmd := range []string{"cd /home/old/public_html && php x", "/home/old/../../etc"} {
			_ = rewriteHome(cmd, "/home/"+m.Customer["username"], "/home/shop", "example.com")
		}
	})
}

func FuzzSiteForms(f *testing.F) {
	f.Add("/old /new\n/a https://example.org/b 302\n", "NODE_ENV=production\n# c\nA = b=c", "949110, 920350\n")
	f.Fuzz(func(t *testing.T, redirects, env, rules string) {
		if rd, err := parseRedirects(redirects); err == nil {
			s := hosting.Site{Account: "shop", ID: 1, Domain: "example.com", DocRoot: "sites/example.com/public", PHPVersion: "8.4", UploadMB: 64, Redirects: rd}
			if s.Validate() == nil {
				conf, err := hosting.NginxSite(s)
				if err != nil || strings.Count(conf, "{") != strings.Count(conf, "}") {
					t.Fatalf("redirects %q: %v", redirects, err)
				}
			}
		}
		e := parseEnv(env)
		for k, v := range e {
			if strings.ContainsAny(k+v, "\n") {
				t.Fatalf("env %q=%q", k, v)
			}
		}
		_ = hosting.App{Name: "api", Kind: "node", Root: "apps/api", Command: "node s.js", Env: e}.Validate()
		if ids, err := parseRuleIDs(rules); err == nil {
			for _, id := range ids {
				if id < 1 || id > 99999999 {
					t.Fatalf("rule %d", id)
				}
			}
		}
	})
}

func FuzzSafeNext(f *testing.F) {
	for _, s := range []string{"/sites/3", "//evil.example", "/\\evil.example", "/\t/evil.example", "https://evil.example", "/%2F%2Fevil", "/backups?x=1#y", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		n := safeNext(p)
		if !strings.HasPrefix(n, "/") || strings.HasPrefix(n, "//") || strings.HasPrefix(n, "/\\") {
			t.Fatalf("%q → %q", p, n)
		}
		// browsers drop tabs and newlines and read \ as /
		b := strings.NewReplacer("\t", "", "\n", "", "\r", "", "\\", "/").Replace(n)
		if u, err := url.Parse(b); err == nil && (u.Host != "" || u.Scheme != "") {
			t.Fatalf("%q → %q leaves the panel", p, n)
		}
	})
}

// FuzzAPIBodies decodes request bodies of the REST API the way the
// handlers do (size limit, unknown fields refused).
func FuzzAPIBodies(f *testing.F) {
	f.Add(`{"username":"shop","package":"basic","email":"a@example.com","domain":"example.com","dns":true}`)
	f.Add(`{"customer_id":"x","records":[{"name":"mail","type":"A","content":"192.0.2.1"}]}`)
	f.Add(`{"username":"a","username":"b","x":1}`)
	f.Fuzz(func(t *testing.T, body string) {
		var c apiCreate
		if readJSON(httptest.NewRequest("POST", "/api/v1/customers", strings.NewReader(body)), &c) == nil {
			_ = hosting.ValidAccount(c.Username)
			_, _ = hosting.NormalizeDomain(c.Domain)
		}
		var in struct {
			CustomerID string           `json:"customer_id"`
			Records    []hosting.Record `json:"records"`
		}
		if readJSON(httptest.NewRequest("PUT", "/api/v1/zones/example.com/owned/emailzit", strings.NewReader(body)), &in) == nil {
			for _, r := range in.Records {
				r.Owner = "emailzit"
				if c, err := hosting.CleanRecord(r, "example.com"); err == nil {
					_ = hosting.AllowedForEmailZit(c)
				}
			}
		}
	})
}
