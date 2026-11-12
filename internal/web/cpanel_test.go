package web

import (
	"strings"
	"testing"
)

func TestCPanelParsers(t *testing.T) {
	m := &cpMeta{Addons: map[string]string{}, DocRoots: map[string]string{}, DBUsers: map[string]cpDBUser{}}
	parseUserdataMain("---\naddon_domains:\n  addon.test: addon.main.test\nmain_domain: main.test\nparked_domains:\n  - alias.test\nsub_domains:\n  - addon.main.test\n  - 'shop.main.test'\n", m)
	if m.Main != "main.test" || m.Addons["addon.test"] != "addon.main.test" || len(m.Parked) != 1 || len(m.Subs) != 2 || m.Subs[1] != "shop.main.test" {
		t.Fatalf("%+v", m)
	}
	parseGrants("GRANT USAGE ON *.* TO 'u_wp'@'localhost' IDENTIFIED BY PASSWORD '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19';\nGRANT ALL PRIVILEGES ON `u\\_wp`.* TO 'u_wp'@'localhost';\nGRANT ALL ON `u\\_x`.* TO 'u_wp'@'%';\nCREATE USER 'u_new'@'localhost' IDENTIFIED WITH 'mysql_native_password' AS '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19';", m)
	if u := m.DBUsers["u_wp"]; u.Hash != "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19" || len(u.DBs) != 1 || u.DBs[0] != "u_wp" {
		t.Fatalf("%+v", m.DBUsers)
	}
	if m.DBUsers["u_new"].Hash == "" {
		t.Fatal("CREATE USER not read")
	}
	zone := "$TTL 14400\nmain.test. 86400 IN SOA ns1.old. admin.old. 1 2 3 4 5\nmain.test. IN NS ns1.old.\nmain.test. IN A 203.0.113.5\nwww 300 IN CNAME main.test.\n\tIN A 203.0.113.5 ; second line of www? no: continuation\nmail IN A 203.0.113.5\nmain.test. IN MX 0 mail.main.test.\nmain.test. IN TXT \"v=spf1 +a ~all\"\nother IN A 198.51.100.1\nold IN LOC 1 2 3\n"
	recs := parseZone(zone, "main.test", "203.0.113.5", "192.0.2.10")
	got := map[string]string{}
	for _, r := range recs {
		got[r.Name+" "+r.Type] = r.Content
	}
	if got["@ A"] != "192.0.2.10" || got["mail A"] != "192.0.2.10" || got["other A"] != "198.51.100.1" || got["www CNAME"] != "main.test." || got["@ MX"] != "0 mail.main.test." || !strings.Contains(got["@ TXT"], "v=spf1") {
		t.Fatalf("%v", got)
	}
	if _, ok := got["@ NS"]; ok {
		t.Fatal("old NS kept")
	}
	if nr, err := newDocRoot("/home/u/public_html/blog", "/home/u", "main.test"); err != nil || nr != "sites/main.test/public/blog" {
		t.Fatal(nr, err)
	}
	if nr, err := newDocRoot("/home/u/addon.test", "/home/u", "main.test"); err != nil || nr != "sites/addon.test" {
		t.Fatal(nr, err)
	}
	if _, err := newDocRoot("/home/u/../../etc", "/home/u", "main.test"); err == nil {
		t.Fatal("traversal accepted")
	}
	if c := rewriteHome("php -q /home/u/public_html/wp-cron.php; /home/u/bin/x", "/home/u", "/home/u", "main.test"); c != "php -q /home/u/sites/main.test/public/wp-cron.php; /home/u/cpanel-home/bin/x" {
		t.Fatal(c)
	}
}

func TestCPanelUser(t *testing.T) {
	for in, want := range map[string]string{
		"cpmove-shop":                                "shop",
		"cpmove-shop.tar.gz":                         "shop",
		"backup-11.12.2026_11-41-01_sportiko":        "sportiko",
		"backup-11.12.2026_11-41-01_sportiko.tar.gz": "sportiko",
		"backup-1.2.2026_9-5-3_ab_c.tgz":             "ab_c",
	} {
		if got, ok := cpanelUser(in); !ok || got != want {
			t.Errorf("%s: %q %v, want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"cpmove-", "site.tar.gz", "backup-x_sportiko", "backup-11.12.2026_11-41-01_../x"} {
		if u, ok := cpanelUser(bad); ok {
			t.Errorf("%s accepted as %q", bad, u)
		}
	}
}
