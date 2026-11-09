package web

import (
	"context"
	"net/http"
	"net/url"
	"testing"
)

// A package can require two-factor sign-in of its customers.
func TestPackageRequires2FA(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin()
	a.ok("/settings/hosting", url.Values{"mode": {"shared"}, "server_name": {"host1.hostzit.test"}, "ipv4": {"192.0.2.10"}, "nameservers": {"ns1.hostzit.test\nns2.hostzit.test"},
		"default_php": {"8.4"}, "grace_days": {"14"}, "spf": {"v=spf1 a mx ~all"}})
	pkg := url.Values{"max_sites": {"1"}, "max_dbs": {"1"}, "max_zones": {"1"}, "disk_mb": {"100"}, "inodes": {"0"}, "cpu_percent": {"100"}, "memory_mb": {"512"},
		"processes": {"50"}, "io_weight": {"100"}, "php_workers": {"2"}, "php_memory_mb": {"128"}, "upload_mb": {"16"}}
	plain, strict := url.Values{}, url.Values{}
	for k, v := range pkg {
		plain[k], strict[k] = v, v
	}
	plain.Set("name", "Plain")
	plain.Set("slug", "plain")
	strict.Set("name", "Strict")
	strict.Set("slug", "strict")
	strict.Set("two_factor", "on")
	a.ok("/packages/new", plain)
	a.ok("/packages/new", strict)
	l, err := e.st.Packages(context.Background())
	if err != nil || len(l) != 2 {
		t.Fatal(l, err)
	}
	ids := map[string]string{}
	for _, p := range l {
		ids[p.Slug] = itoa(p.ID)
		if p.Limits.TwoFactor != (p.Slug == "strict") {
			t.Errorf("package %s: two_factor %v", p.Slug, p.Limits.TwoFactor)
		}
	}
	a.ok("/customers/new", url.Values{"username": {"easy"}, "package": {ids["plain"]}, "domain": {"easy.example.com"}, "password": {"easy password 123"}})
	a.ok("/customers/new", url.Values{"username": {"safe"}, "package": {ids["strict"]}, "domain": {"safe.example.com"}, "password": {"safe password 123"}})
	e.srv.DevNo2FA = false
	for _, c := range []struct{ user, pw, want string }{
		{"easy", "easy password 123", "/"},
		{"safe", "safe password 123", "/login/enroll?next=%2F"},
	} {
		cl := e.client(e.panel.URL)
		st, _, loc := cl.post("/login", url.Values{"username": {c.user}, "password": {c.pw}})
		if st != http.StatusSeeOther || loc != c.want {
			t.Errorf("%s: %d %s, want %s", c.user, st, loc, c.want)
		}
	}
}
