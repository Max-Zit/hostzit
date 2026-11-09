package web

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type fakeResolver struct {
	txt map[string][]string
	ip  map[string][]net.IPAddr
	ns  map[string][]*net.NS
}

var errNoRecord = errors.New("no such host")

func (f *fakeResolver) LookupTXT(_ context.Context, n string) ([]string, error) {
	if v, ok := f.txt[n]; ok {
		return v, nil
	}
	return nil, errNoRecord
}

func (f *fakeResolver) LookupIPAddr(_ context.Context, n string) ([]net.IPAddr, error) {
	if v, ok := f.ip[n]; ok {
		return v, nil
	}
	return nil, errNoRecord
}

func (f *fakeResolver) LookupNS(_ context.Context, n string) ([]*net.NS, error) {
	if v, ok := f.ns[n]; ok {
		return v, nil
	}
	return nil, errNoRecord
}

func TestDomainOwnershipCheck(t *testing.T) {
	fr := &fakeResolver{txt: map[string][]string{}, ip: map[string][]net.IPAddr{}, ns: map[string][]*net.NS{}}
	old := domainResolver
	domainResolver = fr
	t.Cleanup(func() { domainResolver = old })

	e := newEnv(t)
	a := e.setupAdmin()
	ctx := context.Background()
	a.ok("/settings/hosting", url.Values{"mode": {"shared"}, "server_name": {"host1.hostzit.test"}, "ipv4": {"192.0.2.10"}, "nameservers": {"ns1.hostzit.test\nns2.hostzit.test"},
		"default_php": {"8.4"}, "grace_days": {"14"}, "spf": {"v=spf1 a mx ~all"}})
	a.ok("/packages/new", url.Values{"name": {"P"}, "slug": {"p"}, "max_sites": {"9"}, "max_dbs": {"1"}, "max_zones": {"9"}, "disk_mb": {"100"}, "inodes": {"0"},
		"cpu_percent": {"100"}, "memory_mb": {"512"}, "processes": {"50"}, "io_weight": {"100"}, "php_workers": {"2"}, "php_memory_mb": {"128"}, "upload_mb": {"16"}})
	// the administrator adds any domain, also with the check on
	x := DefaultSecurity
	x.DomainCheck = true
	if err := e.st.SetSetting(ctx, settingSecurity, x); err != nil {
		t.Fatal(err)
	}
	a.ok("/customers/new", url.Values{"username": {"shop"}, "package": {"1"}, "domain": {"shop.example.com"}, "dns": {"on"}, "password": {"shop password 123"}})
	c := e.client(e.panel.URL)
	c.ok("/login", url.Values{"username": {"shop"}, "password": {"shop password 123"}})

	addSite := func(dom string) (int, string) {
		st, body, _ := c.post("/sites/new", url.Values{"domain": {dom}})
		return st, body
	}
	// unknown domain: refused, the page tells how to prove it
	st, body := addSite("www.google.com")
	if st != http.StatusBadRequest || !strings.Contains(body, "_hostzit-verify.www.google.com") || !strings.Contains(body, "hostzit-verify=") || !strings.Contains(body, "192.0.2.10") {
		t.Fatalf("unproven domain: %d\n%s", st, body)
	}
	cust, err := e.st.CustomerByRef(ctx, "shop")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := e.srv.domainToken(ctx, cust, "proven.example.org")
	if err != nil {
		t.Fatal(err)
	}
	// the token is the same every time and differs per domain
	if t2, _ := e.srv.domainToken(ctx, cust, "proven.example.org"); t2 != tok {
		t.Fatal("token changes")
	}
	if t3, _ := e.srv.domainToken(ctx, cust, "other.example.org"); t3 == tok {
		t.Fatal("same token for two domains")
	}
	// a wrong token does not help
	fr.txt["_hostzit-verify.proven.example.org"] = []string{"hostzit-verify=0000"}
	if st, _ := addSite("proven.example.org"); st != http.StatusBadRequest {
		t.Fatalf("wrong token accepted: %d", st)
	}
	fr.txt["_hostzit-verify.proven.example.org"] = []string{"v=spf1 -all", tok}
	if st, body := addSite("proven.example.org"); st != http.StatusSeeOther {
		t.Fatalf("TXT proof: %d\n%s", st, body)
	}
	// pointing at the server proves it too
	fr.ip["pointed.example.net"] = []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}}
	if st, _ := addSite("pointed.example.net"); st != http.StatusSeeOther {
		t.Fatalf("A record proof: %d", st)
	}
	fr.ip["elsewhere.example.net"] = []net.IPAddr{{IP: net.ParseIP("198.51.100.7")}}
	if st, _ := addSite("elsewhere.example.net"); st != http.StatusBadRequest {
		t.Fatalf("A record of another server accepted: %d", st)
	}
	// so do this server's name servers (all of them)
	fr.ns["delegated.example.net"] = []*net.NS{{Host: "NS1.hostzit.test."}, {Host: "ns2.hostzit.test."}}
	if st, _ := addSite("delegated.example.net"); st != http.StatusSeeOther {
		t.Fatalf("NS proof: %d", st)
	}
	fr.ns["half.example.net"] = []*net.NS{{Host: "ns1.hostzit.test."}, {Host: "ns.other.example."}}
	if st, _ := addSite("half.example.net"); st != http.StatusBadRequest {
		t.Fatalf("partly delegated accepted: %d", st)
	}
	// names below the customer's own zone need no proof
	if st, _ := addSite("blog.shop.example.com"); st != http.StatusSeeOther {
		t.Fatalf("subdomain of own zone: %d", st)
	}
	// DNS zones are checked the same way
	if st, _, loc := c.post("/dns", url.Values{"zone": {"stranger.example"}}); st != http.StatusSeeOther || loc != "/dns" {
		t.Fatalf("zone without proof: %d %s", st, loc)
	}
	if z, err := e.st.ZoneByName(ctx, "stranger.example"); err == nil {
		t.Fatalf("zone created without proof: %v", z)
	}
	// off: everything goes, as before
	x.DomainCheck = false
	_ = e.st.SetSetting(ctx, settingSecurity, x)
	if st, _ := addSite("anything.example.io"); st != http.StatusSeeOther {
		t.Fatalf("check off: %d", st)
	}
}
