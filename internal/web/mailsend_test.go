package web

import (
	"context"
	"net"
	"net/url"
	"strings"
	"testing"
)

// Without EmailZit the websites' mail is sent by HostZit: every domain of
// the account gets a DKIM key, zones here get the record, the helper learns
// the domains, and the customer sees the records and the log.
func TestWebsiteMailDomainsAndDKIM(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := e.setupAdmin()
	a.ok("/settings/hosting", url.Values{"mode": {"shared"}, "server_name": {"host1.hostzit.test"}, "ipv4": {"192.0.2.10"}, "nameservers": {"ns1.hostzit.test\nns2.hostzit.test"},
		"default_php": {"8.4"}, "grace_days": {"14"}, "spf": {"v=spf1 a mx ~all"}})
	a.ok("/packages/new", url.Values{"name": {"P"}, "slug": {"p"}, "max_sites": {"3"}, "max_dbs": {"3"}, "max_zones": {"3"}, "disk_mb": {"1000"}, "inodes": {"0"},
		"cpu_percent": {"100"}, "memory_mb": {"512"}, "processes": {"50"}, "io_weight": {"100"}, "php_workers": {"2"}, "php_memory_mb": {"128"}, "upload_mb": {"16"}, "mail_per_hour": {"50"}})
	a.ok("/customers/new", url.Values{"username": {"shop"}, "package": {"1"}, "domain": {"shop.example.com"}, "dns": {"on"}, "password": {"shop password 123"}, "email": {"s@example.com"}})
	c, _ := e.st.CustomerByRef(ctx, "shop")
	if m := e.srv.mailMode(ctx); m != "direct" {
		t.Fatal(m)
	}
	keys, err := e.st.DKIMKeys(ctx, c.ID)
	if err != nil || len(keys) != 1 || keys[0].Domain != "shop.example.com" || !strings.HasPrefix(keys[0].Record, "v=DKIM1; k=rsa; p=") || !strings.Contains(keys[0].PrivateKey, "PRIVATE KEY") {
		t.Fatalf("keys %+v %v", keys, err)
	}
	z, _ := e.st.ZoneFor(ctx, "shop.example.com")
	rows, _ := e.st.Records(ctx, z.ID)
	found := false
	for _, r := range rows {
		found = found || r.Owner == dkimOwner && r.Name == "hz1._domainkey" && r.Type == "TXT"
	}
	if !found {
		t.Fatalf("no DKIM record in the zone: %+v", rows)
	}
	if !e.hp.called(`mail.account {"account":"shop","mail":{"primary":"shop.example.com","domains":["shop.example.com"]`) {
		t.Fatal("the helper does not know the mail domains")
	}
	// the key stays, and a second sync does not publish the zone again
	e.hp.mu.Lock()
	e.hp.calls = nil
	e.hp.mu.Unlock()
	e.srv.syncMailAccount(ctx, "test", c)
	if k2, _ := e.st.DKIMKeys(ctx, c.ID); len(k2) != 1 || k2[0].Record != keys[0].Record {
		t.Fatal("the key changed")
	}
	if e.hp.called("dns.apply") {
		t.Fatal("an unchanged DKIM record published the zone again")
	}
	// the customer sees the record and the (empty) log
	p := e.client(e.panel.URL)
	p.ok("/login", url.Values{"username": {"shop"}, "password": {"shop password 123"}})
	page := p.page("/security")
	if !strings.Contains(page, "hz1._domainkey.shop.example.com") || !strings.Contains(page, "set by HostZit") {
		t.Fatal("no DKIM row on the security page")
	}
	// the admin's mail settings show the way website mail leaves
	if !strings.Contains(a.page("/settings/mail"), "HostZit delivers the websites") {
		t.Fatal("no website mail section")
	}
	if !strings.Contains(a.page("/settings/emailzit"), "Pairing code") {
		t.Fatal("no pairing form")
	}
}

func TestKeyDomainAndProxy(t *testing.T) {
	zones := []string{"example.com"}
	for in, want := range map[string]string{"shop.example.com": "example.com", "example.com": "example.com", "www.other.net": "other.net", "other.net": "other.net", "www.co": "www.co"} {
		if got := keyDomain(in, zones); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
	if !behindProxy(net.ParseIP("104.16.1.1")) || !behindProxy(net.ParseIP("2606:4700::1")) || behindProxy(net.ParseIP("192.0.2.10")) {
		t.Fatal("proxy ranges")
	}
}
