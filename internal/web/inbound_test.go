package web

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInboundFirewall(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin()
	conf := func() string {
		b, err := os.ReadFile(filepath.Join(e.root, "etc", "hostzit", "firewall.nft"))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	// a new server is set up with the inbound rule on
	if c := conf(); !strings.Contains(c, "policy drop;") || !strings.Contains(c, "tcp dport { 22, 53, 80, 443, 8442, 8443 } accept") {
		t.Fatalf("after setup:\n%s", c)
	}
	page := a.page("/settings/security")
	if !strings.Contains(page, `name="on" checked`) || strings.Contains(page, "Every port of the server is open") {
		t.Error("security page does not show the rule as on")
	}
	// extra ports, kept in the order of numbers
	a.ok("/settings/security/inbound", url.Values{"on": {"on"}, "tcp": {"8080, 3000 8080"}, "udp": {"51820"}})
	if c := conf(); !strings.Contains(c, "tcp dport { 22, 53, 80, 443, 3000, 8080, 8442, 8443 } accept") || !strings.Contains(c, "udp dport { 53, 51820 } accept") {
		t.Fatalf("extra ports:\n%s", c)
	}
	if in := e.srv.inboundSettings(t.Context()); len(in.TCP) != 2 || in.TCP[0] != 3000 {
		t.Errorf("stored %+v", in)
	}
	// a wrong port changes nothing
	for _, bad := range []string{"0", "65536", "ssh", "22-25"} {
		if st, _, loc := a.post("/settings/security/inbound", url.Values{"on": {"on"}, "tcp": {bad}}); st != http.StatusSeeOther || loc != "/settings/security" {
			t.Errorf("port %q: %d %s", bad, st, loc)
		}
	}
	if in := e.srv.inboundSettings(t.Context()); len(in.TCP) != 2 {
		t.Errorf("a wrong port was stored: %+v", in)
	}
	// off: everything open again, the page warns
	a.ok("/settings/security/inbound", url.Values{"tcp": {""}})
	if c := conf(); !strings.Contains(c, "policy accept;") || strings.Contains(c, "ct state") {
		t.Fatalf("off:\n%s", c)
	}
	if !strings.Contains(a.page("/settings/security"), "Every port of the server is open") {
		t.Error("no warning while the rule is off")
	}
	// blocked addresses still work with the rule on
	a.ok("/settings/security/inbound", url.Values{"on": {"on"}})
	a.ok("/settings/security/blocked", url.Values{"blocked": {"198.51.100.0/24"}})
	if c := conf(); !strings.Contains(c, "198.51.100.0/24") || !strings.Contains(c, "policy drop;") {
		t.Fatalf("blocked + inbound:\n%s", c)
	}
}

func TestParsePorts(t *testing.T) {
	if l, err := parsePorts(" 443,80\n8080 80 "); err != nil || joinInts(l) != "80 443 8080" {
		t.Errorf("%v %v", l, err)
	}
	if l, err := parsePorts(""); err != nil || len(l) != 0 {
		t.Errorf("%v %v", l, err)
	}
}
