package helper

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFirewallConfOpenByDefault(t *testing.T) {
	c := FirewallConf([]string{"198.51.100.0/24", "2001:db8::/32"}, nil)
	for _, want := range []string{"policy accept;", "elements = { 198.51.100.0/24 }", "elements = { 2001:db8::/32 }", "ip saddr @blocked4 drop",
		"tcp dport { 25, 465, 587 } counter reject"} {
		if !strings.Contains(c, want) {
			t.Errorf("missing %q in\n%s", want, c)
		}
	}
	if strings.Contains(c, "policy drop") || strings.Contains(c, "ct state") {
		t.Errorf("default-deny without inbound rule:\n%s", c)
	}
}

func TestFirewallConfInbound(t *testing.T) {
	c := FirewallConf(nil, &Inbound{TCP: []int{22, 53, 80, 443, 8442, 8443}, UDP: []int{53}})
	in := c[strings.Index(c, "chain input"):strings.Index(c, "chain output")]
	for _, want := range []string{"policy drop;", "iif lo accept", "ct state established,related accept", "meta l4proto { icmp, ipv6-icmp } accept",
		"tcp dport { 22, 53, 80, 443, 8442, 8443 } accept", "udp dport { 53 } accept", "udp dport { 68, 546 } accept"} {
		if !strings.Contains(in, want) {
			t.Errorf("missing %q in\n%s", want, in)
		}
	}
	// blocked addresses are dropped before anything is accepted
	if strings.Index(in, "@blocked4 drop") > strings.Index(in, "iif lo accept") {
		t.Errorf("blocked addresses after the accept rules:\n%s", in)
	}
}

func TestFirewallOpPorts(t *testing.T) {
	h, fr, _, _ := newTest(t)
	ctx := context.Background()
	r, err := h.firewall(ctx, firewallArgs{Inbound: true, TCP: []int{8443, 8442, 443, 3000}, UDP: []int{51820}})
	if err != nil {
		t.Fatal(err)
	}
	res := r.(firewallResult)
	if got := joinPorts(res.TCP); got != "22, 53, 80, 443, 3000, 8442, 8443" {
		t.Errorf("tcp %s", got)
	}
	if got := joinPorts(res.UDP); got != "53, 51820" {
		t.Errorf("udp %s", got)
	}
	if !fr.has("nft -f /etc/hostzit/firewall.nft") {
		t.Error(fr.calls)
	}
	for _, bad := range [][]int{{0}, {65536}, {-1}} {
		if _, err := h.firewall(ctx, firewallArgs{Inbound: true, TCP: bad}); err == nil {
			t.Errorf("port %v accepted", bad)
		}
	}
	// off: no port list, policy accept
	if r, err := h.firewall(ctx, firewallArgs{}); err != nil || r.(firewallResult).Inbound || len(r.(firewallResult).TCP) != 0 {
		t.Fatal(r, err)
	}
}

func TestParseSSHDPorts(t *testing.T) {
	got := parseSSHDPorts([]byte("port 2222\nport 22\nlistenaddress 0.0.0.0:2222\npermitrootlogin no\nport x\n"))
	if joinPorts(got) != "2222, 22" {
		t.Errorf("%v", got)
	}
}

// With EmailZit on the server its mail and panel ports stay open.
func TestFirewallKeepsEmailZitPorts(t *testing.T) {
	h, _, root, _ := newTest(t)
	full := filepath.Join(root, filepath.FromSlash(emailzitMarker))
	_ = os.MkdirAll(filepath.Dir(full), 0o755)
	if err := os.WriteFile(full, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := h.firewall(context.Background(), firewallArgs{Inbound: true, TCP: []int{8442, 8443}})
	if err != nil {
		t.Fatal(err)
	}
	if got := joinPorts(r.(firewallResult).TCP); got != "22, 25, 53, 80, 443, 465, 587, 993, 995, 8442, 8443, 8444" {
		t.Errorf("tcp %s", got)
	}
}
