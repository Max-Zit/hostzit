package helper

import (
	"strings"
	"testing"
)

func TestGeoNft(t *testing.T) {
	c := GeoNft(geoFirewallArgs{Mode: "allow", List: []string{"RS"}, Ports: []int{22, 8442}, Allow: []string{"203.0.113.9"}}, []string{"77.46.0.0/15"}, []string{"2a02:2b8::/32"})
	for _, want := range []string{"table inet hostzit_geo {", "tcp dport != { 22, 8442 } accept", "203.0.113.9", "192.168.0.0/16", "elements = { 77.46.0.0/15 }",
		"ip saddr != @geo4 drop", "ip6 saddr != @geo6 drop"} {
		if !strings.Contains(c, want) {
			t.Errorf("missing %q in\n%s", want, c)
		}
	}
	if b := GeoNft(geoFirewallArgs{Mode: "block", List: []string{"@AS"}, Ports: []int{22}}, nil, nil); !strings.Contains(b, "ip saddr @geo4 drop") || strings.Contains(b, "!= @geo4") {
		t.Errorf("block rule:\n%s", b)
	}
}
