package netacl

import (
	"strings"
	"testing"
)

// Allowed networks come from forms and settings files.
func FuzzParse(f *testing.F) {
	f.Add("192.0.2.0/24, 2001:db8::/32 10.0.0.1")
	f.Add("::ffff:1.2.3.4/120 0.0.0.0/0 [::1]:8443")
	f.Fuzz(func(t *testing.T, s string) {
		ps, err := Parse(Split(s))
		if err == nil {
			again, err := Parse(Strings(ps))
			if err != nil || len(again) != len(ps) {
				t.Fatalf("%q → %v → %v (%v)", s, ps, again, err)
			}
			for _, x := range Strings(ps) {
				if strings.ContainsAny(x, " \n\t,") {
					t.Fatalf("network %q", x)
				}
			}
		}
		if a, ok := AddrOf(s); ok && !a.IsValid() {
			t.Fatalf("AddrOf(%q) invalid", s)
		}
	})
}
