package hosting

import "testing"

func TestCPanelUser(t *testing.T) {
	for in, want := range map[string]string{
		"cpmove-shop":                                "shop",
		"cpmove-shop.tar.gz":                         "shop",
		"backup-11.12.2026_11-41-01_sportiko":        "sportiko",
		"backup-11.12.2026_11-41-01_sportiko.tar.gz": "sportiko",
		"backup-1.2.2026_9-5-3_ab_c.tgz":             "ab_c",
	} {
		if got, ok := CPanelUser(in); !ok || got != want {
			t.Errorf("%s: %q %v, want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"cpmove-", "cpmove-../x", "site.tar.gz", "backup-x_sportiko", "backup-11.12.2026_11-41-01_../x"} {
		if u, ok := CPanelUser(bad); ok {
			t.Errorf("%s accepted as %q", bad, u)
		}
	}
}

func TestCPanelPHP(t *testing.T) {
	for in, want := range map[string]string{"ea-php81": "8.1", "alt-php74": "7.4", " ea-php56 ": "5.6", "inherit": "", "ea-php8": "", "ea-php810": ""} {
		if got := CPanelPHP(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
