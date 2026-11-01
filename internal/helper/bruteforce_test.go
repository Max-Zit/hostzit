package helper

import (
	"strings"
	"testing"
	"time"
)

func TestParseBanIPs(t *testing.T) {
	out := "192.168.101.106 \t2026-11-01 22:20:19 + 1800 = 2026-11-01 22:50:19\nnot a line\n"
	b := parseBanIPs(out, "ssh", time.UTC)
	if len(b) != 1 || b[0].IP != "192.168.101.106" || b[0].Source != "ssh" || b[0].Until.Sub(b[0].Since) != 30*time.Minute {
		t.Fatalf("bans %+v", b)
	}
}

func TestBruteJail(t *testing.T) {
	c, err := bruteArgs{Allow: []string{"203.0.113.9", "198.51.100.0/24"}, MaxRetry: 5, FindMinutes: 15, BanMinutes: 30}.jail()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ignoreip = 127.0.0.1/8 ::1 203.0.113.9/32 198.51.100.0/24", "maxretry = 5", "bantime = 30m", "[sshd]", "[hostzit-wordpress]"} {
		if !strings.Contains(c, want) {
			t.Errorf("missing %q in\n%s", want, c)
		}
	}
	if _, err := (bruteArgs{Allow: []string{"x; rm"}, MaxRetry: 5, FindMinutes: 15, BanMinutes: 30}).jail(); err == nil {
		t.Error("an invalid address was accepted")
	}
}
