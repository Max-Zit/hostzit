package helper

import (
	"strings"
	"testing"

	"github.com/max-zit/hostzit/internal/hosting"
)

// Found in the 0.9.3 scans: with one systemctl call per job (each reloads
// systemd) an account with 70 jobs made every cron change take a minute.
func TestCronApplyBatchesSystemctl(t *testing.T) {
	h, fr, _, _ := newTest(t)
	if r := call(t, h, "account.apply", testAccount()); !r.OK {
		t.Fatal(r.Error)
	}
	var jobs []hosting.CronJob
	for i := int64(1); i <= 50; i++ {
		jobs = append(jobs, hosting.CronJob{ID: i, Schedule: "*/5 * * * *", Command: "php -v", Enabled: i%10 != 0})
	}
	fr.calls = nil
	if r := call(t, h, "cron.apply", cronArgs{Account: "shop", Jobs: jobs}); !r.OK {
		t.Fatal(r.Error)
	}
	var enables, disables int
	for _, c := range fr.calls {
		switch {
		case strings.HasPrefix(c, "systemctl enable --now hz-cron-shop-"):
			enables++
			if n := strings.Count(c, ".timer"); n != 45 {
				t.Errorf("enable call has %d timers, want 45", n)
			}
		case strings.HasPrefix(c, "systemctl disable --now hz-cron-shop-"):
			disables++
			if n := strings.Count(c, ".timer"); n != 5 || !strings.Contains(c, "hz-cron-shop-10.timer") {
				t.Errorf("disable call: %s", c)
			}
		}
	}
	if enables != 1 || disables != 1 {
		t.Fatalf("%d enable and %d disable calls, want 1 each: %v", enables, disables, fr.calls)
	}
}
