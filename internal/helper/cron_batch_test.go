package helper

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
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

func TestWorkerCronScripts(t *testing.T) {
	home := t.TempDir()
	write := func(m map[string]string) error {
		b, _ := json.Marshal(m)
		_, err := workerDo(home, WorkerReq{Op: "cron-scripts", Path: ".hz-cron", Data: b})
		return err
	}
	if err := write(map[string]string{"1.sh": "echo one\n", "2.sh": "echo two\n"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".hz-cron", "notes.txt"), []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := write(map[string]string{"2.sh": "echo TWO\n"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, ".hz-cron", "1.sh")); !os.IsNotExist(err) {
		t.Error("script of a removed job kept")
	}
	if _, err := os.Stat(filepath.Join(home, ".hz-cron", "notes.txt")); err != nil {
		t.Error("an own file of the account was removed")
	}
	fi, err := os.Stat(filepath.Join(home, ".hz-cron", "2.sh"))
	if b, _ := os.ReadFile(filepath.Join(home, ".hz-cron", "2.sh")); err != nil || string(b) != "echo TWO\n" || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o700) {
		t.Fatalf("2.sh: %q %v", b, err)
	}
	for _, bad := range []string{"../x.sh", "a.sh", "1.sh/../../x"} {
		if write(map[string]string{bad: "x"}) == nil {
			t.Errorf("name %q accepted", bad)
		}
	}
	b, _ := json.Marshal(map[string]string{"1.sh": "x"})
	if _, err := workerDo(home, WorkerReq{Op: "cron-scripts", Path: "public", Data: b}); err == nil {
		t.Error("cron-scripts outside .hz-cron")
	}
}
