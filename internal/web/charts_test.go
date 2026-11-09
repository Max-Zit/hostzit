package web

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/max-zit/hostzit/internal/store"
)

func TestDownsampleKeepsPeaks(t *testing.T) {
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	var p []point
	for i := 0; i < 90*144; i++ { // 90 days of 10-minute samples
		v := 10.0
		if i == 5000 {
			v = 999
		}
		p = append(p, point{t0.Add(time.Duration(i) * 10 * time.Minute), v})
	}
	d := downsample(p)
	if len(d) != maxPoints {
		t.Fatalf("%d points", len(d))
	}
	peak := false
	for _, x := range d {
		peak = peak || x.V == 999
	}
	if !peak {
		t.Error("the peak was lost")
	}
	if short := downsample(p[:10]); len(short) != 10 {
		t.Error("short series changed")
	}
}

func TestDrawChart(t *testing.T) {
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	p := []point{{t0, 0}, {t0.Add(time.Hour), 50}, {t0.Add(2 * time.Hour), 100}}
	svg := string(drawChart(p, t0, t0.Add(2*time.Hour), 200))
	for _, want := range []string{`<svg class="chart"`, `<polygon class="area"`, `<polyline points="0.0,118.0 300.0,`, `<line class="limit"`} {
		if !strings.Contains(svg, want) {
			t.Errorf("missing %q in %s", want, svg)
		}
	}
	if drawChart(p[:1], t0, t0.Add(time.Hour), 0) != "" {
		t.Error("a single point drew a graph")
	}
}

func TestUsageHistoryPages(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin()
	ctx := context.Background()
	a.ok("/settings/hosting", url.Values{"mode": {"shared"}, "server_name": {"host1.hostzit.test"}, "ipv4": {"192.0.2.10"}, "nameservers": {"ns1.hostzit.test\nns2.hostzit.test"},
		"default_php": {"8.4"}, "grace_days": {"14"}, "spf": {"v=spf1 a mx ~all"}})
	a.ok("/packages/new", url.Values{"name": {"P"}, "slug": {"p"}, "max_sites": {"3"}, "max_dbs": {"3"}, "max_zones": {"3"}, "disk_mb": {"1000"}, "inodes": {"0"},
		"cpu_percent": {"100"}, "memory_mb": {"512"}, "processes": {"50"}, "io_weight": {"100"}, "php_workers": {"2"}, "php_memory_mb": {"128"}, "upload_mb": {"16"}})
	loc := a.ok("/customers/new", url.Values{"username": {"shop"}, "package": {"1"}, "domain": {"shop.example.com"}, "password": {"shop password 123"}})
	c, _ := e.st.CustomerByRef(ctx, "shop")
	now := time.Now()
	for i := 0; i < 200; i++ { // 33 hours
		at := now.Add(-time.Duration(200-i) * 10 * time.Minute)
		_ = e.st.AddUsage(ctx, c.ID, store.UsageSample{At: at, DiskKB: int64(100+i) * 1024, MemoryB: int64(i) << 20, CPUUsec: int64(i) * 300e6, IOB: int64(i) << 20})
	}
	for _, p := range []string{loc, loc + "?range=1d", loc + "?range=90d"} {
		pg := a.page(p)
		if !strings.Contains(pg, `<svg class="chart"`) || !strings.Contains(pg, "limit 1000 MB") {
			t.Errorf("admin %s: no graph", p)
		}
	}
	if !strings.Contains(a.page(loc+"?range=30d"), `aria-current="page" class="on">30 days`) {
		t.Error("the chosen range is not marked")
	}
	cl := e.client(e.panel.URL)
	cl.ok("/login", url.Values{"username": {"shop"}, "password": {"shop password 123"}})
	pg := cl.page("/usage?range=1d")
	if strings.Count(pg, `<svg class="chart"`) != 4 {
		t.Errorf("customer usage page: %d graphs", strings.Count(pg, `<svg class="chart"`))
	}
	// an unknown range falls back to 7 days
	if !strings.Contains(cl.page("/usage?range=x"), `aria-current="page" class="on">7 days`) {
		t.Error("no fallback range")
	}
}
