package store

import (
	"testing"
	"time"
)

func TestRates(t *testing.T) {
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	s := []UsageSample{
		{At: t0, CPUUsec: 0, IOB: 0},
		{At: t0.Add(10 * time.Minute), CPUUsec: 300e6, IOB: 600e6, ThrottledUsec: 200e6, OOM: 1},
		{At: t0.Add(20 * time.Minute), CPUUsec: 5e6}, // the control group restarted
		{At: t0.Add(30 * time.Minute), CPUUsec: 65e6},
	}
	r := Rates(s)
	if len(r) != 2 {
		t.Fatalf("rates: %+v", r)
	}
	if r[0].CPUPercent != 50 || r[0].IOMBps != 1 || !r[0].LimitHit() || r[0].OOM != 1 {
		t.Fatalf("first: %+v", r[0])
	}
	if r[1].CPUPercent != 10 || r[1].LimitHit() {
		t.Fatalf("second: %+v", r[1])
	}
}
