package web

import (
	"net/http"
	"slices"
	"time"

	"github.com/max-zit/hostzit/internal/hosting"
	"github.com/max-zit/hostzit/internal/store"
)

// Resource usage of all accounts (like CloudLinux's LVE manager): what each
// account uses now and in the last day, and how often its package limits
// held it back.

func init() {
	adminExtra = append(adminExtra, func(s *Server, mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc)) {
		app("GET /resources", s.handleResources)
	})
}

type resourceRow struct {
	C       *store.Customer
	Limits  hosting.Limits
	Now     store.UsageRate
	AvgCPU  float64 // last 24 hours
	PeakCPU float64
	Hits    int
	DiskKB  int64
	Seen    bool
}

type resourcesData struct {
	Rows []resourceRow
	Sort string
}

func (s *Server) handleResources(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	list, err := s.store.Customers(ctx, store.CustomerFilter{})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	all, err := s.store.UsageAll(ctx, s.now().Add(-24*time.Hour))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	limits := map[int64]hosting.Limits{}
	if pk, err := s.store.Packages(ctx); err == nil {
		for _, p := range pk {
			limits[p.ID] = p.Limits
		}
	}
	d := &resourcesData{Sort: r.FormValue("sort")}
	for _, c := range list {
		if c.Status == store.StatusTerminated {
			continue
		}
		row := resourceRow{C: c, Limits: limits[c.PackageID]}
		samples := all[c.ID]
		if n := len(samples); n > 0 {
			row.DiskKB = samples[n-1].DiskKB
		}
		rates := store.Rates(samples)
		if n := len(rates); n > 0 {
			row.Now, row.Seen = rates[n-1], true
			for _, x := range rates {
				row.AvgCPU += x.CPUPercent / float64(n)
				row.PeakCPU = max(row.PeakCPU, x.CPUPercent)
				if x.LimitHit() {
					row.Hits++
				}
			}
		}
		d.Rows = append(d.Rows, row)
	}
	slices.SortStableFunc(d.Rows, func(a, b resourceRow) int {
		switch d.Sort {
		case "memory":
			return cmpDesc(float64(a.Now.MemoryB), float64(b.Now.MemoryB))
		case "disk":
			return cmpDesc(float64(a.DiskKB), float64(b.DiskKB))
		case "io":
			return cmpDesc(a.Now.IOMBps, b.Now.IOMBps)
		case "hits":
			return cmpDesc(float64(a.Hits), float64(b.Hits))
		case "avg":
			return cmpDesc(a.AvgCPU, b.AvgCPU)
		}
		return cmpDesc(a.Now.CPUPercent, b.Now.CPUPercent)
	})
	s.render(w, r, http.StatusOK, "resources", &Page{Title: "Resource usage", Nav: "resources", Data: d})
}

func cmpDesc(a, b float64) int {
	switch {
	case a > b:
		return -1
	case a < b:
		return 1
	}
	return 0
}
