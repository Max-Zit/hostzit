package web

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/max-zit/hostzit/internal/helper"
	"github.com/max-zit/hostzit/internal/store"
)

// Visitor statistics of a website (GoAccess over the access logs of the
// last month), kept for an hour.

func init() {
	customerExtra = append(customerExtra, func(s *Server, mux *http.ServeMux, c func(string, http.HandlerFunc)) {
		c("GET /sites/{id}/stats", s.handleSiteStats)
		c("POST /sites/{id}/stats", s.handleSiteStatsRefresh)
	})
}

// cachedStats is a report and when it was made.
type cachedStats struct {
	At    time.Time        `json:"at"`
	Stats helper.SiteStats `json:"stats"`
}

func statsKey(id int64) string { return "stats:" + strconv.FormatInt(id, 10) }

var statsBusy sync.Map

func (s *Server) refreshStats(ctx context.Context, by string, c *store.Customer, x *store.Site) error {
	if _, busy := statsBusy.LoadOrStore(x.ID, true); busy {
		return nil
	}
	defer statsBusy.Delete(x.ID)
	var st helper.SiteStats
	if err := s.call(ctx, by, "site.stats", map[string]any{"account": c.Username, "id": x.ID}, &st); err != nil {
		return err
	}
	return s.store.SetSetting(ctx, statsKey(x.ID), cachedStats{At: s.now(), Stats: st})
}

type statsData struct {
	S      *store.Site
	At     time.Time
	St     helper.SiteStats
	Busy   bool
	Visits []int64 // per day, for the sparkline
	MaxDay int64
}

func (s *Server) handleSiteStats(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	x := s.mySite(w, r, c)
	if x == nil {
		return
	}
	var cs cachedStats
	p := &Page{Title: x.Domain, Nav: "sites", Customer: c, Crumb: "Websites", CrumbURL: "/sites"}
	if s.store.GetSetting(r.Context(), statsKey(x.ID), &cs) != nil || cs.At.IsZero() {
		if err := s.refreshStats(r.Context(), actor(r), c, x); err != nil {
			p.Error = storeErr(err)
		}
		_ = s.store.GetSetting(r.Context(), statsKey(x.ID), &cs)
	} else if s.now().Sub(cs.At) > time.Hour {
		go func() { _ = s.refreshStats(context.WithoutCancel(r.Context()), "system", c, x) }()
	}
	d := &statsData{S: x, At: cs.At, St: cs.Stats}
	_, d.Busy = statsBusy.Load(x.ID)
	for _, day := range cs.Stats.Days {
		d.Visits = append(d.Visits, day.Visitors)
		d.MaxDay = max(d.MaxDay, day.Visitors)
	}
	p.Data = d
	s.render(w, r, http.StatusOK, "sitestats", p)
}

func (s *Server) handleSiteStatsRefresh(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	x := s.mySite(w, r, c)
	if x == nil {
		return
	}
	back := "/sites/" + strconv.FormatInt(x.ID, 10) + "/stats"
	if err := s.refreshStats(r.Context(), actor(r), c, x); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.redirect(w, r, back, "Updated.")
}

// statCtx feeds the template "statlist".
type statCtx struct {
	P     *Page
	Title string
	Items []helper.StatItem
	Mono  bool
}

func init() {
	funcs["statctx"] = func(p *Page, title string, items []helper.StatItem, mono bool) statCtx {
		return statCtx{P: p, Title: title, Items: items, Mono: mono}
	}
}
