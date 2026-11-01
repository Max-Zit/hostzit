package web

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/helper"
	"github.com/max-zit/hostzit/internal/hosting"
	"github.com/max-zit/hostzit/internal/netacl"
	"github.com/max-zit/hostzit/internal/store"
)

// Access by country or continent: the administrator sets a rule for the
// sign-in services (panels, SSH and SFTP) under Brute-force protection;
// customers set one per website. The data is DB-IP's IP to Country Lite.

const settingGeo = "geo"

// GeoSettings is the country rule of the sign-in services.
type GeoSettings struct {
	Mode string   `json:"mode"` // "", block, allow
	List []string `json:"list"`
}

// continents in the order the pages show them
var continents = []struct{ Code, Name string }{
	{"EU", "Europe"}, {"AS", "Asia"}, {"NA", "North America"}, {"SA", "South America"}, {"AF", "Africa"}, {"OC", "Oceania"}, {"AN", "Antarctica"},
}

// geoChoice is the country list of the forms.
type geoChoice struct {
	Ready      bool
	Updated    time.Time
	Continents []geoContinent
	Mode       string
	List       []string
}

type geoContinent struct {
	Code, Name string
	Countries  []helper.Country
}

// Has reports whether a code is chosen (templates).
func (g *geoChoice) Has(code string) bool { return slices.Contains(g.List, code) }

func (s *Server) geoChoice(ctx context.Context, mode string, list []string) *geoChoice {
	var st helper.GeoStatus
	_ = s.call(ctx, "system", "geo.status", nil, &st)
	g := &geoChoice{Ready: st.Ready, Updated: st.Updated, Mode: mode, List: list}
	for _, c := range continents {
		gc := geoContinent{Code: c.Code, Name: c.Name}
		for _, x := range st.Countries {
			if x.Continent == c.Code {
				gc.Countries = append(gc.Countries, x)
			}
		}
		g.Continents = append(g.Continents, gc)
	}
	return g
}

// geoForm reads the mode and the chosen codes of a form.
func geoForm(r *http.Request) (string, []string, error) {
	_ = r.ParseForm()
	mode := r.FormValue("geo_mode")
	var list []string
	for _, c := range r.Form["geo"] {
		if c = strings.TrimSpace(c); c != "" && !slices.Contains(list, c) {
			list = append(list, c)
		}
	}
	if mode == "" {
		list = nil
	}
	return mode, list, hosting.ValidGeo(mode, list)
}

func (s *Server) geoSettings(ctx context.Context) GeoSettings {
	var g GeoSettings
	_ = s.store.GetSetting(ctx, settingGeo, &g)
	return g
}

// geoPorts are the ports of the sign-in services.
func (s *Server) geoPorts(ctx context.Context) []int {
	ports := []int{22}
	n, _ := s.Network(ctx)
	for _, l := range []string{n.AdminListen, n.PanelListen} {
		if i := strings.LastIndex(l, ":"); i >= 0 {
			if p, err := strconv.Atoi(l[i+1:]); err == nil && !slices.Contains(ports, p) {
				ports = append(ports, p)
			}
		}
	}
	return ports
}

// applyGeo writes the country rule of the sign-in services.
func (s *Server) applyGeo(ctx context.Context, by string) error {
	g := s.geoSettings(ctx)
	return s.call(ctx, by, "geo.firewall", map[string]any{"mode": g.Mode, "list": g.List, "ports": s.geoPorts(ctx), "allow": s.bruteSettings(ctx).Allow}, nil)
}

// refused tells whether an address would be refused by a rule.
func (s *Server) refused(ctx context.Context, ip, mode string, list []string) bool {
	if mode == "" {
		return false
	}
	a, ok := netacl.AddrOf(ip)
	if !ok || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() {
		return false
	}
	var loc struct{ Country, Continent string }
	if s.call(ctx, "system", "geo.lookup", map[string]string{"ip": a.String()}, &loc) != nil || loc.Country == "" {
		return false
	}
	hit := slices.Contains(list, loc.Country) || slices.Contains(list, "@"+loc.Continent)
	return hit == (mode == "block")
}

func init() {
	adminExtra = append(adminExtra, func(s *Server, mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc)) {
		admin("POST /settings/geo", s.handleGeoSave)
		admin("POST /settings/geo/update", s.handleGeoUpdate)
	})
	customerExtra = append(customerExtra, func(s *Server, mux *http.ServeMux, c func(string, http.HandlerFunc)) {
		c("POST /sites/{id}/geo", s.handleSiteGeo)
	})
}

func (s *Server) handleGeoUpdate(w http.ResponseWriter, r *http.Request) {
	by := actor(r)
	if _, err := s.runJob("geo.update", nil, "country database", func(ctx context.Context) error {
		if err := s.call(ctx, by, "geo.update", nil, nil); err != nil {
			return err
		}
		return s.reapplyGeoSites(ctx, by)
	}); err != nil {
		s.redirectErr(w, r, "/settings/bruteforce#countries", storeErr(err))
		return
	}
	s.audit(r, "geo.update", "settings", "country database download started")
	s.redirect(w, r, "/settings/bruteforce#countries", "The country database is being downloaded; reload the page in a minute.")
}

// reapplyGeoSites writes the sites with a country rule again (after the
// database came; before, their rule could not be written).
func (s *Server) reapplyGeoSites(ctx context.Context, by string) error {
	sites, err := s.store.Sites(ctx, 0)
	if err != nil {
		return err
	}
	for _, x := range sites {
		if x.GeoMode != "" {
			_ = s.applySite(ctx, by, x, false)
		}
	}
	return nil
}

func (s *Server) handleGeoSave(w http.ResponseWriter, r *http.Request) {
	back := "/settings/bruteforce#countries"
	mode, list, err := geoForm(r)
	if err != nil {
		s.redirectErr(w, r, back, err.Error())
		return
	}
	if s.refused(r.Context(), clientIP(r), mode, list) {
		s.redirectErr(w, r, back, "Your own address would be refused: add it under Never blocked first.")
		return
	}
	if err := s.store.SetSetting(r.Context(), settingGeo, GeoSettings{Mode: mode, List: list}); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.applyGeo(r.Context(), actor(r)); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.audit(r, "settings.geo", "settings", "sign-in country rule %q: %s", mode, strings.Join(list, " "))
	s.redirect(w, r, back, "Saved.")
}

// handleSiteGeo sets the country rule of a customer's website.
func (s *Server) handleSiteGeo(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	x := s.mySite(w, r, c)
	if x == nil {
		return
	}
	back := "/sites/" + strconv.FormatInt(x.ID, 10) + "#countries"
	mode, list, err := geoForm(r)
	if err != nil {
		s.redirectErr(w, r, back, err.Error())
		return
	}
	x.GeoMode, x.GeoList = mode, list
	if err := s.store.SaveSite(r.Context(), x); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	if err := s.applySite(r.Context(), actor(r), x, false); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.audit(r, "site.geo", "site:"+x.Domain, "country rule %q: %s", mode, strings.Join(list, " "))
	s.redirect(w, r, back, "Saved.")
}

// geoSites are the websites with a country rule (admin overview).
func (s *Server) geoSites(ctx context.Context) []*store.Site {
	sites, _ := s.store.Sites(ctx, 0)
	var out []*store.Site
	for _, x := range sites {
		if x.GeoMode != "" {
			out = append(out, x)
		}
	}
	return out
}

// geoMonthly fetches the new country database once a month (DB-IP
// publishes it at the start of each month).
func (s *Server) geoMonthly(ctx context.Context) {
	var st helper.GeoStatus
	if s.call(ctx, "system", "geo.status", nil, &st) != nil || !st.Ready || s.now().Sub(st.Updated) < 32*24*time.Hour {
		return
	}
	if err := s.call(ctx, "system", "geo.update", nil, nil); err != nil {
		s.log.Warn("country database not updated", "err", err)
	}
}
