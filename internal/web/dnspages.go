package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/max-zit/hostzit/internal/hosting"
	"github.com/max-zit/hostzit/internal/store"
)

type zonesData struct {
	Zones []*store.Zone
	NS    []string
}

func (s *Server) handleMyZones(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	list, err := s.store.Zones(r.Context(), c.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "zones", &Page{Title: "Domains and DNS", Nav: "dns", Customer: c, Data: &zonesData{Zones: list, NS: s.hostingSettings(r.Context()).Nameservers}})
}

func (s *Server) handleZoneCreate(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	dom, err := hosting.NormalizeDomain(r.FormValue("zone"))
	if err != nil {
		s.redirectErr(w, r, "/dns", err.Error())
		return
	}
	if err := s.domainAllowed(r.Context(), c, dom); err != nil {
		s.redirectErr(w, r, "/dns", err.Error())
		return
	}
	p, _ := s.store.PackageByID(r.Context(), c.PackageID)
	_, _, zones, _ := s.store.CountFor(r.Context(), c.ID)
	if p != nil && s.hostingSettings(r.Context()).Mode != "dedicated" && zones >= p.MaxZones {
		s.redirectErr(w, r, "/dns", translate(s.lang(r, userFrom(r)), "The package allows %d DNS zones.", p.MaxZones))
		return
	}
	z, err := s.store.CreateZone(r.Context(), c.ID, dom, s.defaultRecords(r.Context()))
	if err != nil {
		s.redirectErr(w, r, "/dns", storeErr(err))
		return
	}
	s.audit(r, "dns.zone.create", "zone:"+dom, "")
	if err := s.applyZone(r.Context(), actor(r), z); err != nil {
		s.redirectErr(w, r, "/dns/"+strconv.FormatInt(z.ID, 10), storeErr(err))
		return
	}
	s.redirect(w, r, "/dns/"+strconv.FormatInt(z.ID, 10), "The DNS zone was created.")
}

func (s *Server) myZone(w http.ResponseWriter, r *http.Request, c *store.Customer) *store.Zone {
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return nil
	}
	z, err := s.store.ZoneByID(r.Context(), id)
	if err != nil || z.CustomerID != c.ID {
		s.notFound(w, r)
		return nil
	}
	return z
}

type zoneData struct {
	Z       *store.Zone
	Records []store.RecordRow
	Types   []string
	NS      []string
	Edit    int64
}

func (s *Server) handleZone(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	z := s.myZone(w, r, c)
	if z == nil {
		return
	}
	recs, err := s.store.Records(r.Context(), z.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	edit, _ := strconv.ParseInt(r.FormValue("edit"), 10, 64)
	s.render(w, r, http.StatusOK, "zone", &Page{Title: z.Name, Nav: "dns", Customer: c, Crumb: "Domains and DNS", CrumbURL: "/dns",
		Data: &zoneData{Z: z, Records: recs, Types: hosting.DNSTypes, NS: s.hostingSettings(r.Context()).Nameservers, Edit: edit}})
}

func recordFromForm(r *http.Request) hosting.Record {
	return hosting.Record{Name: strings.TrimSpace(r.FormValue("name")), Type: r.FormValue("type"), TTL: formInt(r, "ttl"), Content: strings.TrimSpace(r.FormValue("content"))}
}

func (s *Server) zoneChanged(w http.ResponseWriter, r *http.Request, z *store.Zone, msg string) {
	back := "/dns/" + strconv.FormatInt(z.ID, 10)
	if err := s.applyZone(r.Context(), actor(r), z); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.redirect(w, r, back, msg)
}

func (s *Server) handleRecordAdd(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	z := s.myZone(w, r, c)
	if z == nil {
		return
	}
	rec := recordFromForm(r)
	if _, err := s.store.AddRecord(r.Context(), z, rec); err != nil {
		s.redirectErr(w, r, "/dns/"+strconv.FormatInt(z.ID, 10), err.Error())
		return
	}
	s.audit(r, "dns.record.add", "zone:"+z.Name, "%s %s %s", rec.Name, rec.Type, rec.Content)
	s.zoneChanged(w, r, z, "Record added.")
}

func (s *Server) handleRecordUpdate(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	z := s.myZone(w, r, c)
	if z == nil {
		return
	}
	rid, _ := pathID(r, "rid")
	rec := recordFromForm(r)
	if err := s.store.UpdateRecord(r.Context(), z, rid, rec); err != nil {
		s.redirectErr(w, r, "/dns/"+strconv.FormatInt(z.ID, 10), storeErr(err))
		return
	}
	s.audit(r, "dns.record.update", "zone:"+z.Name, "%s %s %s", rec.Name, rec.Type, rec.Content)
	s.zoneChanged(w, r, z, "Record saved.")
}

func (s *Server) handleRecordDelete(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	z := s.myZone(w, r, c)
	if z == nil {
		return
	}
	rid, _ := pathID(r, "rid")
	if err := s.store.DeleteRecord(r.Context(), z.ID, rid); err != nil {
		s.redirectErr(w, r, "/dns/"+strconv.FormatInt(z.ID, 10), storeErr(err))
		return
	}
	s.audit(r, "dns.record.delete", "zone:"+z.Name, "record %d", rid)
	s.zoneChanged(w, r, z, "Record deleted.")
}

func (s *Server) handleZoneDNSSEC(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	z := s.myZone(w, r, c)
	if z == nil {
		return
	}
	on := r.FormValue("on") != ""
	var res struct {
		DS []string `json:"ds"`
	}
	back := "/dns/" + strconv.FormatInt(z.ID, 10)
	if err := s.call(r.Context(), actor(r), "dns.dnssec", map[string]any{"zone": z.Name, "on": on}, &res); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	_ = s.store.SetDNSSEC(r.Context(), z.ID, on, res.DS)
	s.audit(r, "dns.dnssec", "zone:"+z.Name, "DNSSEC %v", on)
	msg := "DNSSEC was switched off. Remove the DS record at your registrar first if it is still there."
	if on {
		msg = "The zone is signed. Put the DS record shown below at your domain registrar."
	}
	s.redirect(w, r, back, msg)
}

func (s *Server) handleZoneDelete(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	z := s.myZone(w, r, c)
	if z == nil {
		return
	}
	if r.FormValue("confirm") != z.Name {
		s.redirectErr(w, r, "/dns/"+strconv.FormatInt(z.ID, 10), "Type the domain to confirm.")
		return
	}
	if err := s.call(r.Context(), actor(r), "dns.delete", map[string]any{"zone": z.Name}, nil); err != nil {
		s.redirectErr(w, r, "/dns/"+strconv.FormatInt(z.ID, 10), storeErr(err))
		return
	}
	_ = s.store.DeleteZone(r.Context(), z.ID)
	s.audit(r, "dns.zone.delete", "zone:"+z.Name, "")
	s.redirect(w, r, "/dns", "The DNS zone was deleted.")
}
