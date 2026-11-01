package web

import (
	"bufio"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/helper"
)

// Settings → System: network, host name, time zone, restart and shut down
// of the HostZit appliance. On other servers the page only says that the
// server's administrator manages these.

// applianceMarker is checked by the panel too (the helper refuses anyway).
var applianceMarker = helper.ApplianceMarker

func isAppliance() bool {
	_, err := os.Stat(applianceMarker)
	return err == nil
}

func init() {
	adminExtra = append(adminExtra, func(s *Server, mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc)) {
		admin("GET /settings/system", s.handleSystem)
		admin("POST /settings/system/network", s.handleSystemNetwork)
		admin("POST /settings/system/timezone", s.handleSystemTimeZone)
		admin("POST /settings/system/power", s.handleSystemPower)
	})
}

type systemData struct {
	St        helper.SystemState
	DNS       string
	Zones     []string
	Appliance bool
	OS        *helper.OSStatus
	OSError   string
}

// timeZones lists the zone names of the system's time zone database.
func timeZones() []string {
	out := []string{"UTC"}
	f, err := os.Open("/usr/share/zoneinfo/tzdata.zi")
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// "Z Europe/Belgrade 1:22 - LMT 1884" and links "L Europe/Belgrade Europe/Zagreb"
		fl := strings.Fields(sc.Text())
		name := ""
		switch {
		case len(fl) >= 2 && fl[0] == "Z":
			name = fl[1]
		case len(fl) >= 3 && fl[0] == "L":
			name = fl[2]
		}
		if strings.Contains(name, "/") && !strings.HasPrefix(name, "Etc/") && !strings.HasPrefix(name, "SystemV/") {
			out = append(out, name)
		}
	}
	sort.Strings(out[1:])
	return out
}

func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	d := &systemData{Appliance: isAppliance()}
	d.OS, d.OSError = s.osStatus(r, r.URL.Query().Get("check") == "1")
	if err := s.call(r.Context(), "system", "system.state", struct{}{}, &d.St); err != nil {
		s.render(w, r, http.StatusOK, "system", &Page{Title: "System", Nav: "settings", Data: d, Error: storeErr(err)})
		return
	}
	d.DNS = strings.Join(d.St.Network.DNS, " ")
	d.Zones = timeZones()
	s.render(w, r, http.StatusOK, "system", &Page{Title: "System", Nav: "settings", Data: d})
}

func (s *Server) handleSystemNetwork(w http.ResponseWriter, r *http.Request) {
	var before helper.SystemState
	_ = s.call(r.Context(), "system", "system.state", struct{}{}, &before)
	c := helper.NetworkConfig{DHCP: r.FormValue("mode") != "static", Hostname: strings.TrimSpace(r.FormValue("hostname"))}
	if !c.DHCP {
		c.Address = strings.TrimSpace(r.FormValue("address"))
		c.Gateway = strings.TrimSpace(r.FormValue("gateway"))
		c.DNS = strings.Fields(strings.ReplaceAll(r.FormValue("dns"), ",", " "))
	}
	if err := c.Validate(); err != nil {
		s.redirectErr(w, r, "/settings/system", err.Error())
		return
	}
	if err := s.call(r.Context(), actor(r), "system.network", c, nil); err != nil {
		s.redirectErr(w, r, "/settings/system", storeErr(err))
		return
	}
	s.audit(r, "system.network", "server", "network: dhcp %v, address %q, gateway %q, dns %v, host name %q", c.DHCP, c.Address, c.Gateway, c.DNS, c.Hostname)
	// The websites' address follows the server's when it was the old one.
	if p, err := netip.ParsePrefix(c.Address); err == nil {
		h := s.hostingSettings(r.Context())
		if old, err := netip.ParsePrefix(before.Current); err == nil && h.IPv4 == old.Addr().String() && h.IPv4 != p.Addr().String() {
			h.IPv4 = p.Addr().String()
			if err := s.store.SetSetting(r.Context(), settingHosting, h); err == nil {
				s.audit(r, "settings.hosting", "settings", "IPv4 address of the websites follows the server: %s", h.IPv4)
			}
		}
	}
	s.redirect(w, r, "/settings/system", "The network settings were applied.")
}

func (s *Server) handleSystemTimeZone(w http.ResponseWriter, r *http.Request) {
	z := r.FormValue("zone")
	if err := s.call(r.Context(), actor(r), "system.timezone", map[string]string{"zone": z}, nil); err != nil {
		s.redirectErr(w, r, "/settings/system", storeErr(err))
		return
	}
	// the panel shows times in the new zone at once (Go reads it only at start)
	if loc, err := time.LoadLocation(z); err == nil {
		time.Local = loc
	}
	s.audit(r, "system.timezone", "server", "time zone %s", z)
	s.redirect(w, r, "/settings/system", "Saved.")
}

func (s *Server) handleSystemPower(w http.ResponseWriter, r *http.Request) {
	a := r.FormValue("action")
	if err := s.call(r.Context(), actor(r), "system.power", map[string]string{"action": a}, nil); err != nil {
		s.redirectErr(w, r, "/settings/system", storeErr(err))
		return
	}
	s.audit(r, "system.power", "server", "%s in 5 seconds", a)
	if a == "reboot" {
		s.redirect(w, r, "/settings/system", "The server restarts in a few seconds. Reload the page in two minutes.")
		return
	}
	s.redirect(w, r, "/settings/system", "The server shuts down in a few seconds.")
}
