package web

import (
	"net/http"

	"github.com/max-zit/hostzit/internal/helper"
)

// System updates (Settings → System): the Debian and PHP packages that
// wait, installing them now and the nightly security updates.

func init() {
	adminExtra = append(adminExtra, func(s *Server, mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc)) {
		admin("POST /settings/system/os-upgrade", s.handleOSUpgrade)
		admin("POST /settings/system/os-auto", s.handleOSAuto)
	})
}

// osStatus is shown on the system page (refresh: read the package lists anew).
func (s *Server) osStatus(r *http.Request, refresh bool) (*helper.OSStatus, string) {
	var st helper.OSStatus
	if err := s.call(r.Context(), "system", "os.status", map[string]bool{"refresh": refresh}, &st); err != nil {
		return nil, storeErr(err)
	}
	return &st, ""
}

func (s *Server) handleOSUpgrade(w http.ResponseWriter, r *http.Request) {
	if err := s.call(r.Context(), actor(r), "os.upgrade", struct{}{}, nil); err != nil {
		s.redirectErr(w, r, "/settings/system", storeErr(err))
		return
	}
	s.audit(r, "system.os-upgrade", "server", "installing the system updates")
	s.redirect(w, r, "/settings/system", "The updates are being installed. This page shows when it is done.")
}

func (s *Server) handleOSAuto(w http.ResponseWriter, r *http.Request) {
	on := r.FormValue("on") == "1"
	if err := s.call(r.Context(), actor(r), "os.auto", map[string]bool{"on": on}, nil); err != nil {
		s.redirectErr(w, r, "/settings/system", storeErr(err))
		return
	}
	s.audit(r, "system.os-auto", "server", "nightly security updates: %v", on)
	s.redirect(w, r, "/settings/system", "Saved.")
}
