package web

import (
	"net/http"
	"slices"

	"github.com/max-zit/hostzit/internal/helper"
)

// Settings → PHP: the PHP versions of the server (like cPanel's MultiPHP).
// Every installed version can be chosen per website (and per package).

func init() {
	adminExtra = append(adminExtra, func(s *Server, mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc)) {
		admin("GET /settings/php", s.handlePHP)
		admin("POST /settings/php/install", s.handlePHPInstall)
		admin("POST /settings/php/remove", s.handlePHPRemove)
	})
}

type phpRow struct {
	Version string
	Sites   int
	Default bool
}

type phpData struct {
	Installed []phpRow
	Offered   []string
	// Candidate: the full version apt installs now ("8.4" → "8.4.16")
	Candidate map[string]string
}

// phpUse counts the websites per PHP version.
func (s *Server) phpUse(r *http.Request) map[string]int {
	use := map[string]int{}
	if sites, err := s.store.Sites(r.Context(), 0); err == nil {
		for _, x := range sites {
			use[x.PHPVersion]++
		}
	}
	return use
}

func (s *Server) handlePHP(w http.ResponseWriter, r *http.Request) {
	installed := s.phpVersions(r.Context())
	def := s.hostingSettings(r.Context()).DefaultPHP
	use := s.phpUse(r)
	d := &phpData{}
	_ = s.call(r.Context(), "system", "php.candidates", nil, &d.Candidate)
	for _, v := range installed {
		d.Installed = append(d.Installed, phpRow{Version: v, Sites: use[v], Default: v == def})
	}
	for _, v := range helper.PHPVersionsOffered {
		if !slices.Contains(installed, v) {
			d.Offered = append(d.Offered, v)
		}
	}
	s.render(w, r, http.StatusOK, "php", &Page{Title: "PHP", Nav: "settings", Data: d})
}

func (s *Server) handlePHPInstall(w http.ResponseWriter, r *http.Request) {
	v := r.FormValue("version")
	if !slices.Contains(helper.PHPVersionsOffered, v) {
		s.redirectErr(w, r, "/settings/php", "This PHP version is not installed.")
		return
	}
	if err := s.call(r.Context(), actor(r), "php.install", map[string]string{"version": v}, nil); err != nil {
		s.redirectErr(w, r, "/settings/php", storeErr(err))
		return
	}
	s.audit(r, "php.install", "server", "PHP %s installed", v)
	s.redirect(w, r, "/settings/php", "PHP was installed. Websites can use it now; packages that list PHP versions need it added.")
}

func (s *Server) handlePHPRemove(w http.ResponseWriter, r *http.Request) {
	v := r.FormValue("version")
	if v == s.hostingSettings(r.Context()).DefaultPHP {
		s.redirectErr(w, r, "/settings/php", "The default PHP version cannot be removed.")
		return
	}
	if s.phpUse(r)[v] > 0 {
		s.redirectErr(w, r, "/settings/php", "Websites still use this PHP version.")
		return
	}
	if len(s.phpVersions(r.Context())) <= 1 {
		s.redirectErr(w, r, "/settings/php", "The default PHP version cannot be removed.")
		return
	}
	if err := s.call(r.Context(), actor(r), "php.remove", map[string]string{"version": v}, nil); err != nil {
		s.redirectErr(w, r, "/settings/php", storeErr(err))
		return
	}
	s.audit(r, "php.remove", "server", "PHP %s removed", v)
	s.redirect(w, r, "/settings/php", "Deleted.")
}
