package web

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/max-zit/hostzit/internal/helper"
	"github.com/max-zit/hostzit/internal/hosting"
	"github.com/max-zit/hostzit/internal/store"
)

// PHP extensions (admin: which extension packages a PHP version has, like
// EasyApache) and the account's own PHP options (customer: extensions
// switched off and php.ini values per version, like "Select PHP
// Extensions" and the "MultiPHP INI Editor").

func init() {
	adminExtra = append(adminExtra, func(s *Server, mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc)) {
		admin("GET /settings/php/{version}", s.handlePHPExt)
		admin("POST /settings/php/{version}", s.handlePHPExtSave)
	})
	customerExtra = append(customerExtra, func(s *Server, mux *http.ServeMux, c func(string, http.HandlerFunc)) {
		c("GET /php", s.handleMyPHP)
		c("POST /php/{version}", s.handleMyPHPSave)
	})
}

func phpOptionsKey(c *store.Customer) string { return "phpopts:" + strconv.FormatInt(c.ID, 10) }

// phpOptions are the account's saved options per version.
func (s *Server) phpOptions(ctx context.Context, c *store.Customer) map[string]hosting.PHPOptions {
	m := map[string]hosting.PHPOptions{}
	_ = s.store.GetSetting(ctx, phpOptionsKey(c), &m)
	return m
}

// phpOptionsFor keeps only valid options of the versions in use (a smaller
// package later must not break the account).
func (s *Server) phpOptionsFor(ctx context.Context, c *store.Customer, versions []string, l hosting.Limits) map[string]hosting.PHPOptions {
	out := map[string]hosting.PHPOptions{}
	for v, o := range s.phpOptions(ctx, c) {
		if !slices.Contains(versions, v) {
			continue
		}
		clean := hosting.PHPOptions{Disabled: o.Disabled, INI: map[string]string{}}
		for k, val := range o.INI {
			if cv, err := hosting.CleanINI(k, val, l); err == nil {
				clean.INI[k] = cv
			}
		}
		if clean.Validate(l) == nil {
			out[v] = clean
		}
	}
	return out
}

// ---- admin

type phpExtData struct {
	Version   string
	Ext       helper.PHPExtensions
	Protected []string
}

func (s *Server) handlePHPExt(w http.ResponseWriter, r *http.Request) {
	v := r.PathValue("version")
	if !slices.Contains(s.phpVersions(r.Context()), v) {
		s.notFound(w, r)
		return
	}
	d := &phpExtData{Version: v, Protected: []string{"fpm", "cli", "common", "opcache", "readline"}}
	p := &Page{Title: "PHP", Nav: "settings", Crumb: "PHP", CrumbURL: "/settings/php", Data: d}
	if err := s.call(r.Context(), actor(r), "php.ext.list", map[string]string{"version": v}, &d.Ext); err != nil {
		p.Error = storeErr(err)
	}
	s.render(w, r, http.StatusOK, "phpext", p)
}

func (s *Server) handlePHPExtSave(w http.ResponseWriter, r *http.Request) {
	v := r.PathValue("version")
	back := "/settings/php/" + v
	var cur helper.PHPExtensions
	if err := s.call(r.Context(), actor(r), "php.ext.list", map[string]string{"version": v}, &cur); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	_ = r.ParseForm()
	want := r.Form["ext"]
	var install, remove []string
	for _, x := range want {
		if slices.Contains(cur.Available, x) && !slices.Contains(cur.Installed, x) {
			install = append(install, x)
		}
	}
	for _, x := range cur.Installed {
		if !slices.Contains(want, x) && !slices.Contains([]string{"fpm", "cli", "common", "opcache", "readline"}, x) {
			remove = append(remove, x)
		}
	}
	if len(install)+len(remove) == 0 {
		s.redirect(w, r, back, "Saved.")
		return
	}
	if err := s.call(r.Context(), actor(r), "php.ext.set", map[string]any{"version": v, "install": install, "remove": remove}, nil); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.audit(r, "php.extensions", "server", "PHP %s: installed %s; removed %s", v, strings.Join(install, " "), strings.Join(remove, " "))
	go s.reapplyAll(context.WithoutCancel(r.Context()), actor(r))
	s.redirect(w, r, back, "Saved. The accounts get the new extensions in a minute.")
}

// reapplyAll applies every active account again (new PHP extensions).
func (s *Server) reapplyAll(ctx context.Context, by string) {
	list, err := s.store.Customers(ctx, store.CustomerFilter{Status: store.StatusActive})
	if err != nil {
		return
	}
	for _, c := range list {
		if err := s.applyCustomer(ctx, by, c); err != nil {
			s.log.Warn("account not applied", "account", c.Username, "err", err)
		}
	}
}

// ---- customer

type myPHPVersion struct {
	Version string
	Modules []string
	Off     []string
	INI     map[string]string
}

type myPHPData struct {
	Versions []myPHPVersion
	Keys     []hosting.INIKey
	Limits   hosting.Limits
}

func (s *Server) handleMyPHP(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	a, _, err := s.accountFor(r.Context(), c)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := &myPHPData{Keys: hosting.INIKeys, Limits: a.Limits}
	saved := s.phpOptions(r.Context(), c)
	for _, v := range a.PHPVersions {
		mv := myPHPVersion{Version: v, Off: saved[v].Disabled, INI: saved[v].INI}
		_ = s.call(r.Context(), actor(r), "php.modules", map[string]string{"version": v}, &mv.Modules)
		d.Versions = append(d.Versions, mv)
	}
	s.render(w, r, http.StatusOK, "myphp", &Page{Title: "PHP", Nav: "php", Customer: c, Data: d})
}

func (s *Server) handleMyPHPSave(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	v := r.PathValue("version")
	a, _, err := s.accountFor(r.Context(), c)
	if err != nil || !slices.Contains(a.PHPVersions, v) {
		s.notFound(w, r)
		return
	}
	var mods []string
	_ = s.call(r.Context(), actor(r), "php.modules", map[string]string{"version": v}, &mods)
	_ = r.ParseForm()
	on := r.Form["ext"]
	o := hosting.PHPOptions{INI: map[string]string{}}
	for _, m := range mods {
		if !slices.Contains(on, m) {
			o.Disabled = append(o.Disabled, m)
		}
	}
	for _, k := range hosting.INIKeys {
		val := strings.TrimSpace(r.FormValue("ini_" + k.Name))
		if val == "" {
			continue
		}
		cv, err := hosting.CleanINI(k.Name, val, a.Limits)
		if err != nil {
			s.redirectErr(w, r, "/php", err.Error())
			return
		}
		o.INI[k.Name] = cv
	}
	all := s.phpOptions(r.Context(), c)
	all[v] = o
	if err := s.store.SetSetting(r.Context(), phpOptionsKey(c), all); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "php.options", "customer:"+c.Username, "PHP %s: %d extensions off, %d php.ini values", v, len(o.Disabled), len(o.INI))
	if err := s.applyCustomer(r.Context(), actor(r), c); err != nil {
		s.redirectErr(w, r, "/php", storeErr(err))
		return
	}
	s.redirect(w, r, "/php", "Saved. PHP restarted with the new settings.")
}
