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
	"github.com/max-zit/hostzit/internal/store"
)

// Node.js and Python applications in the customer panel (like cPanel's
// "Setup Node.js App" / "Setup Python App").

func init() {
	customerExtra = append(customerExtra, func(s *Server, mux *http.ServeMux, c func(string, http.HandlerFunc)) {
		c("GET /apps", s.handleApps)
		c("POST /apps", s.handleAppCreate)
		c("GET /apps/{id}", s.handleApp)
		c("POST /apps/{id}", s.handleAppUpdate)
		c("POST /apps/{id}/restart", s.handleAppRestart)
		c("POST /apps/{id}/run", s.handleAppRun)
		c("POST /apps/{id}/site", s.handleAppSite)
		c("POST /apps/{id}/delete", s.handleAppDelete)
	})
}

// appSpecs are the enabled applications of a customer for the helper.
func (s *Server) appSpecs(ctx context.Context, c *store.Customer, max int) []hosting.App {
	list, _ := s.store.Apps(ctx, c.ID)
	var out []hosting.App
	for _, a := range list {
		if a.Enabled && len(out) < max {
			out = append(out, a.Spec())
		}
	}
	return out
}

type appsData struct {
	Apps  []*store.App
	Max   int
	Sites map[string][]string // application → domains
}

func (s *Server) handleApps(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	d := &appsData{Sites: map[string][]string{}}
	d.Apps, _ = s.store.Apps(r.Context(), c.ID)
	if a, _, err := s.accountFor(r.Context(), c); err == nil {
		d.Max = a.Limits.Apps
	}
	if sites, err := s.store.Sites(r.Context(), c.ID); err == nil {
		for _, x := range sites {
			if x.App != "" {
				d.Sites[x.App] = append(d.Sites[x.App], x.Domain)
			}
		}
	}
	s.render(w, r, http.StatusOK, "apps", &Page{Title: "Applications", Nav: "apps", Customer: c, Data: d})
}

// parseEnv reads KEY=value lines.
func parseEnv(text string) map[string]string {
	env := map[string]string{}
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, _ := strings.Cut(l, "=")
		env[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return env
}

func (s *Server) handleAppCreate(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	a := &store.App{CustomerID: c.ID, Name: strings.TrimSpace(r.FormValue("name")), Kind: r.FormValue("kind"), Root: strings.Trim(strings.TrimSpace(r.FormValue("root")), "/"),
		Command: strings.TrimSpace(r.FormValue("command")), Env: parseEnv(r.FormValue("env")), Enabled: true}
	acct, _, err := s.accountFor(r.Context(), c)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	list, _ := s.store.Apps(r.Context(), c.ID)
	if len(list) >= acct.Limits.Apps {
		s.redirectErr(w, r, "/apps", "Your package allows no more applications.")
		return
	}
	if err := a.Spec().Validate(); err != nil {
		s.redirectErr(w, r, "/apps", err.Error())
		return
	}
	if err := s.fileReq(r.Context(), actor(r), c, helper.WorkerReq{Op: "mkdir", Path: a.Root}); err != nil {
		s.redirectErr(w, r, "/apps", storeErr(err))
		return
	}
	if err := s.store.SaveApp(r.Context(), a); err != nil {
		s.redirectErr(w, r, "/apps", storeErr(err))
		return
	}
	s.audit(r, "app.create", "customer:"+c.Username, "%s application %s in %s", a.Kind, a.Name, a.Root)
	if err := s.applyCustomer(r.Context(), actor(r), c); err != nil {
		s.redirectErr(w, r, "/apps/"+strconv.FormatInt(a.ID, 10), storeErr(err))
		return
	}
	s.redirect(w, r, "/apps/"+strconv.FormatInt(a.ID, 10), "The application was created. Put its files into the folder, install its packages below, then restart it.")
}

func (s *Server) myApp(w http.ResponseWriter, r *http.Request, c *store.Customer) *store.App {
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return nil
	}
	a, err := s.store.AppByID(r.Context(), id)
	if err != nil || a.CustomerID != c.ID {
		s.notFound(w, r)
		return nil
	}
	return a
}

// AppRun is the last one-off command of an application.
type AppRun struct {
	At      time.Time `json:"at"`
	Command string    `json:"command"`
	OK      bool      `json:"ok"`
	Output  string    `json:"output"`
}

func appRunKey(id int64) string { return "apprun:" + strconv.FormatInt(id, 10) }

type appData struct {
	A      *store.App
	State  helper.AppState
	Env    string
	Sites  []*store.Site
	Run    *AppRun
	Socket string
}

func (s *Server) handleApp(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	a := s.myApp(w, r, c)
	if a == nil {
		return
	}
	d := &appData{A: a, Socket: "/.sock/app-" + a.Name + ".sock"}
	if a.Enabled {
		_ = s.call(r.Context(), actor(r), "app.status", map[string]any{"account": c.Username, "name": a.Name, "lines": 120}, &d.State)
	}
	keys := make([]string, 0, len(a.Env))
	for k := range a.Env {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var lines []string
	for _, k := range keys {
		lines = append(lines, k+"="+a.Env[k])
	}
	d.Env = strings.Join(lines, "\n")
	d.Sites, _ = s.store.Sites(r.Context(), c.ID)
	var run AppRun
	if s.store.GetSetting(r.Context(), appRunKey(a.ID), &run) == nil && !run.At.IsZero() {
		d.Run = &run
	}
	s.render(w, r, http.StatusOK, "app", &Page{Title: a.Name, Nav: "apps", Customer: c, Crumb: "Applications", CrumbURL: "/apps", Data: d})
}

func (s *Server) handleAppUpdate(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	a := s.myApp(w, r, c)
	if a == nil {
		return
	}
	back := "/apps/" + strconv.FormatInt(a.ID, 10)
	a.Root = strings.Trim(strings.TrimSpace(r.FormValue("root")), "/")
	a.Command = strings.TrimSpace(r.FormValue("command"))
	a.Env = parseEnv(r.FormValue("env"))
	a.Enabled = r.FormValue("enabled") != ""
	if err := a.Spec().Validate(); err != nil {
		s.redirectErr(w, r, back, err.Error())
		return
	}
	if err := s.store.SaveApp(r.Context(), a); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.audit(r, "app.update", "customer:"+c.Username, "application %s (running %v)", a.Name, a.Enabled)
	if err := s.applyCustomer(r.Context(), actor(r), c); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.redirect(w, r, back, "Saved.")
}

func (s *Server) handleAppRestart(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	a := s.myApp(w, r, c)
	if a == nil {
		return
	}
	back := "/apps/" + strconv.FormatInt(a.ID, 10)
	if err := s.call(r.Context(), actor(r), "app.restart", map[string]any{"account": c.Username, "name": a.Name}, nil); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.audit(r, "app.restart", "customer:"+c.Username, "application %s", a.Name)
	s.redirect(w, r, back, "Restarted.")
}

func (s *Server) handleAppRun(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	a := s.myApp(w, r, c)
	if a == nil {
		return
	}
	back := "/apps/" + strconv.FormatInt(a.ID, 10)
	cmd := strings.TrimSpace(r.FormValue("command"))
	var res struct {
		OK     bool   `json:"ok"`
		Output string `json:"output"`
	}
	if err := s.call(r.Context(), actor(r), "app.run", map[string]any{"account": c.Username, "root": a.Root, "command": cmd}, &res); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	_ = s.store.SetSetting(r.Context(), appRunKey(a.ID), AppRun{At: s.now(), Command: cmd, OK: res.OK, Output: res.Output})
	s.audit(r, "app.run", "customer:"+c.Username, "application %s: %s (ok %v)", a.Name, cmd, res.OK)
	s.redirect(w, r, back+"#run", "The command finished.")
}

// handleAppSite sends a website to the application or back to PHP.
func (s *Server) handleAppSite(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	a := s.myApp(w, r, c)
	if a == nil {
		return
	}
	back := "/apps/" + strconv.FormatInt(a.ID, 10)
	id, _ := strconv.ParseInt(r.FormValue("site"), 10, 64)
	x, err := s.store.SiteByID(r.Context(), id)
	if err != nil || x.CustomerID != c.ID {
		s.redirectErr(w, r, back, "Choose one of your websites.")
		return
	}
	app := a.Name
	if r.FormValue("detach") != "" {
		app = ""
	}
	if err := s.store.SetSiteApp(r.Context(), x.ID, app); err != nil {
		s.serverError(w, r, err)
		return
	}
	x.App = app
	if err := s.applySite(r.Context(), actor(r), x, false); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.audit(r, "app.site", "site:"+x.Domain, "served by application %q", app)
	s.redirect(w, r, back, "Saved.")
}

func (s *Server) handleAppDelete(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	a := s.myApp(w, r, c)
	if a == nil {
		return
	}
	sites, _ := s.store.Sites(r.Context(), c.ID)
	if err := s.store.DeleteApp(r.Context(), a); err != nil {
		s.serverError(w, r, err)
		return
	}
	_ = s.store.DeleteSetting(r.Context(), appRunKey(a.ID))
	for _, x := range sites {
		if x.App == a.Name {
			x.App = ""
			_ = s.applySite(r.Context(), actor(r), x, false)
		}
	}
	if err := s.applyCustomer(r.Context(), actor(r), c); err != nil {
		s.redirectErr(w, r, "/apps", storeErr(err))
		return
	}
	s.audit(r, "app.delete", "customer:"+c.Username, "application %s (its files stay)", a.Name)
	s.redirect(w, r, "/apps", "Deleted. The application's files stay in your home.")
}
