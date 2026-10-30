package web

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/auth"
	"github.com/max-zit/hostzit/internal/hosting"
	"github.com/max-zit/hostzit/internal/store"
)

// me is the customer of a customer panel request.
func (s *Server) me(w http.ResponseWriter, r *http.Request) *store.Customer {
	u := userFrom(r)
	c, err := s.store.CustomerByID(r.Context(), *u.CustomerID)
	if err != nil {
		s.serverError(w, r, err)
		return nil
	}
	if c.Status != store.StatusActive {
		s.forbidden(w, r)
		return nil
	}
	return c
}

// ---- single sign-on

// handleSSO signs in with a one-time link from the billing system or the
// admin panel ("log in as").
func (s *Server) handleSSO(w http.ResponseWriter, r *http.Request) {
	u, by, err := s.store.UseSSOLink(r.Context(), r.PathValue("token"))
	if err != nil || !u.IsCustomer() {
		s.guard.fail(r.Context(), clientIP(r), "", "sso link")
		s.redirectErr(w, r, "/login", "The sign-in link is invalid or expired.")
		return
	}
	sec := s.security(r.Context())
	life := time.Duration(sec.SessionHours) * time.Hour
	var tok string
	if strings.HasPrefix(by, "admin:") {
		tok, err = s.store.CreateActingSession(r.Context(), u.ID, strings.TrimPrefix(by, "admin:"), life, clientIP(r), r.UserAgent())
	} else {
		tok, _, err = s.store.CreateSession(r.Context(), u.ID, store.StageFull, life, clientIP(r), r.UserAgent())
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.setSessionCookie(w, r, tok, life)
	_ = s.store.MarkLogin(r.Context(), u.ID)
	s.auditAs(r, u.Username, "login.sso", "user:"+u.Username, "signed in with a one-time link from %s", by)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ---- home

type homeData struct {
	C      *store.Customer
	P      *store.Package
	Sites  []*store.Site
	Zones  int
	DBs    int
	Usage  *store.UsageSample
	Limits hosting.Limits
}

func (s *Server) handleCustomerHome(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	ctx := r.Context()
	d := &homeData{C: c}
	var err error
	if d.P, err = s.store.PackageByID(ctx, c.PackageID); err != nil {
		s.serverError(w, r, err)
		return
	}
	d.Limits = d.P.Limits
	d.Sites, _ = s.store.Sites(ctx, c.ID)
	_, d.DBs, d.Zones, _ = s.store.CountFor(ctx, c.ID)
	d.Usage, _ = s.store.LastUsage(ctx, c.ID)
	s.render(w, r, http.StatusOK, "home", &Page{Title: "Overview", Nav: "home", Customer: c, Data: d})
}

// ---- sites

func (s *Server) handleMySites(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	list, err := s.store.Sites(r.Context(), c.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "sites", &Page{Title: "Websites", Nav: "sites", Customer: c, Data: list})
}

type siteFormData struct {
	Domain string
	DNS    bool
}

func (s *Server) handleSiteForm(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	s.render(w, r, http.StatusOK, "siteform", &Page{Title: "New website", Nav: "sites", Customer: c, Crumb: "Websites", CrumbURL: "/sites", Data: &siteFormData{DNS: true}})
}

func (s *Server) handleSiteCreate(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	d := &siteFormData{Domain: strings.TrimSpace(r.FormValue("domain")), DNS: r.FormValue("dns") != ""}
	fail := func(msg string) {
		p := &Page{Title: "New website", Nav: "sites", Customer: c, Crumb: "Websites", CrumbURL: "/sites", Data: d}
		p.Error = translate(s.lang(r, userFrom(r)), msg)
		s.render(w, r, http.StatusBadRequest, "siteform", p)
	}
	dom, err := hosting.NormalizeDomain(d.Domain)
	if err != nil {
		fail(err.Error())
		return
	}
	if err := s.domainAllowed(r.Context(), c, dom); err != nil {
		fail(err.Error())
		return
	}
	x, err := s.addSite(r.Context(), actor(r), c, dom, d.DNS)
	if err != nil && x == nil {
		fail(storeErr(err))
		return
	}
	s.audit(r, "site.create", "site:"+dom, "dns zone: %v", d.DNS)
	if err != nil {
		s.redirectErr(w, r, "/sites/"+strconv.FormatInt(x.ID, 10), storeErr(err))
		return
	}
	s.redirect(w, r, "/sites/"+strconv.FormatInt(x.ID, 10), "The website was created.")
}

// domainAllowed refuses names below another customer's zone (one customer
// must not serve a subdomain of another customer's domain) and the
// server's own names.
func (s *Server) domainAllowed(ctx context.Context, c *store.Customer, dom string) error {
	hs := s.hostingSettings(ctx)
	if hs.ServerName != "" && hosting.IsSubdomainOf(dom, hs.ServerName) {
		return errors.New("names of the server itself cannot be used")
	}
	for _, ns := range hs.Nameservers {
		if dom == ns {
			return errors.New("names of the server itself cannot be used")
		}
	}
	if z, err := s.store.ZoneFor(ctx, dom); err == nil && z.CustomerID != c.ID {
		return errors.New("this domain belongs to another account on this server")
	}
	return nil
}

func (s *Server) mySite(w http.ResponseWriter, r *http.Request, c *store.Customer) *store.Site {
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return nil
	}
	x, err := s.store.SiteByID(r.Context(), id)
	if err != nil || x.CustomerID != c.ID {
		s.notFound(w, r)
		return nil
	}
	return x
}

type siteData struct {
	S        *store.Site
	PHP      []string
	Aliases  string
	Redirect string
	MaxUp    int
	Zone     *store.Zone
}

func (s *Server) showSite(w http.ResponseWriter, r *http.Request, status int, c *store.Customer, x *store.Site, errMsg string) {
	p, _ := s.store.PackageByID(r.Context(), c.PackageID)
	d := &siteData{S: x, PHP: s.phpVersions(r.Context()), Aliases: strings.Join(x.Aliases, "\n")}
	if p != nil {
		d.MaxUp = p.Limits.UploadMB
	}
	var lines []string
	for _, rd := range x.Redirects {
		lines = append(lines, rd.From+" "+rd.To+" "+strconv.Itoa(rd.Code))
	}
	d.Redirect = strings.Join(lines, "\n")
	d.Zone, _ = s.store.ZoneFor(r.Context(), x.Domain)
	pg := &Page{Title: x.Domain, Nav: "sites", Customer: c, Crumb: "Websites", CrumbURL: "/sites", Data: d}
	if errMsg != "" {
		pg.Error = translate(s.lang(r, userFrom(r)), errMsg)
	}
	s.render(w, r, status, "site", pg)
}

func (s *Server) handleSite(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	if x := s.mySite(w, r, c); x != nil {
		s.showSite(w, r, http.StatusOK, c, x, "")
	}
}

func parseRedirects(text string) ([]hosting.Redirect, error) {
	var out []hosting.Redirect
	for _, l := range strings.Split(text, "\n") {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		rd := hosting.Redirect{Code: 301}
		switch len(f) {
		case 2:
			rd.From, rd.To = f[0], f[1]
		case 3:
			rd.From, rd.To = f[0], f[1]
			n, err := strconv.Atoi(f[2])
			if err != nil {
				return nil, errors.New("redirects: one per line, e.g. /old /new 301")
			}
			rd.Code = n
		default:
			return nil, errors.New("redirects: one per line, e.g. /old /new 301")
		}
		out = append(out, rd)
	}
	return out, nil
}

func (s *Server) handleSiteUpdate(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	x := s.mySite(w, r, c)
	if x == nil {
		return
	}
	var aliases []string
	for _, a := range strings.Fields(strings.ReplaceAll(r.FormValue("aliases"), ",", " ")) {
		n, err := hosting.NormalizeDomain(a)
		if err != nil {
			s.showSite(w, r, http.StatusBadRequest, c, x, err.Error())
			return
		}
		if err := s.domainAllowed(r.Context(), c, n); err != nil {
			s.showSite(w, r, http.StatusBadRequest, c, x, n+": "+err.Error())
			return
		}
		aliases = append(aliases, n)
	}
	red, err := parseRedirects(r.FormValue("redirects"))
	if err != nil {
		s.showSite(w, r, http.StatusBadRequest, c, x, err.Error())
		return
	}
	docRoot, err := hosting.CleanRelPath(r.FormValue("doc_root"))
	if err != nil {
		s.showSite(w, r, http.StatusBadRequest, c, x, err.Error())
		return
	}
	php := r.FormValue("php")
	if !slices.Contains(s.phpVersions(r.Context()), php) {
		s.showSite(w, r, http.StatusBadRequest, c, x, "This PHP version is not installed.")
		return
	}
	oldPHP := x.PHPVersion
	x.Aliases, x.Redirects, x.DocRoot, x.PHPVersion = aliases, red, docRoot, php
	x.WWW = r.FormValue("www") != ""
	x.Canonical = r.FormValue("canonical")
	if x.Canonical == "www" && !x.WWW {
		x.Canonical = ""
	}
	x.ForceHTTPS, x.HSTS = r.FormValue("force_https") != "", r.FormValue("hsts") != ""
	x.Cache, x.CacheMinutes = r.FormValue("cache") != "", formInt(r, "cache_minutes")
	if x.CacheMinutes == 0 {
		x.CacheMinutes = 60
	}
	x.WordPress, x.BlockXMLRPC = r.FormValue("wordpress") != "", r.FormValue("block_xmlrpc") != ""
	x.AutoTLS = r.FormValue("auto_tls") != ""
	x.UploadMB = formInt(r, "upload_mb")
	if err := s.store.SaveSite(r.Context(), x); err != nil {
		s.showSite(w, r, http.StatusBadRequest, c, x, storeErr(err))
		return
	}
	if oldPHP != php {
		if err := s.applyCustomer(r.Context(), actor(r), c); err != nil {
			s.showSite(w, r, http.StatusBadRequest, c, x, storeErr(err))
			return
		}
	}
	if err := s.applySite(r.Context(), actor(r), x, false); err != nil {
		s.showSite(w, r, http.StatusBadRequest, c, x, storeErr(err))
		return
	}
	s.audit(r, "site.update", "site:"+x.Domain, "PHP %s, cache %v (%d min), aliases %d, redirects %d", php, x.Cache, x.CacheMinutes, len(aliases), len(red))
	s.kickCerts()
	s.redirect(w, r, "/sites/"+strconv.FormatInt(x.ID, 10), "Saved.")
}

func (s *Server) handleSitePurge(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	x := s.mySite(w, r, c)
	if x == nil {
		return
	}
	back := "/sites/" + strconv.FormatInt(x.ID, 10)
	var res struct {
		Removed int `json:"removed"`
	}
	if err := s.call(r.Context(), actor(r), "site.cache.purge", map[string]any{"account": c.Username, "id": x.ID}, &res); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.audit(r, "site.cache.purge", "site:"+x.Domain, "page cache cleared")
	s.redirect(w, r, back, "The page cache was cleared.")
}

// handleSiteCert uploads an own certificate (or switches back to automatic).
func (s *Server) handleSiteCert(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	x := s.mySite(w, r, c)
	if x == nil {
		return
	}
	back := "/sites/" + strconv.FormatInt(x.ID, 10)
	if r.FormValue("auto") != "" {
		_ = s.store.SetCert(r.Context(), x.ID, "", "", nil, nil)
		s.kickCerts()
		s.redirect(w, r, back, "A certificate will be requested automatically.")
		return
	}
	var res struct {
		NotAfter time.Time `json:"not_after"`
		Names    []string  `json:"names"`
	}
	if err := s.call(r.Context(), actor(r), "cert.install", map[string]any{"account": c.Username, "id": x.ID, "fullchain": r.FormValue("cert"), "key": r.FormValue("key")}, &res); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	_ = s.store.SetCert(r.Context(), x.ID, "uploaded", "", &res.NotAfter, res.Names)
	x.CertStatus = "uploaded"
	if err := s.applySite(r.Context(), actor(r), x, false); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.audit(r, "site.cert.upload", "site:"+x.Domain, "own certificate until %s", res.NotAfter.Format("2006-01-02"))
	s.redirect(w, r, back, "The certificate was installed.")
}

func (s *Server) handleSiteDelete(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	x := s.mySite(w, r, c)
	if x == nil {
		return
	}
	if r.FormValue("confirm") != x.Domain {
		s.redirectErr(w, r, "/sites/"+strconv.FormatInt(x.ID, 10), "Type the domain to confirm.")
		return
	}
	args := map[string]any{"account": c.Username, "id": x.ID}
	if r.FormValue("files") != "" {
		args["remove_files"] = hosting.SiteDir(x.Domain)
	}
	if err := s.call(r.Context(), actor(r), "site.delete", args, nil); err != nil {
		s.redirectErr(w, r, "/sites/"+strconv.FormatInt(x.ID, 10), storeErr(err))
		return
	}
	if err := s.store.DeleteSite(r.Context(), x.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "site.delete", "site:"+x.Domain, "files removed: %v", r.FormValue("files") != "")
	s.redirect(w, r, "/sites", "The website was deleted.")
}

type logData struct {
	S    *store.Site
	Kind string
	Text string
}

func (s *Server) handleSiteLogs(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	x := s.mySite(w, r, c)
	if x == nil {
		return
	}
	kind := r.FormValue("kind")
	if kind != "error" {
		kind = "access"
	}
	var res struct {
		Text string `json:"text"`
	}
	if err := s.call(r.Context(), actor(r), "site.log", map[string]any{"account": c.Username, "id": x.ID, "kind": kind, "lines": 300}, &res); err != nil {
		res.Text = storeErr(err)
	}
	s.render(w, r, http.StatusOK, "sitelogs", &Page{Title: "Logs", Nav: "sites", Customer: c, Crumb: x.Domain, CrumbURL: "/sites/" + strconv.FormatInt(x.ID, 10),
		Data: &logData{S: x, Kind: kind, Text: res.Text}})
}

// ---- access (SFTP / SSH)

type accessData struct {
	C    *store.Customer
	Host string
	SSH  bool
	Port int
	Keys []*store.SSHKey
}

func (s *Server) handleAccess(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	p, _ := s.store.PackageByID(r.Context(), c.PackageID)
	host := s.hostingSettings(r.Context()).ServerName
	if host == "" {
		host, _, _ = splitHostPort(r.Host)
	}
	d := &accessData{C: c, Host: host, Port: 22, SSH: p != nil && p.Limits.SSH || s.hostingSettings(r.Context()).Mode == "dedicated"}
	d.Keys, _ = s.store.SSHKeys(r.Context(), c.ID)
	s.render(w, r, http.StatusOK, "access", &Page{Title: "SFTP and SSH", Nav: "access", Customer: c, Data: d})
}

func (s *Server) handleAccessPassword(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	pw := r.FormValue("password")
	if pw != r.FormValue("password2") {
		s.redirectErr(w, r, "/access", "The passwords do not match.")
		return
	}
	if err := auth.CheckPasswordPolicy(pw); err != nil {
		s.redirectErr(w, r, "/access", err.Error())
		return
	}
	if err := s.call(r.Context(), actor(r), "account.password", map[string]string{"name": c.Username, "password": pw}, nil); err != nil {
		s.redirectErr(w, r, "/access", storeErr(err))
		return
	}
	s.audit(r, "access.password", "customer:"+c.Username, "SFTP/SSH password set")
	s.redirect(w, r, "/access", "The SFTP password was set.")
}

// ---- usage

type usageData struct {
	C       *store.Customer
	P       *store.Package
	Last    *store.UsageSample
	Samples []store.UsageSample
	DBs     []*store.Database
	Disk    []int64 // for the sparkline (KB)
	Mem     []int64
}

func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	d := &usageData{C: c}
	d.P, _ = s.store.PackageByID(r.Context(), c.PackageID)
	d.Last, _ = s.store.LastUsage(r.Context(), c.ID)
	d.Samples, _ = s.store.Usage(r.Context(), c.ID, s.now().Add(-7*24*time.Hour))
	d.DBs, _ = s.store.Databases(r.Context(), c.ID)
	for _, u := range d.Samples {
		d.Disk = append(d.Disk, u.DiskKB)
		d.Mem = append(d.Mem, u.MemoryB>>20)
	}
	s.render(w, r, http.StatusOK, "usage", &Page{Title: "Usage", Nav: "usage", Customer: c, Data: d})
}

// ---- optional two-factor sign-in for customers

func (s *Server) handleAccount2FA(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if u.TOTPEnabled {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	d := &enrollData{}
	p := &Page{Title: "Set up two-factor sign-in", Nav: "account", Data: d}
	tf, err := s.store.GetTwoFactor(r.Context(), u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if tf.Secret == "" {
		tf.Secret = auth.NewTOTPSecret()
		if err := s.store.SetPendingTOTP(r.Context(), u.ID, tf.Secret); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	d.Secret = tf.Secret
	d.QR, _ = auth.QRFor(auth.TOTPURI(tf.Secret, u.Username))
	if r.Method == http.MethodPost {
		step, ok := auth.TOTPVerify(tf.Secret, r.FormValue("code"), s.now(), 0)
		if !ok {
			s.guard.fail(r.Context(), clientIP(r), u.Username, "second factor setup")
			p.Error = p.T("The code is wrong. Check that the time of your phone is correct and try again.")
			s.render(w, r, http.StatusBadRequest, "enroll2", p)
			return
		}
		plain, hashed := auth.NewRecoveryCodes()
		if err := s.store.EnableTOTP(r.Context(), u.ID, step, hashed); err != nil {
			s.serverError(w, r, err)
			return
		}
		s.audit(r, "2fa.enable", "user:"+u.Username, "authenticator app set up")
		s.showAccount(w, r, http.StatusOK, &accountData{Codes: plain}, "")
		return
	}
	s.render(w, r, http.StatusOK, "enroll2", p)
}

func (s *Server) handleAccount2FAOff(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if s.security(r.Context()).Customer2FA {
		s.redirectErr(w, r, "/account", "Two-factor sign-in is required on this server.")
		return
	}
	if _, err := s.store.CheckPassword(r.Context(), u.Username, r.FormValue("current")); err != nil {
		s.guard.fail(r.Context(), clientIP(r), u.Username, "2fa off")
		s.redirectErr(w, r, "/account", "The current password is wrong.")
		return
	}
	if err := s.store.ResetTwoFactor(r.Context(), u.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "2fa.disable", "user:"+u.Username, "two-factor sign-in switched off")
	s.redirect(w, r, "/login", "Two-factor sign-in was switched off. Sign in again.")
}
