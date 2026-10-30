package web

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/auth"
	"github.com/max-zit/hostzit/internal/helper"
	"github.com/max-zit/hostzit/internal/hosting"
	"github.com/max-zit/hostzit/internal/netacl"
	"github.com/max-zit/hostzit/internal/store"
)

// ---- overview

type adminOverview struct {
	Counts   map[string]int
	Packages int
	Sites    int
	Zones    int
	Info     *helper.Info
	InfoErr  string
	Hosting  HostingSettings
	Problems []string
	Jobs     []*store.Job
}

func (s *Server) serverInfo(ctx context.Context) (*helper.Info, error) {
	var in helper.Info
	c, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := s.call(c, "system", "system.info", struct{}{}, &in); err != nil {
		return nil, err
	}
	return &in, nil
}

func (s *Server) handleAdminOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d := &adminOverview{Hosting: s.hostingSettings(ctx)}
	var err error
	if d.Counts, err = s.store.CustomerCounts(ctx); err != nil {
		s.serverError(w, r, err)
		return
	}
	pk, _ := s.store.Packages(ctx)
	d.Packages = len(pk)
	sites, _ := s.store.Sites(ctx, 0)
	d.Sites = len(sites)
	zones, _ := s.store.Zones(ctx, 0)
	d.Zones = len(zones)
	if d.Info, err = s.serverInfo(ctx); err != nil {
		d.InfoErr = storeErr(err)
	}
	if d.Hosting.ServerName == "" || len(d.Hosting.Nameservers) == 0 || d.Hosting.IPv4 == "" {
		d.Problems = append(d.Problems, "Set the server name, its IP address and the name servers (Settings → Hosting).")
	}
	if d.Packages == 0 {
		d.Problems = append(d.Problems, "Create a package before the first customer.")
	}
	if d.Info != nil && !d.Info.Quota {
		d.Problems = append(d.Problems, "Disk quotas are not active: disk limits of packages are not enforced.")
	}
	if d.Hosting.ACME == "" {
		d.Problems = append(d.Problems, "Automatic certificates are off (Settings → Hosting).")
	}
	for _, x := range sites {
		if x.ApplyError != "" {
			d.Problems = append(d.Problems, "Website "+x.Domain+": "+x.ApplyError)
		}
	}
	d.Jobs, _ = s.store.Jobs(ctx, 5)
	s.render(w, r, http.StatusOK, "overview", &Page{Title: "Overview", Nav: "overview", Data: d})
}

// ---- customers

type customersData struct {
	List   []*store.Customer
	Q      string
	Status string
}

func (s *Server) handleCustomers(w http.ResponseWriter, r *http.Request) {
	d := &customersData{Q: strings.TrimSpace(r.FormValue("q")), Status: r.FormValue("status")}
	if len(d.Q) > 100 {
		d.Q = d.Q[:100]
	}
	var err error
	if d.List, err = s.store.Customers(r.Context(), store.CustomerFilter{Query: d.Q, Status: d.Status}); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "customers", &Page{Title: "Customers", Nav: "customers", Data: d})
}

type customerFormData struct {
	Packages  []*store.Package
	PHP       []string
	F         map[string]string
	Dedicated bool
}

func (s *Server) phpVersions(ctx context.Context) []string {
	if in, err := s.serverInfo(ctx); err == nil && len(in.PHPVersions) > 0 {
		return in.PHPVersions
	}
	return []string{s.hostingSettings(ctx).DefaultPHP}
}

func (s *Server) showCustomerForm(w http.ResponseWriter, r *http.Request, status int, f map[string]string, errMsg string) {
	pk, err := s.store.Packages(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if f == nil {
		f = map[string]string{"dns": "on"}
	}
	p := &Page{Title: "New customer", Nav: "customers", Crumb: "Customers", CrumbURL: "/customers",
		Data: &customerFormData{Packages: pk, PHP: s.phpVersions(r.Context()), F: f, Dedicated: s.hostingSettings(r.Context()).Mode == "dedicated"}}
	if errMsg != "" {
		p.Error = translate(s.lang(r, userFrom(r)), errMsg)
	}
	s.render(w, r, status, "customerform", p)
}

func (s *Server) handleCustomerForm(w http.ResponseWriter, r *http.Request) {
	s.showCustomerForm(w, r, http.StatusOK, nil, "")
}

func formMap(r *http.Request, keys ...string) map[string]string {
	m := map[string]string{}
	for _, k := range keys {
		m[k] = strings.TrimSpace(r.FormValue(k))
	}
	return m
}

func (s *Server) handleCustomerCreate(w http.ResponseWriter, r *http.Request) {
	f := formMap(r, "username", "display_name", "email", "package", "domain", "php", "dns", "external_id")
	pkg, _ := strconv.ParseInt(f["package"], 10, 64)
	pw := r.FormValue("password")
	generated := false
	if pw == "" {
		pw, generated = auth.RandomToken(12)+"-Hz", true
	}
	n := NewAccount{NewCustomer: store.NewCustomer{Username: strings.ToLower(f["username"]), DisplayName: f["display_name"], Email: f["email"], PackageID: pkg,
		Password: pw, PHPVersion: f["php"], ExternalID: f["external_id"]}, Domain: f["domain"], DNS: f["dns"] != ""}
	c, err := s.createAccount(r.Context(), actor(r), n)
	if err != nil && c == nil {
		s.showCustomerForm(w, r, http.StatusBadRequest, f, storeErr(err))
		return
	}
	s.audit(r, "customer.create", "customer:"+c.Username, "package %s, domain %q", c.Package, n.Domain)
	msg := "Customer created."
	if generated {
		msg = translate(s.lang(r, userFrom(r)), "Customer created. The first password is %s — give it to the customer; it must be changed at the first sign-in.", pw)
		_ = s.store.SetPassword(r.Context(), c.UserID, pw, true, "")
	}
	if err != nil {
		s.redirectErr(w, r, "/customers/"+strconv.FormatInt(c.ID, 10), storeErr(err))
		return
	}
	s.redirect(w, r, "/customers/"+strconv.FormatInt(c.ID, 10), msg)
}

type customerData struct {
	C        *store.Customer
	Packages []*store.Package
	Sites    []*store.Site
	Zones    []*store.Zone
	DBs      []*store.Database
	Usage    *store.UsageSample
	Package  *store.Package
	User     *store.User
	PHP      []string
}

func (s *Server) loadCustomer(w http.ResponseWriter, r *http.Request) *store.Customer {
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return nil
	}
	c, err := s.store.CustomerByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.notFound(w, r)
		return nil
	}
	if err != nil {
		s.serverError(w, r, err)
		return nil
	}
	return c
}

func (s *Server) handleCustomer(w http.ResponseWriter, r *http.Request) {
	c := s.loadCustomer(w, r)
	if c == nil {
		return
	}
	ctx := r.Context()
	d := &customerData{C: c, PHP: s.phpVersions(ctx)}
	var err error
	if d.Packages, err = s.store.Packages(ctx); err != nil {
		s.serverError(w, r, err)
		return
	}
	d.Sites, _ = s.store.Sites(ctx, c.ID)
	d.Zones, _ = s.store.Zones(ctx, c.ID)
	d.DBs, _ = s.store.Databases(ctx, c.ID)
	d.Usage, _ = s.store.LastUsage(ctx, c.ID)
	d.Package, _ = s.store.PackageByID(ctx, c.PackageID)
	d.User, _ = s.store.UserByID(ctx, c.UserID)
	s.render(w, r, http.StatusOK, "customer", &Page{Title: c.Username, Nav: "customers", Crumb: "Customers", CrumbURL: "/customers", Data: d})
}

func (s *Server) handleCustomerUpdate(w http.ResponseWriter, r *http.Request) {
	c := s.loadCustomer(w, r)
	if c == nil {
		return
	}
	back := "/customers/" + strconv.FormatInt(c.ID, 10)
	pkg, _ := strconv.ParseInt(r.FormValue("package"), 10, 64)
	old := c.Package
	c.DisplayName, c.Email, c.PackageID = strings.TrimSpace(r.FormValue("display_name")), r.FormValue("email"), pkg
	if v := r.FormValue("php"); v == "" || hosting.ValidPHPVersion(v) {
		c.PHPVersion = v
	}
	if err := s.store.UpdateCustomer(r.Context(), c); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	c, _ = s.store.CustomerByID(r.Context(), c.ID)
	err := s.applyCustomer(r.Context(), actor(r), c)
	s.audit(r, "customer.update", "customer:"+c.Username, "package %s → %s", old, c.Package)
	if err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.redirect(w, r, back, "Saved.")
}

func (s *Server) handleCustomerStatus(w http.ResponseWriter, r *http.Request) {
	c := s.loadCustomer(w, r)
	if c == nil {
		return
	}
	back := "/customers/" + strconv.FormatInt(c.ID, 10)
	st := r.FormValue("status")
	if st != store.StatusActive && st != store.StatusSuspended && st != store.StatusTerminated {
		s.redirectErr(w, r, back, "Unknown status.")
		return
	}
	reason := strings.TrimSpace(r.FormValue("reason"))
	if st == store.StatusSuspended && reason == "" {
		reason = "admin"
	}
	err := s.setStatus(r.Context(), actor(r), c, st, reason)
	s.audit(r, "customer.status", "customer:"+c.Username, "%s → %s (%s)", c.Status, st, reason)
	if err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.redirect(w, r, back, "Saved.")
}

func (s *Server) handleCustomerReapply(w http.ResponseWriter, r *http.Request) {
	c := s.loadCustomer(w, r)
	if c == nil {
		return
	}
	back := "/customers/" + strconv.FormatInt(c.ID, 10)
	err := s.applyCustomer(r.Context(), actor(r), c)
	if err == nil {
		sites, _ := s.store.Sites(r.Context(), c.ID)
		for _, x := range sites {
			if e := s.applySite(r.Context(), actor(r), x, false); e != nil {
				err = e
			}
		}
		zones, _ := s.store.Zones(r.Context(), c.ID)
		for _, z := range zones {
			if e := s.applyZone(r.Context(), actor(r), z); e != nil {
				err = e
			}
		}
	}
	s.audit(r, "customer.apply", "customer:"+c.Username, "system configuration written again")
	if err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.redirect(w, r, back, "The account was set up again.")
}

func (s *Server) handleCustomerPassword(w http.ResponseWriter, r *http.Request) {
	c := s.loadCustomer(w, r)
	if c == nil {
		return
	}
	back := "/customers/" + strconv.FormatInt(c.ID, 10)
	pw := r.FormValue("password")
	if err := s.store.SetPassword(r.Context(), c.UserID, pw, r.FormValue("must_change") != "", ""); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.audit(r, "customer.password", "customer:"+c.Username, "panel password set by an administrator")
	s.redirect(w, r, back, "Password set.")
}

func (s *Server) handleCustomerReset2FA(w http.ResponseWriter, r *http.Request) {
	c := s.loadCustomer(w, r)
	if c == nil {
		return
	}
	if err := s.store.ResetTwoFactor(r.Context(), c.UserID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "customer.reset-2fa", "customer:"+c.Username, "two-factor sign-in removed")
	s.redirect(w, r, "/customers/"+strconv.FormatInt(c.ID, 10), "Two-factor sign-in removed.")
}

// panelURL is where customers reach their panel.
func (s *Server) panelURL(ctx context.Context, r *http.Request) string {
	if u := s.hostingSettings(ctx).PanelURL; u != "" {
		return u
	}
	host := r.Host
	if h, _, err := splitHostPort(host); err == nil {
		host = h
	}
	_, port, _ := splitListen(s.RunningPanel)
	if port == 0 {
		port = 8443
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + joinHostPort(host, port)
}

// handleCustomerLoginAs opens the customer's panel for the administrator
// (one-time link; the customer panel shows a banner and audits both names).
func (s *Server) handleCustomerLoginAs(w http.ResponseWriter, r *http.Request) {
	c := s.loadCustomer(w, r)
	if c == nil {
		return
	}
	tok, _, err := s.store.CreateSSOLink(r.Context(), c.UserID, "admin:"+userFrom(r).Username)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "customer.login-as", "customer:"+c.Username, "administrator opened the customer panel")
	http.Redirect(w, r, s.panelURL(r.Context(), r)+"/sso/"+tok, http.StatusSeeOther)
}

func (s *Server) handleCustomerDelete(w http.ResponseWriter, r *http.Request) {
	c := s.loadCustomer(w, r)
	if c == nil {
		return
	}
	if r.FormValue("confirm") != c.Username {
		s.redirectErr(w, r, "/customers/"+strconv.FormatInt(c.ID, 10), "Type the account name to confirm.")
		return
	}
	if err := s.deleteAccount(r.Context(), actor(r), c); err != nil {
		s.redirectErr(w, r, "/customers/"+strconv.FormatInt(c.ID, 10), storeErr(err))
		return
	}
	s.audit(r, "customer.delete", "customer:"+c.Username, "account and all its files deleted")
	s.redirect(w, r, "/customers", "The customer and all files were deleted.")
}

// ---- packages

func (s *Server) handlePackages(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.Packages(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "packages", &Page{Title: "Packages", Nav: "packages", Data: list})
}

type packageFormData struct {
	P   *store.Package
	PHP []string
}

func defaultPackage() *store.Package {
	return &store.Package{MaxSites: 5, MaxDBs: 5, MaxZones: 5, Limits: hosting.Limits{DiskMB: 10240, Inodes: 200000, CPUPercent: 100, MemoryMB: 1024, IOWeight: 100,
		Processes: 100, PHPWorkers: 8, PHPMemoryMB: 256, UploadMB: 64, MailPerHour: 200}}
}

func (s *Server) handlePackageForm(w http.ResponseWriter, r *http.Request) {
	p := defaultPackage()
	title := "New package"
	if id, ok := pathID(r, "id"); ok {
		var err error
		if p, err = s.store.PackageByID(r.Context(), id); err != nil {
			s.notFound(w, r)
			return
		}
		title = p.Name
	}
	s.render(w, r, http.StatusOK, "package", &Page{Title: title, Nav: "packages", Crumb: "Packages", CrumbURL: "/packages", Data: &packageFormData{P: p, PHP: s.phpVersions(r.Context())}})
}

func (s *Server) handlePackageSave(w http.ResponseWriter, r *http.Request) {
	p := &store.Package{Slug: r.FormValue("slug"), Name: r.FormValue("name"), MaxSites: formInt(r, "max_sites"), MaxDBs: formInt(r, "max_dbs"), MaxZones: formInt(r, "max_zones"),
		Limits: hosting.Limits{DiskMB: formInt(r, "disk_mb"), Inodes: formInt(r, "inodes"), CPUPercent: formInt(r, "cpu_percent"), MemoryMB: formInt(r, "memory_mb"),
			IOWeight: formInt(r, "io_weight"), Processes: formInt(r, "processes"), PHPWorkers: formInt(r, "php_workers"), PHPMemoryMB: formInt(r, "php_memory_mb"),
			UploadMB: formInt(r, "upload_mb"), AllowExec: r.FormValue("allow_exec") != "", SSH: r.FormValue("ssh") != "", MailPerHour: formInt(r, "mail_per_hour")}}
	if id, ok := pathID(r, "id"); ok {
		p.ID = id
	}
	if err := s.store.SavePackage(r.Context(), p); err != nil {
		title := p.Name
		if p.ID == 0 {
			title = "New package"
		}
		pg := &Page{Title: title, Nav: "packages", Crumb: "Packages", CrumbURL: "/packages", Data: &packageFormData{P: p, PHP: s.phpVersions(r.Context())}}
		pg.Error = translate(s.lang(r, userFrom(r)), storeErr(err))
		s.render(w, r, http.StatusBadRequest, "package", pg)
		return
	}
	s.audit(r, "package.save", "package:"+p.Slug, "disk %d MB, CPU %d %%, memory %d MB, %d sites", p.Limits.DiskMB, p.Limits.CPUPercent, p.Limits.MemoryMB, p.MaxSites)
	// customers on the package get the new limits
	if p.ID != 0 {
		list, _ := s.store.Customers(r.Context(), store.CustomerFilter{})
		for _, c := range list {
			if c.PackageID == p.ID && c.Status != store.StatusTerminated {
				if err := s.applyCustomer(r.Context(), actor(r), c); err != nil {
					s.log.Warn("limits not applied", "customer", c.Username, "err", err)
				}
			}
		}
	}
	s.redirect(w, r, "/packages", "Saved.")
}

func (s *Server) handlePackageDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := pathID(r, "id")
	if err := s.store.DeletePackage(r.Context(), id); err != nil {
		s.redirectErr(w, r, "/packages", storeErr(err))
		return
	}
	s.audit(r, "package.delete", "package:"+strconv.FormatInt(id, 10), "deleted")
	s.redirect(w, r, "/packages", "Deleted.")
}

// ---- lists over all customers

func (s *Server) handleAllSites(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.Sites(r.Context(), 0)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "allsites", &Page{Title: "Websites", Nav: "sites", Data: list})
}

func (s *Server) handleAllZones(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.Zones(r.Context(), 0)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "allzones", &Page{Title: "DNS zones", Nav: "dns", Data: list})
}

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.Jobs(r.Context(), 200)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "jobs", &Page{Title: "Jobs", Nav: "jobs", Data: list})
}

// ---- server

type serverData struct {
	Info *helper.Info
	Err  string
}

func (s *Server) handleServer(w http.ResponseWriter, r *http.Request) {
	d := &serverData{}
	var err error
	if d.Info, err = s.serverInfo(r.Context()); err != nil {
		d.Err = storeErr(err)
	}
	s.render(w, r, http.StatusOK, "server", &Page{Title: "Server", Nav: "server", Data: d})
}

func (s *Server) handleService(w http.ResponseWriter, r *http.Request) {
	name, act := r.FormValue("name"), r.FormValue("action")
	if err := s.call(r.Context(), actor(r), "service", map[string]string{"name": name, "action": act}, nil); err != nil {
		s.redirectErr(w, r, "/server", storeErr(err))
		return
	}
	s.audit(r, "service."+act, "service:"+name, "")
	s.redirect(w, r, "/server", "Done.")
}

// ---- settings

type hostingSettingsData struct {
	H   HostingSettings
	NS  string
	PHP []string
}

func (s *Server) showHostingSettings(w http.ResponseWriter, r *http.Request, status int, h HostingSettings, errMsg string) {
	p := &Page{Title: "Hosting", Nav: "settings", Data: &hostingSettingsData{H: h, NS: strings.Join(h.Nameservers, "\n"), PHP: s.phpVersions(r.Context())}}
	if errMsg != "" {
		p.Error = translate(s.lang(r, userFrom(r)), errMsg)
	}
	s.render(w, r, status, "hosting", p)
}

func (s *Server) handleHostingSettings(w http.ResponseWriter, r *http.Request) {
	s.showHostingSettings(w, r, http.StatusOK, s.hostingSettings(r.Context()), "")
}

func (s *Server) handleHostingSettingsSave(w http.ResponseWriter, r *http.Request) {
	h := HostingSettings{Mode: r.FormValue("mode"), ServerName: strings.TrimSpace(r.FormValue("server_name")), IPv4: strings.TrimSpace(r.FormValue("ipv4")),
		IPv6: strings.TrimSpace(r.FormValue("ipv6")), Nameservers: netacl.Split(r.FormValue("nameservers")), Hostmaster: strings.TrimSpace(r.FormValue("hostmaster")),
		DefaultPHP: r.FormValue("default_php"), ACME: strings.TrimSpace(r.FormValue("acme")), ACMEEmail: strings.TrimSpace(r.FormValue("acme_email")),
		GraceDays: formInt(r, "grace_days"), PanelURL: strings.TrimSpace(r.FormValue("panel_url")), SPF: strings.TrimSpace(r.FormValue("spf")),
		Secondaries: netacl.Split(r.FormValue("secondaries"))}
	if h.ACME == "custom" {
		h.ACME = strings.TrimSpace(r.FormValue("acme_url"))
	}
	if err := h.Validate(); err != nil {
		s.showHostingSettings(w, r, http.StatusBadRequest, h, err.Error())
		return
	}
	if err := s.store.SetSetting(r.Context(), settingHosting, h); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.hosting", "settings", "mode %s, server %s, %s, name servers %s, certificates %q", h.Mode, h.ServerName, h.IPv4, strings.Join(h.Nameservers, " "), h.ACME)
	if err := s.call(r.Context(), actor(r), "dns.secondaries", map[string]any{"ips": h.Secondaries}, nil); err != nil {
		s.redirectErr(w, r, "/settings/hosting", storeErr(err))
		return
	}
	// zones that could not be published (no name servers yet) go out now
	if zones, err := s.store.Zones(r.Context(), 0); err == nil {
		for _, z := range zones {
			if !z.Applied {
				_ = s.applyZone(r.Context(), actor(r), z)
			}
		}
	}
	s.kickCerts()
	s.redirect(w, r, "/settings/hosting", "Saved.")
}

func (s *Server) handleNetwork(w http.ResponseWriter, r *http.Request) {
	n, err := s.Network(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.showNetwork(w, r, http.StatusOK, n, "")
}

type networkData struct {
	N         NetworkSettings
	AdminText string
	PanelText string
	Restart   bool
	ClientIP  string
}

func (s *Server) showNetwork(w http.ResponseWriter, r *http.Request, status int, n NetworkSettings, errMsg string) {
	d := &networkData{N: n, AdminText: strings.Join(n.AdminAllowed, "\n"), PanelText: strings.Join(n.PanelAllowed, "\n"), ClientIP: clientIP(r)}
	d.Restart = !s.ListenOverride && s.RunningAdmin != "" && (n.AdminListen != s.RunningAdmin || n.PanelListen != s.RunningPanel)
	p := &Page{Title: "Network and access", Nav: "settings", Data: d}
	if errMsg != "" {
		p.Error = translate(s.lang(r, userFrom(r)), errMsg)
	}
	s.render(w, r, status, "network", p)
}

func (s *Server) handleNetworkSave(w http.ResponseWriter, r *http.Request) {
	n := NetworkSettings{AdminListen: strings.TrimSpace(r.FormValue("admin_listen")), AdminAllowed: netacl.Split(r.FormValue("admin_allowed")),
		PanelListen: strings.TrimSpace(r.FormValue("panel_listen")), PanelAllowed: netacl.Split(r.FormValue("panel_allowed"))}
	if err := n.Validate(); err != nil {
		s.showNetwork(w, r, http.StatusBadRequest, n, err.Error())
		return
	}
	ad, _ := netacl.Parse(n.AdminAllowed)
	if !netacl.NewManagement(ad).AllowsAddr(r.RemoteAddr) {
		s.showNetwork(w, r, http.StatusBadRequest, n, "Your own address would not be allowed any more. Add it to the list.")
		return
	}
	if err := s.SaveNetwork(r.Context(), n); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.network", "settings", "admin %s (%s), customers %s (%s)", n.AdminListen, strings.Join(n.AdminAllowed, ", "), n.PanelListen, strings.Join(n.PanelAllowed, ", "))
	msg := "Saved."
	if !s.ListenOverride && (n.AdminListen != s.RunningAdmin || n.PanelListen != s.RunningPanel) {
		msg = "Saved. Restart the HostZit service to use the new ports."
	}
	s.redirect(w, r, "/settings/network", msg)
}
