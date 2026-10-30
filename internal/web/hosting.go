package web

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/hostzit/internal/hosting"
	"github.com/max-zit/hostzit/internal/store"
)

const settingHosting = "hosting"

// HostingSettings describe the server as a hosting server.
type HostingSettings struct {
	// Mode is "shared" (many customers) or "dedicated" (one, no limits).
	Mode string `json:"mode"`
	// ServerName is the host name of the server (e.g. host1.example.com).
	ServerName string `json:"server_name"`
	// IPv4 / IPv6 are the addresses websites answer on (default DNS records).
	IPv4 string `json:"ipv4"`
	IPv6 string `json:"ipv6"`
	// Nameservers are the authoritative servers of hosted zones.
	Nameservers []string `json:"nameservers"`
	// Hostmaster is the contact in SOA records (an e-mail address).
	Hostmaster string `json:"hostmaster"`
	DefaultPHP string `json:"default_php"`
	// ACME is "" (off), "letsencrypt", "letsencrypt-staging" or a directory URL.
	ACME      string `json:"acme"`
	ACMEEmail string `json:"acme_email"`
	// GraceDays keep the files of a terminated customer before deletion.
	GraceDays int `json:"grace_days"`
	// PanelURL is the customer panel as customers reach it (SSO links).
	PanelURL string `json:"panel_url"`
	// SPF is the default SPF record of new zones ("" = none).
	SPF string `json:"spf"`
}

func defaultHosting() HostingSettings {
	return HostingSettings{Mode: "shared", DefaultPHP: "8.4", GraceDays: 14, SPF: "v=spf1 a mx ~all"}
}

// Validate checks the settings.
func (h *HostingSettings) Validate() error {
	if h.Mode != "shared" && h.Mode != "dedicated" {
		return errors.New("the mode must be shared or dedicated")
	}
	if h.ServerName != "" {
		n, err := hosting.NormalizeDomain(h.ServerName)
		if err != nil {
			return fmt.Errorf("server name: %w", err)
		}
		h.ServerName = n
	}
	if h.IPv4 != "" {
		a, err := netip.ParseAddr(h.IPv4)
		if err != nil || !a.Is4() {
			return errors.New("the IPv4 address is invalid")
		}
	}
	if h.IPv6 != "" {
		a, err := netip.ParseAddr(h.IPv6)
		if err != nil || !a.Is6() {
			return errors.New("the IPv6 address is invalid")
		}
	}
	if len(h.Nameservers) > 8 {
		return errors.New("at most 8 name servers")
	}
	for i, n := range h.Nameservers {
		d, err := hosting.NormalizeDomain(n)
		if err != nil {
			return fmt.Errorf("name server: %w", err)
		}
		h.Nameservers[i] = d
	}
	if h.Hostmaster != "" {
		if _, err := store.CleanEmail(h.Hostmaster); err != nil {
			return errors.New("the hostmaster address is invalid")
		}
	}
	if !hosting.ValidPHPVersion(h.DefaultPHP) {
		return errors.New("invalid default PHP version")
	}
	switch {
	case h.ACME == "", h.ACME == "letsencrypt", h.ACME == "letsencrypt-staging":
	case strings.HasPrefix(h.ACME, "https://") && len(h.ACME) < 300 && !strings.ContainsAny(h.ACME, " \r\n\"'<>"):
	default:
		return errors.New("certificates: choose Let's Encrypt or enter an ACME directory address (https://…)")
	}
	if h.ACMEEmail != "" {
		if _, err := store.CleanEmail(h.ACMEEmail); err != nil {
			return errors.New("the certificate contact address is invalid")
		}
	}
	if h.GraceDays < 0 || h.GraceDays > 365 {
		return errors.New("keep files of terminated customers 0–365 days")
	}
	if h.PanelURL != "" && (!strings.HasPrefix(h.PanelURL, "https://") || strings.ContainsAny(h.PanelURL, " \r\n\"'<>") || len(h.PanelURL) > 200) {
		return errors.New("the customer panel address must start with https://")
	}
	h.PanelURL = strings.TrimRight(h.PanelURL, "/")
	if strings.ContainsAny(h.SPF, "\r\n\"") || len(h.SPF) > 400 || h.SPF != "" && !strings.HasPrefix(h.SPF, "v=spf1") {
		return errors.New("the SPF record must start with v=spf1")
	}
	return nil
}

func (s *Server) hostingSettings(ctx context.Context) HostingSettings {
	h := defaultHosting()
	if err := s.store.GetSetting(ctx, settingHosting, &h); err != nil || h.Validate() != nil {
		return defaultHosting()
	}
	return h
}

// lockCustomer serialises system changes of one account.
func (s *Server) lockCustomer(id int64) func() {
	m, _ := s.applyMu.LoadOrStore(id, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

func (s *Server) call(ctx context.Context, by, op string, args, result any) error {
	if s.help == nil {
		return errors.New("no helper")
	}
	return s.help.CallAs(ctx, by, "", op, args, result)
}

// accountFor builds the helper's view of a customer.
func (s *Server) accountFor(ctx context.Context, c *store.Customer) (hosting.Account, *store.Package, error) {
	p, err := s.store.PackageByID(ctx, c.PackageID)
	if err != nil {
		return hosting.Account{}, nil, err
	}
	hs := s.hostingSettings(ctx)
	def := c.PHPVersion
	if def == "" {
		def = hs.DefaultPHP
	}
	versions := []string{def}
	sites, err := s.store.Sites(ctx, c.ID)
	if err != nil {
		return hosting.Account{}, nil, err
	}
	for _, x := range sites {
		if !slices.Contains(versions, x.PHPVersion) {
			versions = append(versions, x.PHPVersion)
		}
	}
	slices.Sort(versions)
	lim := p.Limits
	if hs.Mode == "dedicated" {
		lim = hosting.DedicatedLimits()
	}
	return hosting.Account{Name: c.Username, Number: c.Number, Suspended: c.Status != store.StatusActive, Limits: lim, PHPVersions: versions}, p, nil
}

// applyCustomer brings the system account in line with the database.
func (s *Server) applyCustomer(ctx context.Context, by string, c *store.Customer) error {
	defer s.lockCustomer(c.ID)()
	a, _, err := s.accountFor(ctx, c)
	if err != nil {
		return err
	}
	err = s.call(ctx, by, "account.apply", a, nil)
	_ = s.store.MarkCustomerApplied(ctx, c.ID, err)
	return err
}

// applySite writes a site's web server configuration.
func (s *Server) applySite(ctx context.Context, by string, x *store.Site, firstPage bool) error {
	c, err := s.store.CustomerByID(ctx, x.CustomerID)
	if err != nil {
		return err
	}
	_, p, err := s.accountFor(ctx, c)
	if err != nil {
		return err
	}
	spec := x.Spec(c.Status != store.StatusActive, p.Limits.UploadMB)
	args := map[string]any{"site": spec}
	if firstPage {
		args["index"] = welcomePage(x.Domain)
	}
	err = s.call(ctx, by, "site.apply", args, nil)
	_ = s.store.MarkSiteApplied(ctx, x.ID, err)
	return err
}

func welcomePage(domain string) string {
	d := html.EscapeString(domain)
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>` + d + `</title>
<style>body{font-family:system-ui,sans-serif;background:#f8fafc;color:#0f172a;display:grid;place-items:center;min-height:100vh;margin:0}main{text-align:center;padding:2rem}h1{font-size:1.6rem}p{color:#475569}</style></head>
<body><main><h1>` + d + `</h1><p>This website is ready. Upload your files or install WordPress in the control panel.</p></main></body></html>
`
}

// defaultRecords are the first records of a new zone.
func (s *Server) defaultRecords(ctx context.Context) []hosting.Record {
	hs := s.hostingSettings(ctx)
	var r []hosting.Record
	if hs.IPv4 != "" {
		r = append(r, hosting.Record{Name: "@", Type: "A", Content: hs.IPv4}, hosting.Record{Name: "www", Type: "A", Content: hs.IPv4})
	}
	if hs.IPv6 != "" {
		r = append(r, hosting.Record{Name: "@", Type: "AAAA", Content: hs.IPv6}, hosting.Record{Name: "www", Type: "AAAA", Content: hs.IPv6})
	}
	r = append(r, hosting.Record{Name: "@", Type: "CAA", Content: `0 issue "letsencrypt.org"`})
	if hs.SPF != "" {
		r = append(r, hosting.Record{Name: "@", Type: "TXT", Content: hs.SPF})
	}
	return r
}

// applyZone publishes a zone on the DNS server.
func (s *Server) applyZone(ctx context.Context, by string, z *store.Zone) error {
	hs := s.hostingSettings(ctx)
	if len(hs.Nameservers) == 0 {
		err := errors.New("no name servers are set (Settings → Hosting)")
		_ = s.store.MarkZoneApplied(ctx, z.ID, err)
		return err
	}
	recs, err := s.store.Records(ctx, z.ID)
	if err != nil {
		return err
	}
	list := make([]hosting.Record, 0, len(recs))
	for _, r := range recs {
		list = append(list, r.Record)
	}
	hm := ""
	if hs.Hostmaster != "" {
		hm = strings.Replace(hs.Hostmaster, "@", ".", 1)
	}
	err = s.call(ctx, by, "dns.apply", map[string]any{"zone": z.Name, "nameservers": hs.Nameservers, "records": list, "hostmaster": hm}, nil)
	_ = s.store.MarkZoneApplied(ctx, z.ID, err)
	return err
}

// NewAccount is a customer with an optional first website.
type NewAccount struct {
	store.NewCustomer
	Domain string
	// DNS creates a zone for the domain on this server.
	DNS bool
}

// createAccount creates a customer, its system account and the first site.
func (s *Server) createAccount(ctx context.Context, by string, n NewAccount) (*store.Customer, error) {
	hs := s.hostingSettings(ctx)
	if hs.Mode == "dedicated" {
		counts, err := s.store.CustomerCounts(ctx)
		if err != nil {
			return nil, err
		}
		if counts[store.StatusActive]+counts[store.StatusSuspended] > 0 {
			return nil, errors.New("this is a dedicated server: it has one customer account")
		}
	}
	var domain string
	if strings.TrimSpace(n.Domain) != "" {
		d, err := hosting.NormalizeDomain(n.Domain)
		if err != nil {
			return nil, err
		}
		domain = d
		if _, err := s.store.SiteForName(ctx, d); err == nil {
			return nil, fmt.Errorf("%s is already used on this server", d)
		}
	}
	c, err := s.store.CreateCustomer(ctx, n.NewCustomer)
	if err != nil {
		return nil, err
	}
	if err := s.applyCustomer(ctx, by, c); err != nil {
		return c, fmt.Errorf("the account was saved but the system account could not be set up: %w", err)
	}
	if domain != "" {
		if _, err := s.addSite(ctx, by, c, domain, n.DNS); err != nil {
			return c, err
		}
	}
	return s.store.CustomerByID(ctx, c.ID)
}

// addSite creates a site (and its DNS zone when asked) for a customer,
// checking the package limits.
func (s *Server) addSite(ctx context.Context, by string, c *store.Customer, domain string, dns bool) (*store.Site, error) {
	p, err := s.store.PackageByID(ctx, c.PackageID)
	if err != nil {
		return nil, err
	}
	sites, _, zones, err := s.store.CountFor(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	if s.hostingSettings(ctx).Mode != "dedicated" && sites >= p.MaxSites {
		return nil, fmt.Errorf("the package allows %d websites", p.MaxSites)
	}
	hs := s.hostingSettings(ctx)
	php := c.PHPVersion
	if php == "" {
		php = hs.DefaultPHP
	}
	x := &store.Site{CustomerID: c.ID, Account: c.Username, Domain: domain, DocRoot: hosting.DefaultDocRoot(domain), PHPVersion: php, WWW: !strings.HasPrefix(domain, "www."),
		Canonical: "bare", ForceHTTPS: true, CacheMinutes: 60, UploadMB: p.Limits.UploadMB, AutoTLS: true}
	if !x.WWW {
		x.Canonical = ""
	}
	if err := s.store.SaveSite(ctx, x); err != nil {
		return nil, err
	}
	if err := s.applySite(ctx, by, x, true); err != nil {
		return x, fmt.Errorf("the website was saved but the web server could not be set up: %w", err)
	}
	if dns {
		if _, err := s.store.ZoneFor(ctx, domain); errors.Is(err, store.ErrNotFound) && (hs.Mode == "dedicated" || zones < p.MaxZones) {
			z, err := s.store.CreateZone(ctx, c.ID, domain, s.defaultRecords(ctx))
			if err != nil {
				return x, err
			}
			if err := s.applyZone(ctx, by, z); err != nil {
				return x, fmt.Errorf("the DNS zone was saved but could not be published: %w", err)
			}
		}
	}
	s.kickCerts()
	return x, nil
}

// setStatus suspends, unsuspends or terminates a customer and applies it.
func (s *Server) setStatus(ctx context.Context, by string, c *store.Customer, status, reason string) error {
	var del *time.Time
	if status == store.StatusTerminated {
		t := s.now().AddDate(0, 0, s.hostingSettings(ctx).GraceDays)
		del = &t
	}
	if err := s.store.SetCustomerStatus(ctx, c.ID, status, reason, del); err != nil {
		return err
	}
	c, err := s.store.CustomerByID(ctx, c.ID)
	if err != nil {
		return err
	}
	if err := s.applyCustomer(ctx, by, c); err != nil {
		return err
	}
	sites, err := s.store.Sites(ctx, c.ID)
	if err != nil {
		return err
	}
	var errs []error
	for _, x := range sites {
		if err := s.applySite(ctx, by, x, false); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// deleteAccount removes everything of a customer.
func (s *Server) deleteAccount(ctx context.Context, by string, c *store.Customer) error {
	sites, err := s.store.Sites(ctx, c.ID)
	if err != nil {
		return err
	}
	for _, x := range sites {
		if err := s.call(ctx, by, "site.delete", map[string]any{"account": c.Username, "id": x.ID}, nil); err != nil {
			return err
		}
	}
	zones, err := s.store.Zones(ctx, c.ID)
	if err != nil {
		return err
	}
	for _, z := range zones {
		if err := s.call(ctx, by, "dns.delete", map[string]any{"zone": z.Name}, nil); err != nil {
			s.log.Warn("zone not removed from the DNS server", "zone", z.Name, "err", err)
		}
	}
	dbs, err := s.store.Databases(ctx, c.ID)
	if err != nil {
		return err
	}
	for _, d := range dbs {
		if err := s.call(ctx, by, "db.drop", map[string]any{"account": c.Username, "name": d.Name}, nil); err != nil {
			return err
		}
	}
	users, err := s.store.DBUsers(ctx, c.ID)
	if err != nil {
		return err
	}
	for _, u := range users {
		if err := s.call(ctx, by, "db.user.drop", map[string]any{"account": c.Username, "user": u.Name}, nil); err != nil {
			return err
		}
	}
	if err := s.call(ctx, by, "account.delete", map[string]any{"name": c.Username, "number": c.Number}, nil); err != nil {
		return err
	}
	return s.store.DeleteCustomer(ctx, c.ID)
}

// runJob runs work in the background and records it as a job.
func (s *Server) runJob(kind string, customerID *int64, detail string, fn func(ctx context.Context) error) (*store.Job, error) {
	j, err := s.store.CreateJob(context.Background(), kind, customerID, detail)
	if err != nil {
		return nil, err
	}
	s.jobs.Add(1)
	go func() {
		defer s.jobs.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		_ = s.store.StartJob(ctx, j.ID)
		err := fn(ctx)
		if err != nil {
			s.log.Warn("job failed", "kind", kind, "id", j.ID, "err", err)
		}
		_ = s.store.FinishJob(ctx, j.ID, err)
	}()
	return j, nil
}

// Run does the periodic work: usage samples, certificates, deletion of
// terminated customers after their grace period.
func (s *Server) Run(ctx context.Context) {
	_ = s.store.FailStaleJobs(ctx)
	usage := time.NewTicker(10 * time.Minute)
	hourly := time.NewTicker(time.Hour)
	defer usage.Stop()
	defer hourly.Stop()
	go s.runCerts(ctx)
	go func() {
		// the firewall table and the mail relay live in files of the helper; load them
		time.Sleep(2 * time.Second)
		_ = s.applyFirewall(ctx, "system")
		_ = s.applyRelay(ctx, "system")
	}()
	time.AfterFunc(time.Minute, func() { s.collectUsage(ctx) })
	for {
		select {
		case <-ctx.Done():
			return
		case <-usage.C:
			s.collectUsage(ctx)
			s.checkNotices(ctx)
		case <-hourly.C:
			_ = s.store.PurgeSessions(ctx)
			_ = s.store.PruneUsage(ctx)
			s.purgeTerminated(ctx)
			if s.now().Hour() == 3 {
				go s.autoUpdateWP(ctx)
				if _, err := s.consoleBackupNow(ctx); err != nil && err.Error() != "no passphrase set" {
					s.log.Warn("nightly panel backup failed", "err", err)
				}
			}
		}
	}
}

func (s *Server) purgeTerminated(ctx context.Context) {
	ids, err := s.store.DueForDeletion(ctx)
	if err != nil {
		return
	}
	for _, id := range ids {
		c, err := s.store.CustomerByID(ctx, id)
		if err != nil {
			continue
		}
		if err := s.deleteAccount(ctx, "system", c); err != nil {
			s.log.Warn("deleting a terminated customer failed", "customer", c.Username, "err", err)
			continue
		}
		_ = s.store.Audit(ctx, "system", "local", "customer.delete", "customer:"+c.Username, "deleted after the grace period")
	}
}

// helperUsage is the helper's answer to account.usage.
type helperUsage struct {
	DiskKB   int64 `json:"disk_kb"`
	Inodes   int64 `json:"inodes"`
	MemoryB  int64 `json:"memory_b"`
	CPUUsec  int64 `json:"cpu_usec"`
	Tasks    int64 `json:"tasks"`
	IOReadB  int64 `json:"io_read_b"`
	IOWriteB int64 `json:"io_write_b"`
}

func (s *Server) collectUsage(ctx context.Context) {
	list, err := s.store.Customers(ctx, store.CustomerFilter{})
	if err != nil {
		return
	}
	now := s.now().Truncate(time.Minute)
	for _, c := range list {
		if c.Status == store.StatusTerminated || !c.Applied {
			continue
		}
		var u helperUsage
		if err := s.call(ctx, "system", "account.usage", map[string]string{"account": c.Username}, &u); err != nil {
			continue
		}
		var sizes map[string]int64
		var dbb int64
		if err := s.call(ctx, "system", "db.usage", map[string]string{"account": c.Username}, &sizes); err == nil {
			_ = s.store.SetDatabaseSizes(ctx, c.ID, sizes)
			for _, b := range sizes {
				dbb += b
			}
		}
		_ = s.store.AddUsage(ctx, c.ID, store.UsageSample{At: now, DiskKB: u.DiskKB, Inodes: u.Inodes, DBB: dbb, MemoryB: u.MemoryB, CPUUsec: u.CPUUsec, IOB: u.IOReadB + u.IOWriteB, Tasks: int(u.Tasks)})
	}
}
