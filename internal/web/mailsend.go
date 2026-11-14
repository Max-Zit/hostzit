package web

import (
	"context"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/helper"
	"github.com/max-zit/hostzit/internal/hosting"
	"github.com/max-zit/hostzit/internal/store"
)

// Mail from websites (zit-hosting/INTEGRATION.md, "Mail from websites"):
//
//   - EmailZit on this server: emailzit-sendmail in every cage (P7);
//   - EmailZit linked on another server: its relay login of the link;
//   - an SMTP server the administrator set for websites;
//   - otherwise HostZit delivers the mail itself, signed with a DKIM key
//     per domain (published in the zones here, shown to copy otherwise).
//
// The helper's mailer knows each account's domains and keys from
// /etc/hostzit/mail/<account>.json; syncMailAccount keeps that file, the
// keys in the database and the DKIM records of the zones in line.

// dkimOwner owns HostZit's DKIM records in the zones.
const dkimOwner = "hostzit-mail"

// settingMailCheck keeps the last check of direct sending.
const settingMailCheck = "mailcheck"

func init() {
	adminExtra = append(adminExtra, func(s *Server, mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc)) {
		admin("POST /settings/mail/check", s.handleMailCheck)
	})
}

// mailMode is how website mail leaves this server: local, emailzit, relay
// or direct.
func (s *Server) mailMode(ctx context.Context) string {
	if localEmailZit() {
		return "local"
	}
	if l := s.emailzitLink(ctx); l.URL != "" && l.Relay != nil {
		return "emailzit"
	}
	if m := s.mailSettings(ctx); m.WebRelay && m.Host != "" {
		return "relay"
	}
	return "direct"
}

// applyRelay tells the helper where mail from websites goes.
func (s *Server) applyRelay(ctx context.Context, by string) error {
	hs := s.hostingSettings(ctx)
	relay := map[string]any{"mode": "direct", "helo": hs.ServerName}
	switch s.mailMode(ctx) {
	case "emailzit":
		l := s.emailzitLink(ctx)
		pw, err := s.store.OpenSecret("emailzit.relay", l.Relay.Password)
		if err != nil {
			return err
		}
		// EmailZit takes the login only after STARTTLS (and so do we)
		relay = map[string]any{"mode": "emailzit", "host": l.Relay.Host, "port": l.Relay.Port, "security": "starttls", "user": l.Relay.Username, "password": pw, "helo": hs.ServerName}
	case "relay":
		m := s.mailSettings(ctx)
		pw, _ := s.store.OpenSecret("mail.password", m.Password)
		relay = map[string]any{"mode": "relay", "host": m.Host, "port": m.Port, "security": m.Security, "user": m.User, "password": pw, "domain": hs.ServerName, "helo": hs.ServerName}
	}
	return s.call(ctx, by, "mail.relay", map[string]any{"relay": relay}, nil)
}

// keyDomain is the domain whose DKIM key signs mail from d: the customer's
// zone that holds d, else d without a leading www.
func keyDomain(d string, zones []string) string {
	d = strings.ToLower(strings.TrimSuffix(d, "."))
	best := ""
	for _, z := range zones {
		if (d == z || strings.HasSuffix(d, "."+z)) && len(z) > len(best) {
			best = z
		}
	}
	if best != "" {
		return best
	}
	if rest, ok := strings.CutPrefix(d, "www."); ok && strings.Contains(rest, ".") {
		return rest
	}
	return d
}

// mailDomains are the domains an account may send website mail from (each
// with its subdomains), the primary one first.
func (s *Server) mailDomains(ctx context.Context, c *store.Customer) (domains []string, zones []*store.Zone) {
	sites, _ := s.store.Sites(ctx, c.ID)
	zones, _ = s.store.Zones(ctx, c.ID)
	var zn []string
	for _, z := range zones {
		zn = append(zn, z.Name)
	}
	add := func(d string) {
		k := keyDomain(d, zn)
		if hosting.ValidDomain(k) && !slices.Contains(domains, k) && len(domains) < 100 {
			domains = append(domains, k)
		}
	}
	for _, x := range sites {
		add(x.Domain)
		for _, a := range x.Aliases {
			add(a)
		}
	}
	for _, z := range zn {
		add(z)
	}
	return domains, zones
}

// syncMailAccount brings the account's mail domains, DKIM keys and DKIM
// records in line.
func (s *Server) syncMailAccount(ctx context.Context, by string, c *store.Customer) {
	if c == nil || c.Status == store.StatusTerminated {
		return
	}
	domains, zones := s.mailDomains(ctx, c)
	have, err := s.store.DKIMKeys(ctx, c.ID)
	if err != nil {
		s.log.Warn("DKIM keys", "customer", c.Username, "err", err)
		return
	}
	keys := map[string]store.DKIMKey{}
	for _, k := range have {
		keys[k.Domain] = k
	}
	for _, d := range domains {
		if _, ok := keys[d]; ok {
			continue
		}
		priv, rec, err := helper.NewDKIMKey()
		if err != nil {
			s.log.Warn("DKIM key", "domain", d, "err", err)
			continue
		}
		k := store.DKIMKey{Domain: d, CustomerID: c.ID, Selector: helper.DKIMSelector, PrivateKey: priv, Record: rec}
		if err := s.store.SaveDKIMKey(ctx, k); err != nil {
			s.log.Warn("DKIM key", "domain", d, "err", err)
			continue
		}
		keys[d] = k
	}
	_ = s.store.DeleteDKIMKeys(ctx, c.ID, domains)
	relay := s.relaySPF(ctx)
	// the records of the zones here
	for _, z := range zones {
		s.syncRelaySPF(ctx, by, z, relay)
		var want []hosting.Record
		if k, ok := keys[z.Name]; ok {
			want = []hosting.Record{{Name: k.Selector + "._domainkey", Type: "TXT", TTL: 3600, Content: k.Record}}
		}
		if s.dkimRecordsSame(ctx, z, want) {
			continue
		}
		if _, err := s.store.ReplaceOwnedRecords(ctx, z, dkimOwner, want); err != nil {
			s.log.Warn("DKIM record", "zone", z.Name, "err", err)
			continue
		}
		if err := s.applyZone(ctx, by, z); err != nil {
			s.log.Warn("DKIM record not published", "zone", z.Name, "err", err)
		}
	}
	ma := helper.MailAccount{Domains: domains}
	if len(domains) > 0 {
		ma.Primary = domains[0]
	}
	for _, d := range domains {
		if k, ok := keys[d]; ok {
			ma.DKIM = append(ma.DKIM, helper.DKIMKey{Domain: d, Selector: k.Selector, Key: k.PrivateKey})
		}
	}
	if err := s.call(ctx, by, "mail.account", map[string]any{"account": c.Username, "mail": ma}, nil); err != nil {
		s.log.Warn("website mail domains not sent to the helper", "customer", c.Username, "err", err)
	}
}

// dkimRecordsSame compares the zone's DKIM records with want.
func (s *Server) dkimRecordsSame(ctx context.Context, z *store.Zone, want []hosting.Record) bool {
	rows, err := s.store.Records(ctx, z.ID)
	if err != nil {
		return false
	}
	var have []hosting.Record
	for _, r := range rows {
		if r.Owner == dkimOwner {
			have = append(have, r.Record)
		}
	}
	if len(have) != len(want) {
		return false
	}
	for i := range want {
		c, err := hosting.CleanRecord(want[i], z.Name)
		if err != nil || have[i].Name != c.Name || have[i].Type != c.Type || have[i].Content != c.Content || have[i].TTL != c.TTL {
			return false
		}
	}
	return true
}

// syncAllMail runs syncMailAccount for every customer (a safety net for
// changes that did not pass applyCustomer or applySite).
func (s *Server) syncAllMail(ctx context.Context) {
	list, err := s.store.Customers(ctx, store.CustomerFilter{})
	if err != nil {
		return
	}
	for _, c := range list {
		if ctx.Err() != nil {
			return
		}
		s.syncMailAccount(ctx, "system", c)
	}
}

// ---- the check of direct sending

func (s *Server) mailCheck(ctx context.Context) *helper.MailCheck {
	var m helper.MailCheck
	if err := s.store.GetSetting(ctx, settingMailCheck, &m); err != nil || m.At.IsZero() {
		return nil
	}
	return &m
}

// refreshMailCheck tries outgoing port 25 and the reverse names.
func (s *Server) refreshMailCheck(ctx context.Context) (*helper.MailCheck, error) {
	hs := s.hostingSettings(ctx)
	var m helper.MailCheck
	c, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if err := s.call(c, "system", "mail.check", map[string]any{"helo": hs.ServerName, "ips": s.ownAddresses(ctx)}, &m); err != nil {
		return nil, err
	}
	_ = s.store.SetSetting(ctx, settingMailCheck, m)
	return &m, nil
}

func (s *Server) handleMailCheck(w http.ResponseWriter, r *http.Request) {
	if _, err := s.refreshMailCheck(r.Context()); err != nil {
		s.redirectErr(w, r, "/settings/mail", storeErr(err))
		return
	}
	s.redirect(w, r, "/settings/mail#websites", "Checked.")
}

// mailProblems are the overview's notes about website mail.
func (s *Server) mailProblems(ctx context.Context) []string {
	if s.mailMode(ctx) != "direct" {
		return nil
	}
	m := s.mailCheck(ctx)
	if m == nil {
		return nil
	}
	var out []string
	if !m.Port25 {
		out = append(out, "Websites cannot send mail: this server cannot reach port 25 of other mail servers (the provider may block it). Link EmailZit or set a mail server for websites under Settings → Notifications.")
	}
	for _, p := range m.PTR {
		if !p.OK {
			out = append(out, "The reverse DNS name of a server address is not the server name, so large mail providers may refuse website mail. Ask the provider of the server to set it (Settings → Notifications shows the names).")
			break
		}
	}
	return out
}

// ---- what the customer sees

// dkimRow is one domain's DKIM record on the customer's security page.
type dkimRow struct {
	Domain string
	Name   string // the record's full name
	Value  string
	Here   bool // the zone is in this server's DNS: HostZit publishes it
	Found  bool // the record is in the public DNS
	// SPFNeed is the mechanism the domain's SPF needs; SPFOK: it has it
	SPFNeed string
	SPFOK   bool
}

// websiteMail is the mail part of the customer's security page.
type websiteMail struct {
	Mode  string
	DKIM  []dkimRow
	Log   []helper.MailLogEntry
	Queue []helper.QueueItem
}

func (s *Server) websiteMail(ctx context.Context, by string, c *store.Customer) *websiteMail {
	d := &websiteMail{Mode: s.mailMode(ctx)}
	if d.Mode == "direct" || d.Mode == "emailzit" {
		keys, _ := s.store.DKIMKeys(ctx, c.ID)
		zones, _ := s.store.Zones(ctx, c.ID)
		hs := s.hostingSettings(ctx)
		mech := s.relaySPF(ctx)
		if mech == "" && hs.ServerName != "" {
			mech = "a:" + hs.ServerName
		}
		for _, k := range keys {
			row := dkimRow{Domain: k.Domain, Name: k.Selector + "._domainkey." + k.Domain, Value: k.Record, SPFNeed: mech}
			var zone *store.Zone
			for _, z := range zones {
				if z.Name == k.Domain {
					zone = z
				}
			}
			row.Here = zone != nil
			var spf string
			if zone != nil {
				if rows, err := s.store.Records(ctx, zone.ID); err == nil {
					for _, r := range rows {
						if v := unquoteTXT(r.Content); r.Name == "@" && r.Type == "TXT" && strings.HasPrefix(v, "v=spf1") {
							spf = v
						}
					}
				}
			} else {
				lc, cancel := context.WithTimeout(ctx, 3*time.Second)
				txt, err := net.DefaultResolver.LookupTXT(lc, row.Name)
				row.Found = err == nil && slices.Contains(txt, k.Record)
				if all, err := net.DefaultResolver.LookupTXT(lc, k.Domain); err == nil {
					for _, v := range all {
						if strings.HasPrefix(v, "v=spf1") {
							spf = v
						}
					}
				}
				cancel()
			}
			// direct sending from a zone here: HostZit's own "a" record covers
			// the server; otherwise the mechanism must be in the record
			row.SPFOK = spf != "" && (slices.Contains(strings.Fields(spf), mech) ||
				d.Mode == "direct" && zone != nil && slices.Contains(strings.Fields(spf), "a") ||
				d.Mode == "direct" && hs.IPv4 != "" && strings.Contains(spf, "ip4:"+hs.IPv4))
			d.DKIM = append(d.DKIM, row)
		}
	}
	_ = s.call(ctx, by, "mail.log", map[string]string{"account": c.Username}, &d.Log)
	_ = s.call(ctx, by, "mail.queue", map[string]string{"account": c.Username}, &d.Queue)
	if len(d.Log) > 100 {
		d.Log = d.Log[:100]
	}
	return d
}

// mailFailureNotices tells the administrators (and the customer, when
// customers are told) about website mail that bounced, was refused or was
// dropped, at most once a day per account.
func (s *Server) mailFailureNotices(ctx context.Context) {
	var f map[string]helper.MailFailures
	if err := s.call(ctx, "system", "mail.failures", struct{}{}, &f); err != nil {
		return
	}
	for account, x := range f {
		if x.N == 0 {
			continue
		}
		c, err := s.store.CustomerByRef(ctx, account)
		if err != nil {
			continue
		}
		s.notify(ctx, "mail:"+account, c, "Website mail of "+account+" was not delivered",
			"Messages from the websites of "+account+" could not be delivered ("+strconv.Itoa(x.N)+" since the last notice). The last one: "+x.Last+"\n\nThe customer sees every message under Security → Mail from your websites.\n")
	}
}

// sendmailFor is EmailZit's sendmail for a customer a local EmailZit knows,
// else "" (HostZit's own queue).
func (s *Server) sendmailFor(ctx context.Context, c *store.Customer) string {
	if localEmailZit() && s.emailzitKnows(ctx, c.UUID) {
		return "/usr/sbin/emailzit-sendmail"
	}
	return ""
}

// syncLocalEmailZit asks a local EmailZit about every customer (it may have
// got customers since), so their websites use the right sendmail.
func (s *Server) syncLocalEmailZit(ctx context.Context) {
	if !localEmailZit() || s.emailzitLink(ctx).URL == "" {
		return
	}
	list, err := s.store.Customers(ctx, store.CustomerFilter{})
	if err != nil {
		return
	}
	for _, c := range list {
		if ctx.Err() != nil {
			return
		}
		s.syncWebUIDs(ctx, c)
	}
}

// relaySPF is the SPF mechanism of EmailZit's relay while website mail
// goes through it ("" otherwise).
func (s *Server) relaySPF(ctx context.Context) string {
	if s.mailMode(ctx) != "emailzit" {
		return ""
	}
	return "a:" + s.emailzitLink(ctx).Relay.Host
}

// spfWith puts a mechanism into an SPF record, before its "all".
func spfWith(spf, mech string) string {
	f := strings.Fields(spf)
	if n := len(f); n > 0 && strings.TrimLeft(f[n-1], "+-~?") == "all" {
		return strings.Join(append(append(f[:n-1:n-1], mech), f[n-1]), " ")
	}
	return strings.Join(append(f, mech), " ")
}

// spfDefaultWithRelay reports whether an SPF value is def with one "a:"
// mechanism HostZit added for a relay.
func spfDefaultWithRelay(v, def string) bool {
	f := strings.Fields(v)
	for i, x := range f {
		if strings.HasPrefix(x, "a:") {
			rest := append(append([]string{}, f[:i]...), f[i+1:]...)
			return strings.Join(rest, " ") == strings.Join(strings.Fields(def), " ")
		}
	}
	return false
}

func unquoteTXT(c string) string {
	c = strings.TrimSpace(c)
	if strings.HasPrefix(c, `"`) && strings.HasSuffix(c, `"`) && !strings.Contains(c, `" "`) {
		c = c[1 : len(c)-1]
	}
	return strings.NewReplacer(`\"`, `"`, `\`, `\`).Replace(c)
}

// syncRelaySPF keeps EmailZit's mail host in the zone's SPF while website
// mail goes through EmailZit's relay (EmailZit, INTEGRATION.md 7), and
// takes it out again after an unlink. Only an SPF record that is still
// HostZit's default is changed; one the customer wrote stays as it is (the
// Security page tells what it needs).
func (s *Server) syncRelaySPF(ctx context.Context, by string, z *store.Zone, mech string) {
	def := s.hostingSettings(ctx).SPF
	if def == "" {
		return
	}
	want := def
	if mech != "" {
		want = spfWith(def, mech)
	}
	rows, err := s.store.Records(ctx, z.ID)
	if err != nil {
		return
	}
	for _, r := range rows {
		if r.Owner != "" || r.Name != "@" || r.Type != "TXT" {
			continue
		}
		v := unquoteTXT(r.Content)
		if !strings.HasPrefix(v, "v=spf1") {
			continue
		}
		if v == want || (v != def && !spfDefaultWithRelay(v, def)) {
			return
		}
		rec := r.Record
		rec.Content = want
		if err := s.store.UpdateRecord(ctx, z, r.ID, rec); err != nil {
			s.log.Warn("SPF record for EmailZit's relay", "zone", z.Name, "err", err)
			return
		}
		if err := s.applyZone(ctx, by, z); err != nil {
			s.log.Warn("SPF record not published", "zone", z.Name, "err", err)
		}
		return
	}
}
