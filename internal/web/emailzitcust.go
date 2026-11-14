package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/helper"
	"github.com/max-zit/hostzit/internal/hosting"
	"github.com/max-zit/hostzit/internal/store"
)

// Which EmailZit a customer's mail is on. A customer (same UUID in both
// products) has its mail on at most one EmailZit; HostZit asks the linked
// EmailZit servers GET /api/v1/customers/{uuid} (200 = there, 404 = not)
// and remembers the answer: every hour, after a pairing, and when the
// customer presses the EmailZit switch. A link serves only the customers of
// its scope, so an EmailZit of one client never learns about, opens or
// writes the DNS of another client's customers.

// customerLinkMap is customer UUID → link id.
func (s *Server) customerLinkMap(ctx context.Context) map[string]string {
	m := map[string]string{}
	_ = s.store.GetSetting(ctx, settingEmailZitCustomers, &m)
	if m == nil {
		m = map[string]string{}
	}
	return m
}

// inScope reports whether a link may serve a customer: an "assigned" link
// only its customers, the others every customer not assigned to a link.
func inScope(l EmailZitLink, uuid string, all []EmailZitLink) bool {
	if l.Scope == "assigned" {
		return slices.Contains(l.Customers, uuid)
	}
	for _, o := range all {
		if o.ID != l.ID && o.Scope == "assigned" && slices.Contains(o.Customers, uuid) {
			return false
		}
	}
	return true
}

// linkFor is the EmailZit a customer's mail is on (as last found).
func (s *Server) linkFor(ctx context.Context, c *store.Customer) (EmailZitLink, bool) {
	id := s.customerLinkMap(ctx)[c.UUID]
	if id == "" {
		return EmailZitLink{}, false
	}
	all := s.emailzitLinks(ctx)
	for _, l := range all {
		if l.ID == id && inScope(l, c.UUID, all) {
			return l, true
		}
	}
	return EmailZitLink{}, false
}

// resolveCustomer asks the links in scope whether they have the customer
// and remembers the answer. A link that cannot be asked keeps what was
// known about it.
func (s *Server) resolveCustomer(ctx context.Context, c *store.Customer) (EmailZitLink, bool) {
	return s.resolveCustomerSkip(ctx, c, nil)
}

// resolveCustomerSkip is resolveCustomer; links in skip (unreachable in this
// round) are not asked again and count as "cannot tell".
func (s *Server) resolveCustomerSkip(ctx context.Context, c *store.Customer, skip map[string]bool) (EmailZitLink, bool) {
	all := s.emailzitLinks(ctx)
	cur := s.customerLinkMap(ctx)[c.UUID]
	var found []EmailZitLink
	curUnknown := false
	for _, l := range all {
		if !inScope(l, c.UUID, all) {
			continue
		}
		if skip[l.ID] {
			curUnknown = curUnknown || l.ID == cur
			continue
		}
		st, _, err := s.emailzitDo(ctx, l, http.MethodGet, "/api/v1/customers/"+url.PathEscape(c.UUID), nil)
		switch {
		case err == nil && st >= 200 && st < 300:
			found = append(found, l)
		case err == nil && st == http.StatusNotFound:
			// not there
		default:
			// cannot tell (unreachable, refused, busy): never move a customer
			// away from its EmailZit because of it
			curUnknown = curUnknown || l.ID == cur
			if err != nil && skip != nil {
				skip[l.ID] = true
			}
		}
	}
	if curUnknown {
		return s.linkFor(ctx, c)
	}
	for _, l := range found {
		if l.ID == cur {
			return l, true
		}
	}
	if len(found) > 1 {
		names := make([]string, 0, len(found))
		for _, l := range found {
			names = append(names, l.Name())
		}
		s.log.Warn("a customer is on more than one EmailZit; none is used until only one has it", "customer", c.Username, "emailzit", strings.Join(names, ", "))
		s.notify(ctx, "mail-link-conflict:"+c.UUID, nil, "Customer "+c.Username+" is on more than one EmailZit",
			"The EmailZit servers "+strings.Join(names, ", ")+" all say they have customer "+c.Username+". HostZit uses none of them for this customer until only one has it (or the customer is assigned to one link under Settings → EmailZit).\n")
		s.setCustomerLink(ctx, c.UUID, "")
		return EmailZitLink{}, false
	}
	if len(found) == 1 {
		s.setCustomerLink(ctx, c.UUID, found[0].ID)
		return found[0], true
	}
	s.setCustomerLink(ctx, c.UUID, "")
	return EmailZitLink{}, false
}

// resolveAllCustomers finds every customer's EmailZit; a customer whose
// EmailZit changed gets its website mail (and sendmail) set again.
func (s *Server) resolveAllCustomers(ctx context.Context) {
	if !s.resolving.CompareAndSwap(false, true) {
		return // one run at a time
	}
	defer s.resolving.Store(false)
	if len(s.emailzitLinks(ctx)) == 0 {
		s.ezMu.Lock()
		if m := s.customerLinkMap(ctx); len(m) > 0 {
			_ = s.store.SetSetting(ctx, settingEmailZitCustomers, map[string]string{})
		}
		s.ezMu.Unlock()
		return
	}
	list, err := s.store.Customers(ctx, store.CustomerFilter{})
	if err != nil {
		return
	}
	skip := map[string]bool{}
	for _, c := range list {
		if ctx.Err() != nil {
			return
		}
		before := s.customerLinkMap(ctx)[c.UUID]
		s.resolveCustomerSkip(ctx, c, skip)
		if s.customerLinkMap(ctx)[c.UUID] != before {
			s.customerMailChanged(ctx, c)
		}
	}
}

// customerMailChanged sets the website mail of a customer whose EmailZit
// changed: the sendmail of the cages (EmailZit on this server) and the
// relay, domains and SPF the mailer uses.
func (s *Server) customerMailChanged(ctx context.Context, c *store.Customer) {
	if localEmailZit() {
		if err := s.applyCustomer(ctx, "system", c); err != nil {
			s.log.Warn("website mail of the account not switched", "customer", c.Username, "err", err)
		}
		return // applyCustomer syncs the mail too
	}
	s.syncMailAccount(ctx, "system", c)
}

// localLink is the link to an EmailZit installed on this server.
func (s *Server) localLink(ctx context.Context) (EmailZitLink, bool) {
	if !localEmailZit() {
		return EmailZitLink{}, false
	}
	hs := s.hostingSettings(ctx)
	all := s.emailzitLinks(ctx)
	for _, l := range all {
		h := strings.ToLower(urlHost(l.URL))
		if h == "127.0.0.1" || h == "::1" || h == "localhost" || (hs.ServerName != "" && (h == hs.ServerName || l.MailHost == hs.ServerName)) ||
			(hs.IPv4 != "" && h == hs.IPv4) || (hs.IPv6 != "" && h == hs.IPv6) {
			return l, true
		}
	}
	if len(all) == 1 {
		return all[0], true // the only link of a server that has EmailZit
	}
	return EmailZitLink{}, false
}

// syncWebUIDs tells the EmailZit on this server the uid of a hosting
// account (empty list when the account is gone or not active), so it counts
// the websites' mail against the right customer. The answer also says
// whether that EmailZit has the customer (404 customer_not_found: not).
func (s *Server) syncWebUIDs(ctx context.Context, c *store.Customer) {
	l, ok := s.localLink(ctx)
	if !ok || !inScope(l, c.UUID, s.emailzitLinks(ctx)) {
		return
	}
	uids := []int{}
	if c.Status == store.StatusActive {
		if u, err := hosting.UID(c.Number); err == nil {
			uids = append(uids, u)
		}
	}
	err := s.emailzitCall(ctx, l, http.MethodPut, "/api/v1/customers/"+c.UUID+"/web-uids", map[string]any{"uids": uids})
	var ez *ezError
	if err != nil && !(errors.As(err, &ez) && ez.Status == http.StatusNotFound) {
		s.log.Warn("EmailZit web uids not sent", "customer", c.Username, "err", err)
		return
	}
	changed := false
	switch before := s.customerLinkMap(ctx)[c.UUID]; {
	case err == nil:
		changed = s.setCustomerLink(ctx, c.UUID, l.ID)
	case before == l.ID:
		changed = s.setCustomerLink(ctx, c.UUID, "")
	}
	if changed {
		if err := s.applyCustomer(ctx, "system", c); err != nil {
			s.log.Warn("website mail of the account not switched", "customer", c.Username, "err", err)
		}
	}
}

// ---- the customer's switch to EmailZit

// handleEmailZitOpen asks the customer's EmailZit for a one-time sign-in
// link (same UUID in both products) and goes there.
func (s *Server) handleEmailZitOpen(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	l, ok := s.linkFor(r.Context(), c)
	if !ok {
		if l, ok = s.resolveCustomer(r.Context(), c); ok {
			s.background(r.Context(), func(bg context.Context) { s.customerMailChanged(bg, c) })
		}
	}
	if !ok {
		s.redirectErr(w, r, "/", "You have no mail service in EmailZit yet. Ask your provider to set it up.")
		return
	}
	note := ""
	st, b, err := s.emailzitDo(r.Context(), l, http.MethodPost, "/api/v1/customers/"+url.PathEscape(c.UUID)+"/sso", map[string]any{})
	switch {
	case err != nil:
		s.log.Warn("EmailZit sign-in link", "customer", c.Username, "err", err)
		note = "EmailZit cannot be reached right now. Try again in a few minutes."
	case st == http.StatusNotFound:
		if nl, _ := s.resolveCustomer(r.Context(), c); nl.ID != l.ID {
			s.background(r.Context(), func(bg context.Context) { s.customerMailChanged(bg, c) })
		}
		note = "You have no mail service in EmailZit yet. Ask your provider to set it up."
	case st == http.StatusConflict:
		note = "Your sign-in to EmailZit is not switched on. Ask your provider to switch it on."
	case st >= 300:
		s.log.Warn("EmailZit sign-in link", "customer", c.Username, "status", st, "code", ezErrorCode(b))
		note = "EmailZit did not open a session. Try again in a few minutes."
	default:
		var out struct {
			URL string `json:"url"`
		}
		if json.Unmarshal(b, &out) == nil && ezLinkTarget(out.URL, l.URL, l.MailHost) {
			s.audit(r, "emailzit.sso", "customer:"+c.Username, "opened EmailZit %s with a one-time link", l.Name())
			http.Redirect(w, r, out.URL, http.StatusSeeOther)
			return
		}
		note = "EmailZit did not open a session. Try again in a few minutes."
	}
	s.redirectErr(w, r, "/", note)
}

// ezLinkTarget: the one-time link must lead to the customer's EmailZit
// (its panel address or its mail host name), never somewhere else.
func ezLinkTarget(link, panel, mailHost string) bool {
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return h != "" && (h == strings.ToLower(urlHost(panel)) || mailHost != "" && h == mailHost)
}

// ---- what an EmailZit may do with HostZit's API

// apiScopeAllows: the zone or domain of a customer may be read or written
// with this request's token. A token handed to an EmailZit link works only
// for the customers of that link's scope; other tokens (made by hand, the
// local socket) as before.
func (s *Server) apiScopeAllows(r *http.Request, customerUUID string, write bool) bool {
	t := apiToken(r)
	if t == nil {
		return true // the local socket of EmailZit on this server
	}
	ctx := r.Context()
	l, ok := s.linkOfToken(ctx, t.ID)
	if !ok {
		// a pairing token whose link is gone gets nothing; tokens made by
		// hand for an EmailZit (older links) keep working as before
		return !strings.HasPrefix(t.Name, linkTokenPrefix)
	}
	all := s.emailzitLinks(ctx)
	if !inScope(l, customerUUID, all) {
		return false
	}
	if l.Scope == "assigned" {
		return true // the administrator assigned these customers to it
	}
	// a link for all customers: only for customers whose mail is on it
	// (asked now when nobody has the customer yet) — never for a customer
	// another EmailZit has
	cur := s.customerLinkMap(ctx)[customerUUID]
	if cur == l.ID {
		return true
	}
	if cur != "" {
		return false
	}
	if !write && s.emailzitOptions(ctx).WebDefault == l.ID {
		return true // it relays the website mail of customers without EmailZit
	}
	c, err := s.store.CustomerByRef(ctx, customerUUID)
	if err != nil {
		return false
	}
	nl, ok := s.resolveCustomer(ctx, c)
	return ok && nl.ID == l.ID
}

// ---- the health of the links

// checkEmailZitLinks asks every EmailZit whether it still takes HostZit's
// token, and reads whether its relay still takes the login. A broken link
// is shown on the page and told once a day; website mail waits meanwhile.
func (s *Server) checkEmailZitLinks(ctx context.Context) {
	var relays map[string]helper.RelayState
	_ = s.call(ctx, "system", "mail.relays", struct{}{}, &relays)
	for _, l := range s.emailzitLinks(ctx) {
		state, msg := "", ""
		c, cancel := context.WithTimeout(ctx, 20*time.Second)
		st, _, err := s.emailzitDo(c, l, http.MethodGet, "/api/v1/customers/00000000-0000-0000-0000-000000000000", nil)
		cancel()
		switch {
		case err != nil:
			state, msg = "unreachable", truncateStr(err.Error(), 200)
		case st == http.StatusUnauthorized || st == http.StatusForbidden:
			state, msg = "broken", "EmailZit no longer accepts HostZit's token. Make a new pairing code in EmailZit and link again."
		}
		if rs, ok := relays[l.ID]; ok && state == "" && strings.Contains(rs.Error, "sign-in") && rs.At.After(l.LinkedAt) {
			state, msg = "broken", "EmailZit's relay refuses HostZit's login. Make a new pairing code in EmailZit and link again."
		}
		was := l.State
		_ = s.updateEmailZitLink(ctx, l.ID, func(x *EmailZitLink) {
			if x.LinkedAt.Equal(l.LinkedAt) { // not paired again meanwhile
				x.State, x.StateMsg, x.CheckedAt = state, msg, s.now().UTC()
			}
		})
		if state != "" && state != was {
			s.notify(ctx, "mail-link:"+l.ID, nil, "The link to EmailZit "+l.Name()+" does not work",
				"HostZit cannot use its link to EmailZit "+l.Name()+": "+msg+"\n\nWebsite mail of its customers waits in the queue (up to 48 hours). Settings → EmailZit shows the link.\n")
		}
	}
}

// askedRecently reports whether a customer may be asked about now (and
// notes it): at most once an hour per customer from applyCustomer.
func (s *Server) askedRecently(uuid string) bool {
	now := time.Now()
	if v, ok := s.ezAsked.Load(uuid); ok && now.Sub(v.(time.Time)) < time.Hour {
		return false
	}
	s.ezAsked.Store(uuid, now)
	return true
}

// background runs work after a request (resync of mail, finding customers'
// EmailZit); Wait waits for it at shutdown and in tests.
func (s *Server) background(ctx context.Context, fn func(context.Context)) {
	s.jobs.Add(1)
	go func() {
		defer s.jobs.Done()
		fn(context.WithoutCancel(ctx))
	}()
}

// setCustomerLink records (id != "") or forgets (id == "") a customer's
// EmailZit; it reports whether that changed anything.
func (s *Server) setCustomerLink(ctx context.Context, uuid, id string) bool {
	s.ezMu.Lock()
	defer s.ezMu.Unlock()
	m := s.customerLinkMap(ctx)
	if m[uuid] == id {
		return false
	}
	if id == "" {
		delete(m, uuid)
	} else {
		m[uuid] = id
	}
	_ = s.store.SetSetting(ctx, settingEmailZitCustomers, m)
	return true
}
