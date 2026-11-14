package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/hosting"
	"github.com/max-zit/hostzit/internal/netacl"
	"github.com/max-zit/hostzit/internal/store"
	"github.com/max-zit/hostzit/internal/tlsutil"
)

// Links to EmailZit servers (zit-hosting/INTEGRATION.md: "Integration
// plan" and "Many HostZit and many EmailZit servers"). A HostZit server can
// be linked with any number of EmailZit servers and each of them with any
// number of HostZit servers. The administrator makes a pairing code in
// EmailZit and pastes it here; the two servers then make each other's
// tokens with the least rights and the addresses of the other server:
//
//   - step 1: POST {emailzit}/api/v1/link/hostzit with the code's secret →
//     an ezt_ token (customers:read/write, sso:create) and EmailZit's relay
//     login for the websites' mail;
//   - step 2: HostZit makes an hzt_ token (dns:mail, only from EmailZit's
//     addresses) and hands it over with PUT …/link/hostzit/dns-token;
//   - Unlink on either side ends that one link.
//
// A customer (same UUID in both products) has its mail on at most one
// EmailZit; HostZit finds it by asking (emailzitcust.go). A link can serve
// all customers of this server, or only customers assigned to it — for an
// EmailZit that belongs to one client, which must not see or touch the
// other customers.

const (
	settingEmailZitLinks     = "emailzit_links"
	settingEmailZitOld       = "emailzit" // the single link of 0.9.x
	settingEmailZitOptions   = "emailzit_options"
	settingEmailZitCustomers = "emailzit_customers" // customer UUID → link id
)

// slugRE is a package slug (the same rule in both products).
var slugRE = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// pairingPrefix starts every pairing code of EmailZit.
const pairingPrefix = "ezlink_"

// EmailZitLink is one linked EmailZit server.
type EmailZitLink struct {
	ID       string `json:"id"`
	URL      string `json:"url"`   // e.g. https://mail.example.com:8444
	Token    string `json:"token"` // sealed ezt_… token
	Insecure bool   `json:"insecure,omitempty"`
	// ImportPackage: EmailZit package (slug) of customers made by a cPanel import.
	ImportPackage string `json:"import_package,omitempty"`

	// Paired: made with a pairing code (not typed in by hand).
	Paired bool `json:"paired,omitempty"`
	// MailHost is EmailZit's mail host name.
	MailHost string `json:"mail_host,omitempty"`
	// Pin is the SHA-256 of the public key of EmailZit's certificate
	// (base64), from the code; it is accepted when the certificate is not
	// one the system trusts.
	Pin string `json:"pin,omitempty"`
	// Addresses are EmailZit's addresses: the hzt_ token works only from them.
	Addresses []string `json:"addresses,omitempty"`
	// OwnAddresses are the addresses HostZit told EmailZit (its token and
	// the relay port work only from them).
	OwnAddresses []string `json:"own_addresses,omitempty"`
	// DNSTokenID is the hzt_ token HostZit gave EmailZit.
	DNSTokenID int64 `json:"dns_token_id,omitempty"`
	// AdminAdded are EmailZit's addresses the pairing added to the
	// addresses that may reach the admin port (removed again on Unlink).
	AdminAdded []string       `json:"admin_added,omitempty"`
	Relay      *EmailZitRelay `json:"relay,omitempty"`
	LinkedAt   time.Time      `json:"linked_at,omitempty"`
	LinkedBy   string         `json:"linked_by,omitempty"`

	// Scope: "" serves all customers of this server (except those assigned
	// to another link); "assigned" serves only Customers (UUIDs).
	Scope     string   `json:"scope,omitempty"`
	Customers []string `json:"customers,omitempty"`

	// State of the last check: "" works, "broken" (EmailZit refuses the
	// token or the relay login: pair again), "unreachable".
	State     string    `json:"state,omitempty"`
	StateMsg  string    `json:"state_msg,omitempty"`
	CheckedAt time.Time `json:"checked_at,omitempty"`
}

// Name is how pages call the link.
func (l EmailZitLink) Name() string {
	if l.MailHost != "" {
		return l.MailHost
	}
	return urlHost(l.URL)
}

// EmailZitRelay is EmailZit's relay login for the websites' mail.
type EmailZitRelay struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"` // sealed
	StartTLS bool   `json:"starttls"`
}

// EmailZitOptions are the choices that concern all links.
type EmailZitOptions struct {
	// WebDefault: the link whose relay the websites of customers without
	// mail in EmailZit use ("" = HostZit sends their mail itself).
	WebDefault string `json:"web_default,omitempty"`
	// ImportLink: the EmailZit that takes the mail of cPanel imports.
	ImportLink string `json:"import_link,omitempty"`
}

func init() {
	adminExtra = append(adminExtra, func(s *Server, mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc)) {
		admin("GET /settings/emailzit", s.handleEmailZit)
		admin("POST /settings/emailzit", s.handleEmailZitOptions)
		admin("POST /settings/emailzit/pair", s.handleEmailZitPair)
		admin("POST /settings/emailzit/{id}/unlink", s.handleEmailZitUnlink)
		admin("POST /settings/emailzit/{id}/scope", s.handleEmailZitScope)
		admin("POST /settings/emailzit/check", s.handleEmailZitCheck)
	})
	customerExtra = append(customerExtra, func(s *Server, mux *http.ServeMux, c func(string, http.HandlerFunc)) {
		c("GET /emailzit", s.handleEmailZitOpen)
	})
	apiExtra = append(apiExtra, func(s *Server, need func(scope, pattern string, h http.HandlerFunc)) {
		need("dns:mail", "DELETE /api/v1/link/emailzit", s.apiLinkDelete)
	})
}

// localEmailZit reports whether EmailZit is installed on this server.
var localEmailZit = func() bool {
	_, err := os.Stat("/usr/sbin/emailzit-sendmail")
	return err == nil
}

// ---- storage

// emailzitLinks lists the links (the single link of 0.9.x becomes the first).
func (s *Server) emailzitLinks(ctx context.Context) []EmailZitLink {
	var list []EmailZitLink
	_ = s.store.GetSetting(ctx, settingEmailZitLinks, &list)
	if len(list) == 0 {
		var old EmailZitLink
		if err := s.store.GetSetting(ctx, settingEmailZitOld, &old); err == nil && old.URL != "" {
			old.ID = linkIDFor(old.URL)
			list = []EmailZitLink{old}
			if s.store.SetSetting(ctx, settingEmailZitLinks, list) == nil {
				_ = s.store.SetSetting(ctx, settingEmailZitOld, EmailZitLink{})
				if old.ImportPackage != "" {
					o := s.emailzitOptions(ctx)
					o.ImportLink = old.ID
					_ = s.store.SetSetting(ctx, settingEmailZitOptions, o)
				}
			}
		}
	}
	return list
}

func (s *Server) saveEmailZitLinks(ctx context.Context, list []EmailZitLink) error {
	if list == nil {
		list = []EmailZitLink{}
	}
	return s.store.SetSetting(ctx, settingEmailZitLinks, list)
}

func (s *Server) emailzitLinkByID(ctx context.Context, id string) (EmailZitLink, bool) {
	for _, l := range s.emailzitLinks(ctx) {
		if l.ID == id && id != "" {
			return l, true
		}
	}
	return EmailZitLink{}, false
}

// updateEmailZitLink changes one link in place.
func (s *Server) updateEmailZitLink(ctx context.Context, id string, fn func(*EmailZitLink)) error {
	s.ezMu.Lock()
	defer s.ezMu.Unlock()
	list := s.emailzitLinks(ctx)
	for i := range list {
		if list[i].ID == id {
			fn(&list[i])
			return s.saveEmailZitLinks(ctx, list)
		}
	}
	return store.ErrNotFound
}

func (s *Server) emailzitOptions(ctx context.Context) EmailZitOptions {
	var o EmailZitOptions
	_ = s.store.GetSetting(ctx, settingEmailZitOptions, &o)
	return o
}

// linkIDFor is a fixed id for a link migrated from 0.9.x.
func linkIDFor(u string) string {
	sum := sha256.Sum256([]byte(normEmailZitURL(u)))
	return "ez" + hex.EncodeToString(sum[:4])
}

// normEmailZitURL compares EmailZit addresses: lower-case host, no :443.
func normEmailZitURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return strings.ToLower(raw)
	}
	h, p := strings.ToLower(u.Hostname()), u.Port()
	if p == "" || p == "443" {
		return "https://" + h
	}
	return "https://" + net.JoinHostPort(h, p)
}

// linkTokenPrefix names the hzt_ tokens a pairing makes; a token with this
// name that belongs to no link any more gets no access (fail closed).
const linkTokenPrefix = "EmailZit link (" // #nosec G101 -- the name of a token, not a secret

func newLinkID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return "ez" + hex.EncodeToString(b[:])
}

// ---- calls to EmailZit

// emailzitClient checks EmailZit's certificate the usual way and, when
// that fails, against the pin of the pairing code.
func emailzitClient(host, pin string, insecure bool, timeout time.Duration) *http.Client {
	cfg := tlsutil.PinnedConfig(host, pin)
	if pin == "" && insecure {
		cfg.InsecureSkipVerify = true // #nosec G402 -- old links typed in by hand, where the administrator allowed a self-signed EmailZit
	}
	return &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: cfg},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// ezRequest sends one call to EmailZit; auth is the whole Authorization value.
func ezRequest(ctx context.Context, cl *http.Client, base, method, path, auth string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, b, nil
}

// emailzitDo calls one EmailZit with that link's token.
func (s *Server) emailzitDo(ctx context.Context, l EmailZitLink, method, path string, body any) (int, []byte, error) {
	if l.URL == "" {
		return 0, nil, errors.New("EmailZit is not linked")
	}
	tok, err := s.store.OpenSecret("emailzit.token", l.Token)
	if err != nil {
		return 0, nil, err
	}
	return ezRequest(ctx, emailzitClient(urlHost(l.URL), l.Pin, l.Insecure, 20*time.Second), l.URL, method, path, "Bearer "+tok, body)
}

// emailzitCall is emailzitDo with an answer of 300 or more as an error.
func (s *Server) emailzitCall(ctx context.Context, l EmailZitLink, method, path string, body any) error {
	st, b, err := s.emailzitDo(ctx, l, method, path, body)
	if err != nil {
		return err
	}
	if st >= 300 {
		return &ezError{Status: st, Code: ezErrorCode(b), Msg: fmt.Sprintf("EmailZit %s %s: %d %s", method, path, st, strings.TrimSpace(truncateStr(string(b), 300)))}
	}
	return nil
}

// ezError is an error answer of EmailZit.
type ezError struct {
	Status int
	Code   string
	Msg    string
}

func (e *ezError) Error() string { return e.Msg }

// ezErrorCode reads {"error":{"code":…}}.
func ezErrorCode(b []byte) string {
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(b, &e)
	return e.Error.Code
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}

func urlHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// ---- the settings page

type emailzitData struct {
	Links []EmailZitLink
	Opts  EmailZitOptions
	// Usernames of the customers assigned to each link (by link id).
	Assigned map[string]string
	// Counts: customers whose mail is on each link (by link id).
	Counts map[string]int
	Local  string // the id of the link to EmailZit on this server
	// Own are the addresses HostZit tells EmailZit at the pairing.
	Own []string
	// OIDCLeft: a sign-in client for EmailZit is still set (no longer used).
	OIDCLeft bool
}

func (s *Server) handleEmailZit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d := &emailzitData{Links: s.emailzitLinks(ctx), Opts: s.emailzitOptions(ctx), Assigned: map[string]string{}, Counts: map[string]int{},
		Own: s.ownAddresses(ctx), OIDCLeft: s.oidcClient(ctx).ID != ""}
	if l, ok := s.localLink(ctx); ok {
		d.Local = l.ID
	}
	for _, id := range s.customerLinkMap(ctx) {
		d.Counts[id]++
	}
	for _, l := range d.Links {
		var names []string
		for _, u := range l.Customers {
			if c, err := s.store.CustomerByRef(ctx, u); err == nil {
				names = append(names, c.Username)
			}
		}
		d.Assigned[l.ID] = strings.Join(names, "\n")
	}
	s.render(w, r, http.StatusOK, "emailzit", &Page{Title: "EmailZit", Nav: "settings", Data: d})
}

// handleEmailZitOptions keeps the choices for all links: the relay of the
// customers without mail in EmailZit, and the EmailZit (and package) of
// cPanel imports.
func (s *Server) handleEmailZitOptions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	o := EmailZitOptions{WebDefault: r.FormValue("web_default"), ImportLink: r.FormValue("import_link")}
	pkg := strings.TrimSpace(r.FormValue("import_package"))
	if pkg != "" && !slugRE.MatchString(pkg) {
		s.redirectErr(w, r, "/settings/emailzit", "A package slug has lower-case letters, digits and dashes.")
		return
	}
	if o.WebDefault != "" {
		if l, ok := s.emailzitLinkByID(ctx, o.WebDefault); !ok || l.Relay == nil || l.Scope == "assigned" {
			s.redirectErr(w, r, "/settings/emailzit", "Choose an EmailZit that gave a relay login and serves all customers.")
			return
		}
	}
	if links := s.emailzitLinks(ctx); o.ImportLink == "" && len(links) == 1 && links[0].Scope != "assigned" {
		o.ImportLink = links[0].ID // the only EmailZit
	}
	if o.ImportLink != "" {
		if l, ok := s.emailzitLinkByID(ctx, o.ImportLink); !ok || l.Scope == "assigned" {
			s.redirectErr(w, r, "/settings/emailzit", "cPanel imports need an EmailZit that serves all customers.")
			return
		}
		_ = s.updateEmailZitLink(ctx, o.ImportLink, func(l *EmailZitLink) { l.ImportPackage = pkg })
	}
	s.ezMu.Lock()
	err := s.store.SetSetting(ctx, settingEmailZitOptions, o)
	s.ezMu.Unlock()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.emailzit", "settings", "website mail of customers without EmailZit through %q, cPanel imports to %q (package %q)", o.WebDefault, o.ImportLink, pkg)
	if err := s.applyRelay(ctx, actor(r)); err != nil {
		s.log.Warn("website mail after the EmailZit options", "err", err)
	}
	s.background(ctx, s.syncAllMail)
	s.redirect(w, r, "/settings/emailzit", "Saved.")
}

// handleEmailZitScope sets which customers a link serves.
func (s *Server) handleEmailZitScope(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	cur, ok := s.emailzitLinkByID(ctx, id)
	if !ok {
		s.notFound(w, r)
		return
	}
	uuids, msg := s.scopeCustomers(r, r.FormValue("scope"), r.FormValue("customers"), id)
	if msg != "" {
		s.redirectErr(w, r, "/settings/emailzit", msg)
		return
	}
	if uuids != nil && cur.DNSTokenID == 0 {
		s.redirectErr(w, r, "/settings/emailzit", "This link was typed in by hand, so HostZit cannot limit its token. Link it again with a pairing code first.")
		return
	}
	if uuids != nil {
		if o := s.emailzitOptions(ctx); o.WebDefault == id || o.ImportLink == id {
			s.redirectErr(w, r, "/settings/emailzit", "This EmailZit is chosen for the customers without EmailZit or for cPanel imports. Choose another one there first.")
			return
		}
	}
	err := s.updateEmailZitLink(ctx, id, func(l *EmailZitLink) {
		l.Scope, l.Customers = "", nil
		if uuids != nil {
			l.Scope, l.Customers = "assigned", uuids
		}
	})
	if err != nil {
		s.notFound(w, r)
		return
	}
	s.audit(r, "settings.emailzit", "settings", "EmailZit link %s serves %d assigned customers (0 = all)", id, len(uuids))
	s.background(ctx, s.resolveAllCustomers)
	s.redirect(w, r, "/settings/emailzit", "Saved.")
}

// scopeCustomers reads the scope fields of a form: nil for all customers,
// else the UUIDs of the named customers. A customer already assigned to
// another link (not self) is refused: two EmailZit servers would get it.
func (s *Server) scopeCustomers(r *http.Request, scope, names, self string) ([]string, string) {
	if scope != "assigned" {
		return nil, ""
	}
	ctx := r.Context()
	links := s.emailzitLinks(ctx)
	uuids := []string{}
	for _, name := range netacl.Split(names) {
		c, err := s.store.CustomerByRef(ctx, name)
		if err != nil {
			return nil, translate(s.lang(r, userFrom(r)), "There is no customer %s.", name)
		}
		for _, l := range links {
			if l.ID != self && l.Scope == "assigned" && slices.Contains(l.Customers, c.UUID) {
				return nil, translate(s.lang(r, userFrom(r)), "%s is assigned to the EmailZit %s already.", c.Username, l.Name())
			}
		}
		if !slices.Contains(uuids, c.UUID) {
			uuids = append(uuids, c.UUID)
		}
	}
	if len(uuids) == 0 {
		return nil, "Name at least one customer, or let the link serve all customers."
	}
	return uuids, ""
}

// handleEmailZitCheck checks every link (in the background).
func (s *Server) handleEmailZitCheck(w http.ResponseWriter, r *http.Request) {
	s.background(r.Context(), func(ctx context.Context) {
		s.checkEmailZitLinks(ctx)
		s.resolveAllCustomers(ctx)
	})
	s.redirect(w, r, "/settings/emailzit", "The check runs in the background; reload the page in a minute.")
}

// ownAddresses are this server's addresses as EmailZit sees them.
func (s *Server) ownAddresses(ctx context.Context) []string {
	hs := s.hostingSettings(ctx)
	var out []string
	for _, a := range []string{hs.IPv4, hs.IPv6} {
		if a != "" {
			out = append(out, a)
		}
	}
	return out
}

// ---- pairing

// pairingCode is what EmailZit puts into the code.
type pairingCode struct {
	V      int    `json:"v"`
	URL    string `json:"url"`
	Secret string `json:"secret"`
	Pin    string `json:"pin,omitempty"`
}

//lint:ignore ST1005 a message for the page, translated as written
var errBadPairing = errors.New("This is not an EmailZit pairing code. Copy the whole code from EmailZit: Settings → HostZit → Make a pairing code.")

// parsePairingCode reads a code as pasted (line breaks and spaces are dropped).
func parsePairingCode(raw string) (pairingCode, error) {
	raw = strings.Join(strings.Fields(raw), "")
	body, ok := strings.CutPrefix(raw, pairingPrefix)
	if !ok || body == "" || len(body) > 4096 {
		return pairingCode{}, errBadPairing
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(body, "="))
	if err != nil {
		return pairingCode{}, errBadPairing
	}
	var c pairingCode
	if json.Unmarshal(b, &c) != nil || c.V != 1 || c.Secret == "" || len(c.Secret) > 200 || strings.ContainsAny(c.Secret, " \r\n") {
		return pairingCode{}, errBadPairing
	}
	if c.URL, err = cleanEmailZitURL(c.URL); err != nil {
		return pairingCode{}, errBadPairing
	}
	if c.Pin != "" {
		if p, err := base64.StdEncoding.DecodeString(c.Pin); err != nil || len(p) != sha256.Size {
			return pairingCode{}, errBadPairing
		}
	}
	return c, nil
}

// cleanEmailZitURL keeps scheme and host of an https address.
func cleanEmailZitURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || len(raw) > 200 {
		return "", errors.New("not an https address")
	}
	return "https://" + u.Host, nil
}

// pairAnswer is EmailZit's answer to step 1.
type pairAnswer struct {
	APIToken  string   `json:"api_token"`
	Addresses []string `json:"emailzit_addresses"`
	MailHost  string   `json:"emailzit_mail_host"`
	Relay     *struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
		StartTLS bool   `json:"starttls"`
	} `json:"relay"`
}

// ownPin is the pin of the admin panel's certificate when it is not one a
// public CA issued for the server name (EmailZit then checks it by the pin).
func (s *Server) ownPin(serverName string) string {
	if c := s.panelCert.Load(); c != nil && c.Leaf != nil && serverName != "" && c.Leaf.VerifyHostname(serverName) == nil {
		return ""
	}
	c := s.selfPanelCert
	if c == nil || len(c.Certificate) == 0 {
		return ""
	}
	return tlsutil.SPKIPin(c.Certificate[0])
}

// handleEmailZitPair links one more EmailZit (or links the same EmailZit
// again: the link to that address is replaced, the others stay).
func (s *Server) handleEmailZitPair(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fail := func(msg string) { s.redirectErr(w, r, "/settings/emailzit", msg) }
	code, err := parsePairingCode(r.FormValue("code"))
	if err != nil {
		fail(err.Error())
		return
	}
	// the scope is chosen before anything is sent: a new EmailZit is never
	// told about customers it is not meant to serve
	var scopeUUIDs []string
	var existing *EmailZitLink
	for _, x := range s.emailzitLinks(ctx) {
		if normEmailZitURL(x.URL) == normEmailZitURL(code.URL) {
			existing = &x
		}
	}
	if existing != nil && strings.TrimSpace(r.FormValue("customers")) == "" {
		scopeUUIDs = existing.Customers // linking the same EmailZit again keeps its scope
		if existing.Scope != "assigned" {
			scopeUUIDs = nil
		}
	} else {
		var msg string
		scopeUUIDs, msg = s.scopeCustomers(r, r.FormValue("scope"), r.FormValue("customers"), func() string {
			if existing != nil {
				return existing.ID
			}
			return ""
		}())
		if msg != "" {
			fail(msg)
			return
		}
	}
	hs := s.hostingSettings(ctx)
	n, _ := s.Network(ctx)
	_, port, _ := splitListen(n.AdminListen)
	if hs.ServerName == "" || port == 0 {
		fail("Set the server name under Settings → Hosting first: EmailZit reaches HostZit by it.")
		return
	}
	own := s.ownAddresses(ctx)
	if extra := netacl.Split(r.FormValue("addresses")); len(extra) > 0 {
		x, err := store.CleanTokenAddresses(extra)
		if err != nil {
			fail(storeErr(err))
			return
		}
		for _, a := range x {
			if !slices.Contains(own, a) {
				own = append(own, a)
			}
		}
	}
	if len(own) == 0 {
		fail("Set the server's IPv4 and IPv6 address under Settings → Hosting first: EmailZit allows its token only from them.")
		return
	}
	host := urlHost(code.URL)
	cl := emailzitClient(host, code.Pin, false, 30*time.Second)
	hostzitURL := "https://" + net.JoinHostPort(hs.ServerName, fmt.Sprint(port))
	in := map[string]any{"hostzit_url": hostzitURL, "server_name": hs.ServerName, "addresses": own}
	if pin := s.ownPin(hs.ServerName); pin != "" {
		in["pin"] = pin
	}
	st, b, err := ezRequest(ctx, cl, code.URL, http.MethodPost, "/api/v1/link/hostzit", "Pairing "+code.Secret, in)
	switch {
	case err != nil:
		s.log.Warn("EmailZit pairing", "url", code.URL, "err", err)
		fail(translate(s.lang(r, userFrom(r)), "EmailZit at %s cannot be reached: %s", code.URL, err.Error()))
		return
	case st == http.StatusUnauthorized:
		fail("EmailZit did not accept the code: it is wrong, used or older than ten minutes. Make a new code in EmailZit.")
		return
	case st == http.StatusTooManyRequests:
		fail("Too many attempts. Wait a minute and make a new code in EmailZit.")
		return
	case st != http.StatusCreated && st != http.StatusOK:
		fail(translate(s.lang(r, userFrom(r)), "EmailZit refused the pairing (%d %s).", st, ezErrorCode(b)))
		return
	}
	var ans pairAnswer
	if json.Unmarshal(b, &ans) != nil || !strings.HasPrefix(ans.APIToken, "ezt_") || len(ans.APIToken) > 200 || strings.ContainsAny(ans.APIToken, " \r\n") {
		fail("EmailZit's answer is not one HostZit understands. Is EmailZit 0.10.0 or newer?")
		return
	}
	ezTok := ans.APIToken
	// whatever fails from here on, EmailZit forgets the half-made link
	undo := func(tokenID int64, added []string) {
		_, _, _ = ezRequest(context.WithoutCancel(ctx), cl, code.URL, http.MethodDelete, "/api/v1/link/hostzit", "Bearer "+ezTok, nil)
		if tokenID != 0 {
			_ = s.store.DeleteAPITokenByID(context.WithoutCancel(ctx), tokenID)
		}
		s.removeAdminAddresses(context.WithoutCancel(ctx), added, "")
	}
	addrs := emailzitAddresses(ctx, ans.Addresses, host, ans.MailHost)
	if len(addrs) == 0 {
		undo(0, nil)
		fail("EmailZit did not say its addresses and its name does not resolve; HostZit cannot limit its token.")
		return
	}
	// EmailZit calls HostZit's API on the admin port
	added, err := s.allowAdminAddresses(ctx, addrs)
	if err != nil {
		undo(0, nil)
		fail(storeErr(err))
		return
	}
	u := userFrom(r)
	tokID, hzTok, err := s.store.CreateAPIToken(ctx, u.ID, linkTokenPrefix+truncateStr(host, 60)+")", 0, []string{"dns:mail"}, addrs)
	if err != nil {
		undo(0, added)
		fail(storeErr(err))
		return
	}
	l := EmailZitLink{ID: newLinkID(), URL: code.URL, Token: s.store.SealSecret("emailzit.token", ezTok), Paired: true, MailHost: strings.ToLower(truncateStr(ans.MailHost, 253)),
		Pin: code.Pin, Addresses: addrs, OwnAddresses: own, DNSTokenID: tokID, AdminAdded: added, LinkedAt: s.now().UTC(), LinkedBy: u.Username}
	if rl := ans.Relay; rl != nil && rl.Host != "" {
		if (hosting.ValidDomain(rl.Host) || net.ParseIP(rl.Host) != nil) && rl.Port > 0 && rl.Port < 65536 && rl.Username != "" && len(rl.Username) <= 200 && len(rl.Password) <= 200 && !strings.ContainsAny(rl.Username+rl.Password, "\r\n") {
			l.Relay = &EmailZitRelay{Host: strings.ToLower(rl.Host), Port: rl.Port, Username: rl.Username, Password: s.store.SealSecret("emailzit.relay", rl.Password), StartTLS: rl.StartTLS}
		}
	}
	if scopeUUIDs != nil {
		l.Scope, l.Customers = "assigned", scopeUUIDs
	}
	// the same EmailZit again: that link is replaced (keeping its id and
	// import package); the other links stay. The old token goes before the
	// list is saved, so it never outlives its link.
	s.ezMu.Lock()
	list := s.emailzitLinks(ctx)
	var old *EmailZitLink
	for i := range list {
		if normEmailZitURL(list[i].URL) == normEmailZitURL(l.URL) {
			old = &list[i]
			break
		}
	}
	var oldAdded []string
	if old != nil {
		l.ID, l.ImportPackage = old.ID, old.ImportPackage
		for _, a := range old.AdminAdded {
			if !slices.Contains(l.AdminAdded, a) && slices.Contains(addrs, a) {
				l.AdminAdded = append(l.AdminAdded, a)
			}
		}
		if old.DNSTokenID != 0 && old.DNSTokenID != tokID {
			_ = s.store.DeleteAPITokenByID(ctx, old.DNSTokenID)
		}
		oldAdded = old.AdminAdded
		*old = l
	} else {
		list = append(list, l)
	}
	err = s.saveEmailZitLinks(ctx, list)
	s.ezMu.Unlock()
	if err != nil {
		undo(tokID, added)
		s.serverError(w, r, err)
		return
	}
	// step 2: EmailZit gets HostZit's token (the link exists already, so
	// the DNS it publishes right away is accepted)
	st, b, err = ezRequest(ctx, cl, code.URL, http.MethodPut, "/api/v1/link/hostzit/dns-token", "Bearer "+ezTok, map[string]string{"token": hzTok})
	if err != nil || st >= 300 {
		detail := ezErrorCode(b)
		if err != nil {
			detail = err.Error()
		}
		s.log.Warn("EmailZit pairing step 2", "status", st, "detail", detail)
		_ = s.dropLink(context.WithoutCancel(ctx), actor(r), l)
		undo(tokID, added)
		fail(translate(s.lang(r, userFrom(r)), "EmailZit could not use HostZit's token (%s). Check that EmailZit reaches %s and make a new code.", detail, hostzitURL))
		return
	}
	s.removeAdminAddresses(ctx, oldAdded, "")
	s.audit(r, "emailzit.paired", "settings", "paired with EmailZit %s (link %s; its token only from %s; HostZit's dns:mail token #%d only from %s; relay %v)",
		l.URL, l.ID, strings.Join(own, " "), tokID, strings.Join(addrs, " "), l.Relay != nil)
	if err := s.applyRelay(ctx, actor(r)); err != nil {
		s.log.Warn("website mail after the pairing", "err", err)
	}
	// which customers are on this EmailZit, then their mail and SPF records
	s.background(ctx, func(bg context.Context) {
		s.resolveAllCustomers(bg)
		s.syncAllMail(bg)
	})
	s.redirect(w, r, "/settings/emailzit", "EmailZit is linked.")
}

// emailzitAddresses are the addresses HostZit allows for EmailZit's token
// and on the admin port: single addresses only (never a network: a
// malicious answer could open the admin port to everyone), and, when the
// EmailZit names resolve, only those of them.
func emailzitAddresses(ctx context.Context, said []string, host, mailHost string) []string {
	known := resolveHost(ctx, host)
	if mailHost != "" && hosting.ValidDomain(mailHost) {
		for _, a := range resolveHost(ctx, mailHost) {
			if !slices.Contains(known, a) {
				known = append(known, a)
			}
		}
	}
	var out []string
	for _, a := range said {
		ip := net.ParseIP(strings.TrimSpace(a))
		if ip == nil || ip.IsUnspecified() || ip.IsLoopback() && host != "127.0.0.1" && host != "::1" && host != "localhost" {
			continue
		}
		s := ip.String()
		if (len(known) == 0 || slices.Contains(known, s)) && !slices.Contains(out, s) && len(out) < 8 {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		out = known
	}
	return out
}

// resolveHost gives the addresses of a host name (or the address itself).
func resolveHost(ctx context.Context, host string) []string {
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}
	}
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(c, "ip", host)
	if err != nil {
		return nil
	}
	var out []string
	for _, ip := range ips {
		if !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			out = append(out, ip.String())
		}
	}
	return out
}

// allowAdminAddresses lets addresses reach the admin port; it returns the
// ones it had to add.
func (s *Server) allowAdminAddresses(ctx context.Context, addrs []string) ([]string, error) {
	n, err := s.Network(ctx)
	if err != nil {
		return nil, err
	}
	var added []string
	for _, a := range addrs {
		p, err := netacl.ParsePrefix(a)
		if err != nil {
			continue
		}
		if s.AdminACL != nil && s.AdminACL.Allows(p.Addr()) {
			continue
		}
		n.AdminAllowed = append(n.AdminAllowed, a)
		added = append(added, a)
	}
	if len(added) == 0 {
		return nil, nil
	}
	return added, s.SaveNetwork(ctx, n)
}

// removeAdminAddresses takes back what allowAdminAddresses added, except
// the addresses another link (not except) still needs.
func (s *Server) removeAdminAddresses(ctx context.Context, list []string, except string) {
	var drop []string
	for _, a := range list {
		needed := false
		for _, l := range s.emailzitLinks(ctx) {
			if l.ID != except && (slices.Contains(l.AdminAdded, a) || slices.Contains(l.Addresses, a)) {
				needed = true
			}
		}
		if !needed {
			drop = append(drop, a)
		}
	}
	if len(drop) == 0 {
		return
	}
	n, err := s.Network(ctx)
	if err != nil {
		return
	}
	n.AdminAllowed = slices.DeleteFunc(n.AdminAllowed, func(a string) bool { return slices.Contains(drop, a) })
	if err := s.SaveNetwork(ctx, n); err != nil {
		s.log.Warn("EmailZit addresses not removed from the admin port", "err", err)
	}
}

// dropLink forgets one link here: its token, its admin-port addresses, the
// customers it had and the choices that named it.
func (s *Server) dropLink(ctx context.Context, by string, l EmailZitLink) error {
	if l.DNSTokenID != 0 {
		_ = s.store.DeleteAPITokenByID(ctx, l.DNSTokenID)
	}
	s.ezMu.Lock()
	list := slices.DeleteFunc(s.emailzitLinks(ctx), func(x EmailZitLink) bool { return x.ID == l.ID })
	err := s.saveEmailZitLinks(ctx, list)
	if err == nil {
		m := s.customerLinkMap(ctx)
		for u, id := range m {
			if id == l.ID {
				delete(m, u)
			}
		}
		_ = s.store.SetSetting(ctx, settingEmailZitCustomers, m)
	}
	s.ezMu.Unlock()
	if err != nil {
		return err
	}
	s.removeAdminAddresses(ctx, l.AdminAdded, l.ID)
	s.ezMu.Lock()
	if o := s.emailzitOptions(ctx); o.WebDefault == l.ID || o.ImportLink == l.ID {
		if o.WebDefault == l.ID {
			o.WebDefault = ""
		}
		if o.ImportLink == l.ID {
			o.ImportLink = ""
		}
		_ = s.store.SetSetting(ctx, settingEmailZitOptions, o)
	}
	s.ezMu.Unlock()
	if err := s.applyRelay(ctx, by); err != nil {
		s.log.Warn("website mail after the unlink", "err", err)
	}
	s.background(ctx, s.syncAllMail)
	return nil
}

func (s *Server) handleEmailZitUnlink(w http.ResponseWriter, r *http.Request) {
	l, ok := s.emailzitLinkByID(r.Context(), r.PathValue("id"))
	if !ok {
		s.redirect(w, r, "/settings/emailzit", "Not linked.")
		return
	}
	msg := "The link is ended on both sides."
	st, _, err := s.emailzitDo(r.Context(), l, http.MethodDelete, "/api/v1/link/hostzit", nil)
	if !l.Paired {
		msg = "The link is ended here. It was typed in by hand: revoke HostZit's token in EmailZit as well."
	} else if err != nil || (st >= 300 && st != http.StatusNotFound && st != http.StatusUnauthorized) {
		msg = "The link is ended here; EmailZit could not be reached, so remove the link there as well."
	}
	if err := s.dropLink(r.Context(), actor(r), l); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "emailzit.unlink", "settings", "link with EmailZit %s (%s) ended", l.URL, l.ID)
	s.redirect(w, r, "/settings/emailzit", msg)
}

// apiLinkDelete: an EmailZit ends its link from its side with the hzt_
// token of that link; the other links stay.
func (s *Server) apiLinkDelete(w http.ResponseWriter, r *http.Request) {
	t := apiToken(r)
	// the caller is done with its token in any case
	_ = s.store.DeleteAPITokenByID(r.Context(), t.ID)
	if l, ok := s.linkOfToken(r.Context(), t.ID); ok {
		if err := s.dropLink(r.Context(), apiActor(r), l); err != nil {
			apiError(w, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		s.apiAudit(r, "emailzit.unlink", "settings", "EmailZit %s ended the link", l.URL)
	} else {
		s.apiAudit(r, "api.token.delete", "settings", "API token #%d %q revoked by an EmailZit unlink", t.ID, t.Name)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// linkOfToken is the link an hzt_ token was handed to.
func (s *Server) linkOfToken(ctx context.Context, tokenID int64) (EmailZitLink, bool) {
	for _, l := range s.emailzitLinks(ctx) {
		if l.DNSTokenID != 0 && l.DNSTokenID == tokenID {
			return l, true
		}
	}
	return EmailZitLink{}, false
}
