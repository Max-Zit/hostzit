package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
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

// The link to EmailZit (zit-hosting/INTEGRATION.md, "Integration plan").
// The administrator makes a pairing code in EmailZit and pastes it here;
// the two servers then make each other's tokens with the least rights and
// the addresses of the other server, so nobody copies a token by hand:
//
//   - step 1: POST {emailzit}/api/v1/link/hostzit with the code's secret →
//     an ezt_ token (customers:read/write, sso:create) and EmailZit's relay
//     login for the websites' mail;
//   - step 2: HostZit makes an hzt_ token (dns:mail, only from EmailZit's
//     addresses) and hands it over with PUT …/link/hostzit/dns-token;
//   - Unlink on either side revokes both tokens and the relay login.
//
// With the link, customers open EmailZit with one click (sso:create),
// EmailZit writes the mail records into the zones here (P6), and website
// mail goes through EmailZit: on the same server by emailzit-sendmail in
// the cages (plus web-uids), on another server through the relay login.

const settingEmailZit = "emailzit"

// slugRE is a package slug (the same rule in both products).
var slugRE = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// pairingPrefix starts every pairing code of EmailZit.
const pairingPrefix = "ezlink_"

// EmailZitLink is where EmailZit's API is and what the link holds.
type EmailZitLink struct {
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
}

// EmailZitRelay is EmailZit's relay login for the websites' mail.
type EmailZitRelay struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"` // sealed
	StartTLS bool   `json:"starttls"`
}

func init() {
	adminExtra = append(adminExtra, func(s *Server, mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc)) {
		admin("GET /settings/emailzit", s.handleEmailZit)
		admin("POST /settings/emailzit", s.handleEmailZitSave)
		admin("POST /settings/emailzit/pair", s.handleEmailZitPair)
		admin("POST /settings/emailzit/unlink", s.handleEmailZitUnlink)
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

func (s *Server) emailzitLink(ctx context.Context) EmailZitLink {
	var l EmailZitLink
	_ = s.store.GetSetting(ctx, settingEmailZit, &l)
	return l
}

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

// emailzitDo calls EmailZit with the link's token.
func (s *Server) emailzitDo(ctx context.Context, method, path string, body any) (int, []byte, error) {
	l := s.emailzitLink(ctx)
	if l.URL == "" {
		return 0, nil, errors.New("EmailZit is not linked")
	}
	tok, err := s.store.OpenSecret("emailzit.token", l.Token)
	if err != nil {
		return 0, nil, err
	}
	return ezRequest(ctx, emailzitClient(urlHost(l.URL), l.Pin, l.Insecure, 20*time.Second), l.URL, method, path, "Bearer "+tok, body)
}

func (s *Server) emailzitCall(ctx context.Context, method, path string, body any) error {
	if s.emailzitLink(ctx).URL == "" {
		return nil
	}
	st, b, err := s.emailzitDo(ctx, method, path, body)
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

// syncWebUIDs tells a local EmailZit the uid of a hosting account (empty
// list when the account is gone or not active). Only EmailZit on the same
// server counts mail by uid; a customer EmailZit does not know is not an
// error (404 customer_not_found: no mail customer). The answer also decides
// which sendmail the account's websites use: EmailZit's only for customers
// EmailZit knows (it refuses senders that are not its mail domains), HostZit's
// queue for the others.
func (s *Server) syncWebUIDs(ctx context.Context, c *store.Customer) {
	if s.emailzitLink(ctx).URL == "" || !localEmailZit() {
		return
	}
	uids := []int{}
	if c.Status == store.StatusActive {
		if u, err := hosting.UID(c.Number); err == nil {
			uids = append(uids, u)
		}
	}
	err := s.emailzitCall(ctx, http.MethodPut, "/api/v1/customers/"+c.UUID+"/web-uids", map[string]any{"uids": uids})
	var ez *ezError
	known := err == nil
	if err != nil && !(errors.As(err, &ez) && ez.Status == http.StatusNotFound) {
		s.log.Warn("EmailZit web uids not sent", "customer", c.Username, "err", err)
		return
	}
	if known != s.emailzitKnows(ctx, c.UUID) {
		s.setEmailZitKnows(ctx, c.UUID, known)
		if err := s.applyCustomer(ctx, "system", c); err != nil {
			s.log.Warn("website mail of the account not switched", "customer", c.Username, "err", err)
		}
	}
}

const settingEmailZitKnown = "emailzit_known"

// emailzitKnows: a local EmailZit has the customer (same UUID).
func (s *Server) emailzitKnows(ctx context.Context, uuid string) bool {
	var m map[string]bool
	_ = s.store.GetSetting(ctx, settingEmailZitKnown, &m)
	return m[uuid]
}

func (s *Server) setEmailZitKnows(ctx context.Context, uuid string, known bool) {
	var m map[string]bool
	_ = s.store.GetSetting(ctx, settingEmailZitKnown, &m)
	if m == nil {
		m = map[string]bool{}
	}
	if known {
		m[uuid] = true
	} else {
		delete(m, uuid)
	}
	_ = s.store.SetSetting(ctx, settingEmailZitKnown, m)
}

// ---- the settings page

type emailzitData struct {
	L      EmailZitLink
	Manual bool // linked by hand: address + token typed in
	Local  bool // EmailZit runs on this server
	// Own are the addresses HostZit tells EmailZit at the pairing.
	Own []string
	// OIDCLeft: a sign-in client for EmailZit is still set (no longer used).
	OIDCLeft bool
}

func (s *Server) handleEmailZit(w http.ResponseWriter, r *http.Request) {
	l := s.emailzitLink(r.Context())
	d := &emailzitData{L: l, Manual: l.URL != "" && !l.Paired, Local: localEmailZit(), Own: s.ownAddresses(r.Context()), OIDCLeft: s.oidcClient(r.Context()).ID != ""}
	s.render(w, r, http.StatusOK, "emailzit", &Page{Title: "EmailZit", Nav: "settings", Data: d})
}

// handleEmailZitSave keeps the package for cPanel imports.
func (s *Server) handleEmailZitSave(w http.ResponseWriter, r *http.Request) {
	l := s.emailzitLink(r.Context())
	pkg := strings.TrimSpace(r.FormValue("import_package"))
	if pkg != "" && !slugRE.MatchString(pkg) {
		s.redirectErr(w, r, "/settings/emailzit", "A package slug has lower-case letters, digits and dashes.")
		return
	}
	if l.URL == "" {
		s.redirectErr(w, r, "/settings/emailzit", "Link EmailZit first.")
		return
	}
	l.ImportPackage = pkg
	if err := s.store.SetSetting(r.Context(), settingEmailZit, l); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.emailzit", "settings", "EmailZit package for cPanel imports %q", pkg)
	s.redirect(w, r, "/settings/emailzit", "Saved.")
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

func (s *Server) handleEmailZitPair(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fail := func(msg string) { s.redirectErr(w, r, "/settings/emailzit", msg) }
	code, err := parsePairingCode(r.FormValue("code"))
	if err != nil {
		fail(err.Error())
		return
	}
	hs := s.hostingSettings(ctx)
	n, _ := s.Network(ctx)
	_, port, _ := splitListen(n.AdminListen)
	if hs.ServerName == "" || port == 0 {
		fail("Set the server name under Settings → Hosting first: EmailZit reaches HostZit by it.")
		return
	}
	own := s.ownAddresses(ctx)
	extra := netacl.Split(r.FormValue("addresses"))
	if len(extra) > 0 {
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
		s.removeAdminAddresses(context.WithoutCancel(ctx), added)
	}
	addrs, err := store.CleanTokenAddresses(ans.Addresses)
	if err != nil || len(addrs) == 0 {
		addrs = resolveHost(ctx, host)
	}
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
	tokID, hzTok, err := s.store.CreateAPIToken(ctx, u.ID, "EmailZit link ("+truncateStr(host, 60)+")", 0, []string{"dns:mail"}, addrs)
	if err != nil {
		undo(0, added)
		fail(storeErr(err))
		return
	}
	st, b, err = ezRequest(ctx, cl, code.URL, http.MethodPut, "/api/v1/link/hostzit/dns-token", "Bearer "+ezTok, map[string]string{"token": hzTok})
	if err != nil || st >= 300 {
		undo(tokID, added)
		detail := ezErrorCode(b)
		if err != nil {
			detail = err.Error()
		}
		s.log.Warn("EmailZit pairing step 2", "status", st, "detail", detail)
		fail(translate(s.lang(r, userFrom(r)), "EmailZit could not use HostZit's token (%s). Check that EmailZit reaches %s and make a new code.", detail, hostzitURL))
		return
	}
	old := s.emailzitLink(ctx)
	l := EmailZitLink{URL: code.URL, Token: s.store.SealSecret("emailzit.token", ezTok), Paired: true, MailHost: strings.ToLower(truncateStr(ans.MailHost, 253)),
		Pin: code.Pin, Addresses: addrs, OwnAddresses: own, DNSTokenID: tokID, AdminAdded: added, ImportPackage: old.ImportPackage,
		LinkedAt: s.now().UTC(), LinkedBy: u.Username}
	if rl := ans.Relay; rl != nil && rl.Host != "" {
		if (hosting.ValidDomain(rl.Host) || net.ParseIP(rl.Host) != nil) && rl.Port > 0 && rl.Port < 65536 && rl.Username != "" && len(rl.Username) <= 200 && len(rl.Password) <= 200 && !strings.ContainsAny(rl.Username+rl.Password, "\r\n") {
			l.Relay = &EmailZitRelay{Host: strings.ToLower(rl.Host), Port: rl.Port, Username: rl.Username, Password: s.store.SealSecret("emailzit.relay", rl.Password), StartTLS: rl.StartTLS}
		}
	}
	if err := s.store.SetSetting(ctx, settingEmailZit, l); err != nil {
		undo(tokID, added)
		s.serverError(w, r, err)
		return
	}
	// what the old link left behind
	if old.DNSTokenID != 0 && old.DNSTokenID != tokID {
		_ = s.store.DeleteAPITokenByID(ctx, old.DNSTokenID)
	}
	if old.URL != "" && old.URL != l.URL && old.Token != "" {
		if t, err := s.store.OpenSecret("emailzit.token", old.Token); err == nil {
			_, _, _ = ezRequest(ctx, emailzitClient(urlHost(old.URL), old.Pin, old.Insecure, 10*time.Second), old.URL, http.MethodDelete, "/api/v1/link/hostzit", "Bearer "+t, nil)
		}
	}
	var stale []string
	for _, a := range old.AdminAdded {
		if !slices.Contains(added, a) && !slices.Contains(addrs, a) {
			stale = append(stale, a)
		}
	}
	s.removeAdminAddresses(ctx, stale)
	s.audit(r, "emailzit.paired", "settings", "paired with EmailZit %s (its token only from %s; HostZit's dns:mail token #%d only from %s; relay %v)",
		l.URL, strings.Join(own, " "), tokID, strings.Join(addrs, " "), l.Relay != nil)
	if err := s.applyRelay(ctx, actor(r)); err != nil {
		s.log.Warn("website mail after the pairing", "err", err)
	}
	// SPF records of the zones get EmailZit's relay
	go s.syncAllMail(context.WithoutCancel(ctx))
	if localEmailZit() {
		list, _ := s.store.Customers(ctx, store.CustomerFilter{})
		for _, c := range list {
			s.syncWebUIDs(ctx, c)
		}
	}
	s.redirect(w, r, "/settings/emailzit", "EmailZit is linked.")
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

// removeAdminAddresses takes back what allowAdminAddresses added.
func (s *Server) removeAdminAddresses(ctx context.Context, list []string) {
	if len(list) == 0 {
		return
	}
	n, err := s.Network(ctx)
	if err != nil {
		return
	}
	n.AdminAllowed = slices.DeleteFunc(n.AdminAllowed, func(a string) bool { return slices.Contains(list, a) })
	if err := s.SaveNetwork(ctx, n); err != nil {
		s.log.Warn("EmailZit addresses not removed from the admin port", "err", err)
	}
}

// dropLink forgets the link here: HostZit's token, the relay login and
// the admin-port addresses of the pairing go.
func (s *Server) dropLink(ctx context.Context, by string, l EmailZitLink) error {
	if err := s.store.SetSetting(ctx, settingEmailZit, EmailZitLink{}); err != nil {
		return err
	}
	if l.DNSTokenID != 0 {
		_ = s.store.DeleteAPITokenByID(ctx, l.DNSTokenID)
	}
	s.removeAdminAddresses(ctx, l.AdminAdded)
	if err := s.applyRelay(ctx, by); err != nil {
		s.log.Warn("website mail after the unlink", "err", err)
	}
	go s.syncAllMail(context.WithoutCancel(ctx))
	return nil
}

func (s *Server) handleEmailZitUnlink(w http.ResponseWriter, r *http.Request) {
	l := s.emailzitLink(r.Context())
	if l.URL == "" {
		s.redirect(w, r, "/settings/emailzit", "Not linked.")
		return
	}
	msg := "The link is ended on both sides."
	st, _, err := s.emailzitDo(r.Context(), http.MethodDelete, "/api/v1/link/hostzit", nil)
	if !l.Paired {
		msg = "The link is ended here. It was typed in by hand: revoke HostZit's token in EmailZit as well."
	} else if err != nil || (st >= 300 && st != http.StatusNotFound && st != http.StatusUnauthorized) {
		msg = "The link is ended here; EmailZit could not be reached, so remove the link there as well."
	}
	if err := s.dropLink(r.Context(), actor(r), l); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "emailzit.unlink", "settings", "link with EmailZit %s ended", l.URL)
	s.redirect(w, r, "/settings/emailzit", msg)
}

// apiLinkDelete: EmailZit ends the link from its side with HostZit's token.
func (s *Server) apiLinkDelete(w http.ResponseWriter, r *http.Request) {
	t := apiToken(r)
	l := s.emailzitLink(r.Context())
	// the caller is done with its token in any case
	_ = s.store.DeleteAPITokenByID(r.Context(), t.ID)
	if l.URL != "" && (!l.Paired || l.DNSTokenID == t.ID) {
		if err := s.dropLink(r.Context(), apiActor(r), l); err != nil {
			apiError(w, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		s.apiAudit(r, "emailzit.unlink", "settings", "EmailZit %s ended the link", l.URL)
	} else {
		s.apiAudit(r, "api.token.delete", "settings", "API token #%d %q revoked by EmailZit's unlink", t.ID, t.Name)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- the customer's switch to EmailZit

// handleEmailZitOpen asks EmailZit for a one-time sign-in link of the
// customer (same UUID in both products) and goes there.
func (s *Server) handleEmailZitOpen(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	note := ""
	st, b, err := s.emailzitDo(r.Context(), http.MethodPost, "/api/v1/customers/"+url.PathEscape(c.UUID)+"/sso", map[string]any{})
	switch {
	case err != nil:
		s.log.Warn("EmailZit sign-in link", "customer", c.Username, "err", err)
		note = "EmailZit cannot be reached right now. Try again in a few minutes."
	case st == http.StatusNotFound:
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
		l := s.emailzitLink(r.Context())
		if json.Unmarshal(b, &out) == nil && ezLinkTarget(out.URL, l.URL, l.MailHost) {
			s.audit(r, "emailzit.sso", "customer:"+c.Username, "opened EmailZit with a one-time link")
			http.Redirect(w, r, out.URL, http.StatusSeeOther)
			return
		}
		note = "EmailZit did not open a session. Try again in a few minutes."
	}
	s.redirectErr(w, r, "/", note)
}

// ezLinkTarget: the one-time link must lead to the linked EmailZit (its
// panel address or its mail host name), never somewhere else.
func ezLinkTarget(link, panel, mailHost string) bool {
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return h != "" && (h == strings.ToLower(urlHost(panel)) || mailHost != "" && h == mailHost)
}
