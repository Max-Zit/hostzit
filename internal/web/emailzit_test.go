package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/max-zit/hostzit/internal/store"
	"github.com/max-zit/hostzit/internal/tlsutil"
)

// fakeEZ is EmailZit's side of the pairing (INTEGRATION.md "Pairing
// protocol", EmailZit 0.10.0).
type fakeEZ struct {
	srv       *httptest.Server
	mu        sync.Mutex
	secret    string
	calls     []string
	step1     map[string]any
	dnsTok    string
	addresses []string
	ssoStatus int
	// knows: the customers this EmailZit has (nil = every customer)
	knows func(uuid string) bool
	token string // the ezt_ token it hands out
	extra http.HandlerFunc
}

func newFakeEZ(t *testing.T, extra http.HandlerFunc) *fakeEZ {
	f := &fakeEZ{secret: "pairing-secret-1", ssoStatus: http.StatusCreated, extra: extra, addresses: []string{"127.0.0.1"}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// code is a pairing code with the pin of the test server's certificate
// (which no system trusts, so the pin is what HostZit checks).
func (f *fakeEZ) code() string {
	b, _ := json.Marshal(map[string]any{"v": 1, "url": f.srv.URL, "secret": f.secret, "pin": tlsutil.SPKIPin(f.srv.Certificate().Raw)})
	return "ezlink_" + base64.RawURLEncoding.EncodeToString(b)
}

func (f *fakeEZ) seen(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func (f *fakeEZ) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization")+" "+string(body))
	f.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/link/hostzit":
		if r.Header.Get("Authorization") != "Pairing "+f.secret {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "invalid_code"}})
			return
		}
		f.mu.Lock()
		_ = json.Unmarshal(body, &f.step1)
		addrs := f.addresses
		f.mu.Unlock()
		writeJSON(w, http.StatusCreated, map[string]any{"api_token": f.tok(), "scopes": []string{"customers:read", "customers:write", "sso:create"},
			"emailzit_addresses": addrs, "emailzit_url": f.srv.URL, "emailzit_mail_host": "mail.example.test",
			"relay": map[string]any{"host": "mail.example.test", "port": 2587, "username": "hostzit-relay@mail.example.test", "password": "relay-pass-1", "starttls": true}})
	case r.Method == http.MethodPut && r.URL.Path == "/api/v1/link/hostzit/dns-token":
		if r.Header.Get("Authorization") != "Bearer "+f.tok() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var in struct {
			Token string `json:"token"`
		}
		_ = json.Unmarshal(body, &in)
		f.mu.Lock()
		f.dnsTok = in.Token
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/link/hostzit":
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/customers/") && strings.Count(r.URL.Path, "/") == 4:
		if r.Header.Get("Authorization") != "Bearer "+f.tok() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		k := f.knows
		f.mu.Unlock()
		if k != nil && !k(strings.TrimPrefix(r.URL.Path, "/api/v1/customers/")) {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]string{"code": "customer_not_found"}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": strings.TrimPrefix(r.URL.Path, "/api/v1/customers/")})
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/sso"):
		f.mu.Lock()
		st := f.ssoStatus
		f.mu.Unlock()
		if st != http.StatusCreated {
			writeJSON(w, st, map[string]any{"error": map[string]string{"code": "no_login"}})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"url": f.srv.URL + "/sso/one-time", "expires_at": time.Now().Add(time.Minute)})
	case f.extra != nil:
		f.extra(w, r)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// pairEmailZit links the test server with a fake EmailZit.
func pairEmailZit(t *testing.T, a *client, f *fakeEZ) {
	t.Helper()
	a.ok("/settings/hosting", url.Values{"mode": {"shared"}, "server_name": {"host1.hostzit.test"}, "ipv4": {"192.0.2.10"}, "ipv6": {"2001:db8::10"},
		"nameservers": {"ns1.hostzit.test\nns2.hostzit.test"}, "default_php": {"8.4"}, "grace_days": {"14"}, "spf": {"v=spf1 a mx ~all"}})
	a.ok("/settings/emailzit/pair", url.Values{"code": {f.code()}})
}

func TestEmailZitPairing(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin()
	ctx := context.Background()
	f := newFakeEZ(t, nil)
	// a foreign address and a whole network in EmailZit's answer: only the
	// address its name resolves to is kept (else the admin port would open)
	f.addresses = []string{"127.0.0.1", "203.0.113.25", "0.0.0.0/0"}

	// a code that is no code, and a code EmailZit refuses
	if st, _, _ := a.post("/settings/emailzit/pair", url.Values{"code": {"ezt_not_a_code"}}); st != http.StatusSeeOther {
		t.Fatal(st)
	}
	if firstLink(e).URL != "" || f.seen("POST") {
		t.Fatal("a bad code reached EmailZit")
	}
	pairEmailZit(t, a, f)
	l := firstLink(e)
	if !l.Paired || l.URL != f.srv.URL || l.MailHost != "mail.example.test" || l.Relay == nil || l.Relay.Port != 2587 || l.DNSTokenID == 0 {
		t.Fatalf("link %+v", l)
	}
	if l.Relay.Password == "relay-pass-1" || strings.Contains(l.Token, "ezt_paired_token") {
		t.Fatal("relay password or token stored in the clear")
	}
	// step 1 told EmailZit the server's URL and both addresses
	f.mu.Lock()
	s1, dnsTok := f.step1, f.dnsTok
	f.mu.Unlock()
	if s1["hostzit_url"] != "https://host1.hostzit.test:8442" || !strings.Contains(strings.Join(anyStrings(s1["addresses"]), " "), "192.0.2.10 2001:db8::10") || s1["pin"] == "" {
		t.Fatalf("step 1 %v", s1)
	}
	// step 2 handed over a dns:mail token that works only from EmailZit's addresses
	if !strings.HasPrefix(dnsTok, "hzt_") {
		t.Fatal(dnsTok)
	}
	tok, err := e.srv.store.APITokens(ctx, 1)
	if err != nil || len(tok) != 1 || !slices.Equal(tok[0].Scopes, []string{"dns:mail"}) || !slices.Equal(tok[0].AllowedIPs, []string{"127.0.0.1"}) {
		t.Fatalf("tokens %+v %v", tok, err)
	}
	// nothing foreign reached the admin port (the loopback address always may)
	if len(l.AdminAdded) != 0 {
		t.Fatal(l.AdminAdded)
	}
	n, _ := e.srv.Network(ctx)
	if slices.Contains(n.AdminAllowed, "203.0.113.25") || slices.Contains(n.AdminAllowed, "0.0.0.0/0") {
		t.Fatal(n.AdminAllowed)
	}
	api := func(method, path, tok string) int {
		req, _ := http.NewRequest(method, e.admin.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if st := api("GET", "/api/v1/zit/info", dnsTok); st != http.StatusOK {
		t.Fatal("token check with zit/info", st)
	}
	if st := api("GET", "/api/v1/zit/info", "hzt_wrong"); st != http.StatusUnauthorized {
		t.Fatal("zit/info took a wrong token", st)
	}
	if st := api("GET", "/api/v1/customers", dnsTok); st != http.StatusForbidden {
		t.Fatal("the dns:mail token read customers", st)
	}
	page := a.page("/settings/emailzit")
	for _, want := range []string{"mail.example.test", "127.0.0.1", "2001:db8::10", "2587"} {
		if !strings.Contains(page, want) {
			t.Fatalf("settings page without %q", want)
		}
	}
	if strings.Contains(page, "relay-pass-1") || strings.Contains(page, dnsTok) {
		t.Fatal("a secret on the settings page")
	}

	// EmailZit ends the link from its side with HostZit's token
	if st := api("DELETE", "/api/v1/link/emailzit", dnsTok); st != http.StatusOK {
		t.Fatal(st)
	}
	if l := firstLink(e); l.URL != "" {
		t.Fatalf("still linked %+v", l)
	}
	if st := api("GET", "/api/v1/zit/info", dnsTok); st != http.StatusUnauthorized {
		t.Fatal("HostZit's token still works after the unlink", st)
	}
	n, _ = e.srv.Network(ctx)
	if slices.Contains(n.AdminAllowed, "203.0.113.25") {
		t.Fatal("EmailZit's address still reaches the admin port", n.AdminAllowed)
	}

	// link again, then end it from HostZit's side
	f.addresses = []string{"127.0.0.1"}
	a.ok("/settings/emailzit/pair", url.Values{"code": {f.code()}})
	if !firstLink(e).Paired {
		t.Fatal("not paired again")
	}
	a.ok("/settings/emailzit/"+firstLink(e).ID+"/unlink", url.Values{})
	if !f.seen("DELETE /api/v1/link/hostzit Bearer ezt_paired_token") || firstLink(e).URL != "" {
		t.Fatal("unlink from HostZit")
	}
	if tok, _ := e.srv.store.APITokens(ctx, 1); len(tok) != 0 {
		t.Fatal("HostZit's token left after the unlink", tok)
	}

	// a wrong secret: EmailZit answers invalid_code and nothing is kept
	f.secret = "another-secret"
	b, _ := json.Marshal(map[string]any{"v": 1, "url": f.srv.URL, "secret": "pairing-secret-1", "pin": tlsutil.SPKIPin(f.srv.Certificate().Raw)})
	if st, _, _ := a.post("/settings/emailzit/pair", url.Values{"code": {"ezlink_" + base64.RawURLEncoding.EncodeToString(b)}}); st != http.StatusSeeOther {
		t.Fatal(st)
	}
	if firstLink(e).URL != "" {
		t.Fatal("linked with a wrong code")
	}
	// a code with a pin that does not match the certificate is refused before anything is sent
	b, _ = json.Marshal(map[string]any{"v": 1, "url": f.srv.URL, "secret": "another-secret", "pin": base64.StdEncoding.EncodeToString(make([]byte, 32))})
	f.mu.Lock()
	f.calls = nil
	f.mu.Unlock()
	a.post("/settings/emailzit/pair", url.Values{"code": {"ezlink_" + base64.RawURLEncoding.EncodeToString(b)}})
	if f.seen("POST") || firstLink(e).URL != "" {
		t.Fatal("pairing with a certificate that does not match the pin")
	}
}

func anyStrings(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, x := range l {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

// The customer's switch opens EmailZit with a one-time link; web-uids go
// only to EmailZit on the same server.
func TestEmailZitSwitchAndWebUIDs(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	got := make(chan string, 8)
	f := newFakeEZ(t, func(w http.ResponseWriter, r *http.Request) {
		got <- r.Method + " " + r.URL.Path
		w.WriteHeader(http.StatusNotFound) // web-uids of a customer EmailZit does not know
	})
	a := e.setupAdmin()
	pairEmailZit(t, a, f)
	a.ok("/packages/new", url.Values{"name": {"P"}, "slug": {"p"}, "max_sites": {"1"}, "max_dbs": {"1"}, "max_zones": {"1"}, "disk_mb": {"100"}, "inodes": {"0"},
		"cpu_percent": {"0"}, "memory_mb": {"0"}, "processes": {"0"}, "io_weight": {"100"}, "php_workers": {"2"}, "php_memory_mb": {"128"}, "upload_mb": {"8"}, "mail_per_hour": {"0"}})
	a.ok("/customers/new", url.Values{"username": {"mailer"}, "package": {"1"}, "password": {"mailer password 1"}})
	select {
	case m := <-got:
		t.Fatal("EmailZit on another server got", m)
	case <-time.After(300 * time.Millisecond):
	}
	old := localEmailZit
	localEmailZit = func() bool { return true }
	t.Cleanup(func() { localEmailZit = old })
	c, _ := e.st.CustomerByRef(ctx, "mailer")
	e.srv.syncWebUIDs(ctx, c)
	select {
	case m := <-got:
		if m != "PUT /api/v1/customers/"+c.UUID+"/web-uids" {
			t.Fatal(m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("local EmailZit was not told the uid")
	}
	// the admin's switch goes to EmailZit's panel, the customer's to the one-time link
	if !strings.Contains(a.page("/"), `href="`+f.srv.URL+`/"`) {
		t.Fatal("no switch to EmailZit for the admin")
	}
	p := e.client(e.panel.URL)
	p.ok("/login", url.Values{"username": {"mailer"}, "password": {"mailer password 1"}})
	if !strings.Contains(p.page("/"), `href="/emailzit"`) {
		t.Fatal("no switch for the customer")
	}
	if st, _, loc := p.get("/emailzit"); st != http.StatusSeeOther || loc != f.srv.URL+"/sso/one-time" {
		t.Fatalf("switch: %d %s", st, loc)
	}
	if !f.seen("POST /api/v1/customers/" + c.UUID + "/sso Bearer ezt_paired_token") {
		t.Fatal("no sso call")
	}
	// no login in EmailZit: back to the panel with a note
	f.mu.Lock()
	f.ssoStatus = http.StatusConflict
	f.mu.Unlock()
	if st, _, loc := p.get("/emailzit"); st != http.StatusSeeOther || loc != "/" {
		t.Fatalf("no login: %d %s", st, loc)
	}
	if !strings.Contains(p.page("/"), "not switched on") {
		t.Fatal("no note without a login")
	}
}

// API tokens may be limited to addresses; the hint asks for IPv4 and IPv6.
func TestAPITokenAddresses(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin()
	if !strings.Contains(a.page("/account"), "IPv4 and IPv6") {
		t.Fatal("no address hint on the token form")
	}
	a.post("/account/tokens", url.Values{"name": {"far"}, "days": {"0"}, "scope_customers:read": {"on"}, "allowed": {"203.0.113.7, 2001:db8::/64"}})
	a.post("/account/tokens", url.Values{"name": {"near"}, "days": {"0"}, "scope_customers:read": {"on"}, "allowed": {"127.0.0.1"}})
	if st, body, _ := a.post("/account/tokens", url.Values{"name": {"bad"}, "days": {"0"}, "scope_customers:read": {"on"}, "allowed": {"not-an-address"}}); st != http.StatusBadRequest || !strings.Contains(body, "not an IP address") {
		t.Fatal("bad address taken", st)
	}
	list, _ := e.st.APITokens(context.Background(), 1)
	if len(list) != 2 {
		t.Fatal(list)
	}
	for _, tk := range list {
		if tk.Name == "far" && !slices.Equal(tk.AllowedIPs, []string{"203.0.113.7", "2001:db8::/64"}) {
			t.Fatal(tk.AllowedIPs)
		}
	}
	// a token the test can use: made in the store with a known value
	_, far, _ := e.st.CreateAPIToken(context.Background(), 1, "far2", 0, []string{"customers:read"}, []string{"203.0.113.7"})
	_, near, _ := e.st.CreateAPIToken(context.Background(), 1, "near2", 0, []string{"customers:read"}, []string{"127.0.0.0/8", "::1"})
	call := func(tok string) int {
		req, _ := http.NewRequest("GET", e.admin.URL+"/api/v1/customers", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if st := call(far); st != http.StatusForbidden {
		t.Fatal("token used from an address it does not allow", st)
	}
	if st := call(near); st != http.StatusOK {
		t.Fatal("token from its own address", st)
	}
	// a refused address is not counted as a failed sign-in
	for i := 0; i < 10; i++ {
		call(far)
	}
	if st := call(near); st != http.StatusOK {
		t.Fatal("the address was blocked after wrong-address calls", st)
	}
}

// With EmailZit's relay the default SPF of a zone here names EmailZit's
// mail host (a record the customer wrote stays), and goes back after the
// unlink. A local EmailZit gets the websites' mail only of customers it knows.
func TestRelaySPFAndLocalSendmail(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var known atomic.Bool
	f := newFakeEZ(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/web-uids") && !known.Load() {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	a := e.setupAdmin()
	pairEmailZit(t, a, f)
	a.ok("/packages/new", url.Values{"name": {"P"}, "slug": {"p"}, "max_sites": {"3"}, "max_dbs": {"1"}, "max_zones": {"3"}, "disk_mb": {"100"}, "inodes": {"0"},
		"cpu_percent": {"0"}, "memory_mb": {"0"}, "processes": {"0"}, "io_weight": {"100"}, "php_workers": {"2"}, "php_memory_mb": {"128"}, "upload_mb": {"8"}, "mail_per_hour": {"10"}})
	a.ok("/customers/new", url.Values{"username": {"web1"}, "package": {"1"}, "domain": {"web1.example.com"}, "dns": {"on"}, "password": {"web1 password 123"}})
	c, _ := e.st.CustomerByRef(ctx, "web1")
	f.mu.Lock()
	f.knows = func(string) bool { return known.Load() }
	f.mu.Unlock()
	known.Store(true)
	e.srv.resolveCustomer(ctx, c)
	spf := func() string {
		z, _ := e.st.ZoneFor(ctx, "web1.example.com")
		rows, _ := e.st.Records(ctx, z.ID)
		for _, r := range rows {
			if r.Owner == "" && r.Name == "@" && r.Type == "TXT" {
				return unquoteTXT(r.Content)
			}
		}
		return ""
	}
	e.srv.syncMailAccount(ctx, "test", c)
	if got := spf(); got != "v=spf1 a mx a:mail.example.test ~all" {
		t.Fatalf("SPF with the relay: %q", got)
	}
	e.srv.syncMailAccount(ctx, "test", c) // stays, no second mechanism
	if got := spf(); got != "v=spf1 a mx a:mail.example.test ~all" {
		t.Fatalf("SPF after a second sync: %q", got)
	}
	// the customer sees the SPF as fine
	p := e.client(e.panel.URL)
	p.ok("/login", url.Values{"username": {"web1"}, "password": {"web1 password 123"}})
	if page := p.page("/security"); !strings.Contains(page, "hz1._domainkey.web1.example.com") || strings.Contains(page, "to the SPF record") {
		t.Fatal("security page: DKIM row missing or SPF reported as missing")
	}
	a.ok("/settings/emailzit/"+firstLink(e).ID+"/unlink", url.Values{})
	e.srv.syncMailAccount(ctx, "test", c)
	if got := spf(); got != "v=spf1 a mx ~all" {
		t.Fatalf("SPF after the unlink: %q", got)
	}

	// EmailZit on this server: its sendmail only for a customer it knows
	old := localEmailZit
	localEmailZit = func() bool { return true }
	t.Cleanup(func() { localEmailZit = old })
	known.Store(false)
	pairEmailZit(t, a, f)
	e.srv.syncWebUIDs(ctx, c)
	if acc, _, _ := e.srv.accountFor(ctx, c); acc.Sendmail != "" {
		t.Fatal("a customer EmailZit does not know got EmailZit's sendmail")
	}
	known.Store(true)
	e.srv.syncWebUIDs(ctx, c)
	if acc, _, _ := e.srv.accountFor(ctx, c); acc.Sendmail != "/usr/sbin/emailzit-sendmail" {
		t.Fatal("a customer EmailZit knows keeps HostZit's queue")
	}
}

func TestSPFWith(t *testing.T) {
	for in, want := range map[string]string{"v=spf1 a mx ~all": "v=spf1 a mx a:m.test ~all", "v=spf1 mx -all": "v=spf1 mx a:m.test -all", "v=spf1 a": "v=spf1 a a:m.test"} {
		if got := spfWith(in, "a:m.test"); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
	if !spfDefaultWithRelay("v=spf1 a mx a:old.test ~all", "v=spf1 a mx ~all") || spfDefaultWithRelay("v=spf1 a mx include:x ~all", "v=spf1 a mx ~all") {
		t.Fatal("spfDefaultWithRelay")
	}
}

// tok is the ezt_ token this fake EmailZit hands out.
func (f *fakeEZ) tok() string {
	if f.token != "" {
		return f.token
	}
	return "ezt_paired_token"
}

// firstLink is the first EmailZit link (empty when there is none).
func firstLink(e *env) EmailZitLink {
	links := e.srv.emailzitLinks(context.Background())
	if len(links) == 0 {
		return EmailZitLink{}
	}
	return links[0]
}

// One HostZit with two EmailZit servers: each customer is found on its
// own EmailZit, opens that one, sends through its relay; a customer on
// neither sends directly. An EmailZit of one client (scope "assigned")
// sees nothing of the others. Unlinking one EmailZit leaves the other.
func TestManyEmailZitLinks(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := e.setupAdmin()
	fa := newFakeEZ(t, nil)
	fb := newFakeEZ(t, nil)
	fb.secret, fb.token = "pairing-secret-b", "ezt_token_b"
	var onA, onB sync.Map
	fa.knows = func(u string) bool { _, ok := onA.Load(u); return ok }
	fb.knows = func(u string) bool { _, ok := onB.Load(u); return ok }
	pairEmailZit(t, a, fa)
	a.ok("/settings/emailzit/pair", url.Values{"code": {fb.code()}})
	links := e.srv.emailzitLinks(ctx)
	if len(links) != 2 || links[0].URL != fa.srv.URL || links[1].URL != fb.srv.URL || links[0].ID == links[1].ID {
		t.Fatalf("links %+v", links)
	}
	la, lb := links[0], links[1]
	a.ok("/packages/new", url.Values{"name": {"P"}, "slug": {"p"}, "max_sites": {"3"}, "max_dbs": {"1"}, "max_zones": {"3"}, "disk_mb": {"100"}, "inodes": {"0"},
		"cpu_percent": {"0"}, "memory_mb": {"0"}, "processes": {"0"}, "io_weight": {"100"}, "php_workers": {"2"}, "php_memory_mb": {"128"}, "upload_mb": {"8"}, "mail_per_hour": {"10"}})
	cust := map[string]*store.Customer{}
	for _, n := range []string{"custa", "custb", "custnone"} {
		a.ok("/customers/new", url.Values{"username": {n}, "package": {"1"}, "domain": {n + ".example.com"}, "dns": {"on"}, "password": {n + " password 123"}})
		cust[n], _ = e.st.CustomerByRef(ctx, n)
	}
	onA.Store(cust["custa"].UUID, true)
	onB.Store(cust["custb"].UUID, true)
	e.srv.resolveAllCustomers(ctx)
	for n, want := range map[string]string{"custa": la.ID, "custb": lb.ID, "custnone": ""} {
		l, _ := e.srv.linkFor(ctx, cust[n])
		if l.ID != want {
			t.Fatalf("%s is on %q, want %q", n, l.ID, want)
		}
	}
	// website mail: each through its own EmailZit, the third directly
	for n, want := range map[string]string{"custa": la.ID, "custb": lb.ID, "custnone": ""} {
		e.hp.mu.Lock()
		e.hp.calls = nil
		e.hp.mu.Unlock()
		e.srv.syncMailAccount(ctx, "test", cust[n])
		if !e.hp.called(`mail.account {"account":"`+n+`"`) || (want != "" && !e.hp.called(`mail.account {"account":"`+n+`","mail":{"primary":"`+n+`.example.com","domains":["`+n+`.example.com"],"dkim":`)) {
			t.Fatalf("%s: no mail.account call", n)
		}
		var relay string
		e.hp.mu.Lock()
		for _, c := range e.hp.calls {
			if strings.HasPrefix(c, `mail.account {"account":"`+n+`"`) {
				if i := strings.Index(c, `"relay":"`); i > 0 {
					relay = strings.SplitN(c[i+9:], `"`, 2)[0]
				}
			}
		}
		e.hp.mu.Unlock()
		if relay != want {
			t.Fatalf("%s sends through %q, want %q", n, relay, want)
		}
	}
	if !e.hp.called(`mail.relay`) {
		e.srv.applyRelay(ctx, "test")
	}
	// the switch opens each customer's own EmailZit
	for n, f := range map[string]*fakeEZ{"custa": fa, "custb": fb} {
		p := e.client(e.panel.URL)
		p.ok("/login", url.Values{"username": {n}, "password": {n + " password 123"}})
		if st, _, loc := p.get("/emailzit"); st != http.StatusSeeOther || !strings.HasPrefix(loc, f.srv.URL) {
			t.Fatalf("%s switch: %d %s", n, st, loc)
		}
	}
	p := e.client(e.panel.URL)
	p.ok("/login", url.Values{"username": {"custnone"}, "password": {"custnone password 123"}})
	if _, _, loc := p.get("/emailzit"); loc != "/" {
		t.Fatalf("a customer without mail went to %s", loc)
	}

	// EmailZit B belongs to one client: assigned only cb; it learns nothing of ca
	a.ok("/settings/emailzit/"+lb.ID+"/scope", url.Values{"scope": {"assigned"}, "customers": {"custb"}})
	fb.mu.Lock()
	dnsB := fb.dnsTok
	fb.mu.Unlock()
	fa.mu.Lock()
	dnsA := fa.dnsTok
	fa.mu.Unlock()
	api := func(tok, path string) int {
		req, _ := http.NewRequest("GET", e.admin.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if st := api(dnsB, "/api/v1/domains/custa.example.com"); st != http.StatusNotFound {
		t.Fatal("EmailZit B learned about customer ca", st)
	}
	if st := api(dnsB, "/api/v1/dns/zones/custa.example.com/owned/emailzit"); st != http.StatusNotFound {
		t.Fatal("EmailZit B read ca's zone", st)
	}
	if st := api(dnsB, "/api/v1/domains/custb.example.com"); st != http.StatusOK {
		t.Fatal("EmailZit B cannot see its own customer", st)
	}
	// EmailZit A (all customers) no longer serves cb, assigned to B
	if st := api(dnsA, "/api/v1/domains/custb.example.com"); st != http.StatusNotFound {
		t.Fatal("EmailZit A still sees cb", st)
	}
	if st := api(dnsA, "/api/v1/domains/custa.example.com"); st != http.StatusOK {
		t.Fatal("EmailZit A cannot see ca", st)
	}

	// a link whose token EmailZit no longer takes shows as broken
	fa.mu.Lock()
	fa.token = "ezt_changed"
	fa.mu.Unlock()
	e.srv.checkEmailZitLinks(ctx)
	if l, _ := e.srv.emailzitLinkByID(ctx, la.ID); l.State != "broken" {
		t.Fatalf("state %q", l.State)
	}
	if !strings.Contains(a.page("/settings/emailzit"), "not working") {
		t.Fatal("the page does not show the broken link")
	}

	// EmailZit B ends its link: A stays
	req, _ := http.NewRequest("DELETE", e.admin.URL+"/api/v1/link/emailzit", nil)
	req.Header.Set("Authorization", "Bearer "+dnsB)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatal(err, resp.StatusCode)
	}
	resp.Body.Close()
	links = e.srv.emailzitLinks(ctx)
	if len(links) != 1 || links[0].ID != la.ID {
		t.Fatalf("after B's unlink: %+v", links)
	}
	if l, ok := e.srv.linkFor(ctx, cust["custb"]); ok {
		t.Fatalf("cb still on %s", l.ID)
	}
}

// An EmailZit paired for one client (scope chosen in the pairing form) is
// never asked about, nor allowed near, the other customers.
func TestPairAssignedLearnsNothing(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := e.setupAdmin()
	a.ok("/settings/hosting", url.Values{"mode": {"shared"}, "server_name": {"host1.hostzit.test"}, "ipv4": {"192.0.2.10"}, "ipv6": {"2001:db8::10"},
		"nameservers": {"ns1.hostzit.test\nns2.hostzit.test"}, "default_php": {"8.4"}, "grace_days": {"14"}, "spf": {"v=spf1 a mx ~all"}})
	a.ok("/packages/new", url.Values{"name": {"P"}, "slug": {"p"}, "max_sites": {"3"}, "max_dbs": {"1"}, "max_zones": {"3"}, "disk_mb": {"100"}, "inodes": {"0"},
		"cpu_percent": {"0"}, "memory_mb": {"0"}, "processes": {"0"}, "io_weight": {"100"}, "php_workers": {"2"}, "php_memory_mb": {"128"}, "upload_mb": {"8"}, "mail_per_hour": {"10"}})
	for _, n := range []string{"client1", "other1"} {
		a.ok("/customers/new", url.Values{"username": {n}, "package": {"1"}, "domain": {n + ".example.com"}, "dns": {"on"}, "password": {n + " password 123"}})
	}
	client, _ := e.st.CustomerByRef(ctx, "client1")
	other, _ := e.st.CustomerByRef(ctx, "other1")
	f := newFakeEZ(t, nil) // claims every customer it is asked about
	a.ok("/settings/emailzit/pair", url.Values{"code": {f.code()}, "scope": {"assigned"}, "customers": {"client1"}})
	l := firstLink(e)
	if l.Scope != "assigned" || !slices.Equal(l.Customers, []string{client.UUID}) {
		t.Fatalf("link %+v", l)
	}
	e.srv.Wait()
	e.srv.resolveAllCustomers(ctx)
	if f.seen("GET /api/v1/customers/" + other.UUID) {
		t.Fatal("the client's EmailZit was asked about another customer")
	}
	if got, _ := e.srv.linkFor(ctx, other); got.ID != "" {
		t.Fatal("another customer was given to the client's EmailZit")
	}
	if got, _ := e.srv.linkFor(ctx, client); got.ID != l.ID {
		t.Fatal("the client's own customer is not on its EmailZit")
	}
	// a link token whose link is gone gets nothing
	f.mu.Lock()
	dns := f.dnsTok
	f.mu.Unlock()
	if err := e.srv.saveEmailZitLinks(ctx, nil); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", e.admin.URL+"/api/v1/domains/client1.example.com", nil)
	req.Header.Set("Authorization", "Bearer "+dns)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatal("a pairing token without its link still works", resp.StatusCode)
	}
}
