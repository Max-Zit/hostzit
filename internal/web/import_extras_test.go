package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/max-zit/hostzit/internal/store"
)

// From the first real cPanel import (0.9.3): PHP version and the www name
// of a parked domain come from userdata.
func TestCPanelUserdataDomain(t *testing.T) {
	m := &cpMeta{Main: "sportiko.mycpanel.rs", Parked: []string{"sportikopancevo.rs", "other.rs"}, DocRoots: map[string]string{}, PHP: map[string]string{}, Aliases: map[string][]string{}}
	parseUserdataDomain("---\ndocumentroot: /home/sportiko/public_html\nphpversion: ea-php81\nserveralias: mail.sportiko.mycpanel.rs mail.sportikopancevo.rs sportikopancevo.rs www.sportiko.mycpanel.rs www.sportikopancevo.rs\n", m.Main, m)
	if m.DocRoots[m.Main] != "/home/sportiko/public_html" || m.PHP[m.Main] != "8.1" {
		t.Fatalf("meta %+v", m)
	}
	got := parkedAliases(m)
	if !slices.Equal(got, []string{"sportikopancevo.rs", "www.sportikopancevo.rs", "other.rs"}) {
		t.Fatalf("aliases %v", got)
	}
}

func selfSigned(t *testing.T, names []string, notAfter time.Time) []byte {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(k)
	// cPanel's apache_tls file: key first, then the chain
	return append(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
}

func TestSplitCertPEM(t *testing.T) {
	chain, key, leaf := splitCertPEM(selfSigned(t, []string{"www.example.rs", "example.rs"}, time.Now().Add(90*24*time.Hour)))
	if leaf == nil || leaf.VerifyHostname("example.rs") != nil || !strings.Contains(key, "EC PRIVATE KEY") || strings.Contains(chain, "PRIVATE") || !strings.Contains(chain, "CERTIFICATE") {
		t.Fatalf("chain %q key %q leaf %v", chain, key, leaf)
	}
	if _, _, leaf := splitCertPEM([]byte("nothing")); leaf != nil {
		t.Fatal("leaf from garbage")
	}
}

// A valid certificate must stay "ok" (and in nginx) while a renewal or a
// first free certificate for an imported site fails; such sites are tried
// again after six hours, not every round.
func TestCertsDueKeepsValidAndBacksOff(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin()
	ctx := context.Background()
	a.ok("/settings/hosting", url.Values{"mode": {"shared"}, "server_name": {"host1.hostzit.test"}, "ipv4": {"192.0.2.10"}, "nameservers": {"ns1.hostzit.test\nns2.hostzit.test"},
		"default_php": {"8.4"}, "grace_days": {"14"}, "spf": {"v=spf1 a mx ~all"}})
	a.ok("/packages/new", url.Values{"name": {"P"}, "slug": {"p"}, "max_sites": {"3"}, "max_dbs": {"3"}, "max_zones": {"3"}, "disk_mb": {"1000"}, "inodes": {"0"},
		"cpu_percent": {"100"}, "memory_mb": {"512"}, "processes": {"50"}, "io_weight": {"100"}, "php_workers": {"2"}, "php_memory_mb": {"128"}, "upload_mb": {"16"}})
	a.ok("/customers/new", url.Values{"username": {"shop"}, "package": {"1"}, "domain": {"shop.example.com"}, "password": {"shop password 123"}, "email": {"s@example.com"}})
	c, _ := e.st.CustomerByRef(ctx, "shop")
	sites, _ := e.st.Sites(ctx, c.ID)
	x := sites[0]
	na := time.Now().Add(80 * 24 * time.Hour)
	// a certificate for only some of the names, with a note: not due now
	_ = e.st.SetCert(ctx, x.ID, "ok", "not yet pointing to this server: www.shop.example.com", &na, []string{"shop.example.com"})
	if due(t, e.st, x.ID) {
		t.Fatal("site with a fresh note is due again at once")
	}
	// the same without a note (names changed by the customer): due
	_ = e.st.SetCertNote(ctx, x.ID, "")
	if !due(t, e.st, x.ID) {
		t.Fatal("site with missing names is not due")
	}
	x, _ = e.st.SiteByID(ctx, x.ID)
	if !hasValidCert(x, time.Now()) || hasValidCert(&store.Site{CertStatus: "failed", CertNotAfter: &na}, time.Now()) {
		t.Fatal("hasValidCert")
	}
	if !sameNames([]string{"b", "a"}, []string{"a", "b"}) || sameNames([]string{"a"}, []string{"a", "b"}) {
		t.Fatal("sameNames")
	}
}

func due(t *testing.T, st *store.Store, id int64) bool {
	t.Helper()
	l, err := st.CertsDue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return slices.ContainsFunc(l, func(s *store.Site) bool { return s.ID == id })
}

// Found on the first real import (0.9.3): an imported account must change
// its random password but the form asked for that password, which nobody
// knows, so a customer arriving by a one-time link was stuck. An
// administrator working in the customer panel is not sent there at all.
func TestForcedPasswordChangeWithoutCurrent(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin()
	ctx := context.Background()
	a.ok("/packages/new", url.Values{"name": {"P"}, "slug": {"p"}, "max_sites": {"1"}, "max_dbs": {"1"}, "max_zones": {"1"}, "disk_mb": {"100"}, "inodes": {"0"},
		"cpu_percent": {"0"}, "memory_mb": {"0"}, "processes": {"0"}, "io_weight": {"100"}, "php_workers": {"2"}, "php_memory_mb": {"128"}, "upload_mb": {"8"}, "mail_per_hour": {"0"}})
	a.ok("/customers/new", url.Values{"username": {"moved"}, "package": {"1"}, "password": {"unknown random 1"}})
	c, _ := e.st.CustomerByRef(ctx, "moved")
	_ = e.st.SetPassword(ctx, c.UserID, "unknown random 1", true, "")

	// the administrator's "log in as" is not forced to the password page
	tok, _, err := e.st.CreateSSOLink(ctx, c.UserID, "admin:admin")
	if err != nil {
		t.Fatal(err)
	}
	adm := e.client(e.panel.URL)
	adm.get("/sso/" + tok)
	if st, _, loc := adm.get("/"); st != http.StatusOK {
		t.Fatalf("acting admin sent to %d %s", st, loc)
	}
	if st, _, _ := adm.post("/account/password", url.Values{"password": {"chosen by admin 1"}, "password2": {"chosen by admin 1"}}); st != http.StatusForbidden {
		t.Fatalf("acting admin changed the customer's password: %d", st)
	}

	// the customer by a link from the billing system
	tok, _, _ = e.st.CreateSSOLink(ctx, c.UserID, "api")
	cu := e.client(e.panel.URL)
	cu.get("/sso/" + tok)
	if st, _, loc := cu.get("/"); st != http.StatusSeeOther || !strings.HasSuffix(loc, "/account") {
		t.Fatalf("not sent to the password page: %d %s", st, loc)
	}
	if _, body, _ := cu.get("/account"); strings.Contains(body, `name="current"`) && strings.Contains(body, "/account/password") && strings.Index(body, `name="current"`) < strings.Index(body, `name="password2"`) {
		t.Fatal("the forced change still asks for the current password")
	}
	cu.ok("/account/password", url.Values{"password": {"my own pass 123"}, "password2": {"my own pass 123"}})
	if _, err := e.st.CheckPassword(ctx, "moved", "my own pass 123"); err != nil {
		t.Fatal("new password not set:", err)
	}
	if st, _, _ := cu.get("/"); st != http.StatusOK {
		t.Fatalf("still forced after the change: %d", st)
	}
	// from now on the current password is needed again
	if st, _, _ := cu.post("/account/password", url.Values{"password": {"another pass 1234"}, "password2": {"another pass 1234"}}); st != http.StatusBadRequest {
		t.Fatalf("changed without the current password: %d", st)
	}
}

// Copying and unpacking a cPanel archive inside the account needs about
// twice its size; a package that is too small is refused before the account
// is made (the first real import on a 2 GB package failed after the copy).
func TestImportRefusesSmallPackage(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin()
	a.ok("/packages/new", url.Values{"name": {"Tiny"}, "slug": {"tiny"}, "max_sites": {"1"}, "max_dbs": {"1"}, "max_zones": {"1"}, "disk_mb": {"1"}, "inodes": {"0"},
		"cpu_percent": {"0"}, "memory_mb": {"0"}, "processes": {"0"}, "io_weight": {"100"}, "php_workers": {"2"}, "php_memory_mb": {"128"}, "upload_mb": {"8"}, "mail_per_hour": {"0"}})
	dir := filepath.Join(e.root, "var", "lib", "hostzit", "import")
	_ = os.MkdirAll(dir, 0o700)
	p := filepath.Join(dir, "backup-1.2.2026_3-4-5_shop.tar.gz")
	if err := os.WriteFile(p, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-5 * time.Minute)
	_ = os.Chtimes(p, old, old)
	st, _, loc := a.post("/import", url.Values{"file": {"backup-1.2.2026_3-4-5_shop.tar.gz"}, "username": {""}, "package": {"1"}})
	if st != http.StatusSeeOther || !strings.HasSuffix(loc, "/import") {
		t.Fatalf("%d %s", st, loc)
	}
	if body := a.page("/import"); !strings.Contains(body, "disk space is too small") {
		t.Fatal("no message about the package's disk space: ", regexp.MustCompile(`<span>[^<]{10,200}</span>`).FindAllString(body, 5))
	}
	if c, err := e.st.CustomerByRef(context.Background(), "shop"); err == nil {
		t.Fatalf("account %s made anyway", c.Username)
	}
}

// Found on h1 in Chrome (0.9.4): form-action 'self' also applies to the
// redirects after a form, so "Open the customer panel" (→ customer panel
// port) and the EmailZit sign-in (→ EmailZit's redirect URI) did nothing.
// form-action lists exactly those origins, nothing else.
func TestCSPFormActionAllowsPanelAndOIDC(t *testing.T) {
	e := newEnv(t)
	formAction := func(base string) string {
		resp, err := http.Get(base + "/login")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		for _, d := range strings.Split(resp.Header.Get("Content-Security-Policy"), ";") {
			if d = strings.TrimSpace(d); strings.HasPrefix(d, "form-action ") {
				return strings.TrimPrefix(d, "form-action ")
			}
		}
		t.Fatal("no form-action")
		return ""
	}
	// without a configured panel address: the customer panel on the same host
	got := formAction(e.admin.URL)
	if !strings.HasPrefix(got, "'self' http://127.0.0.1:") || strings.Count(got, " ") != 1 {
		t.Fatalf("admin form-action %q", got)
	}
	ctx := context.Background()
	h := e.srv.hostingSettings(ctx)
	h.PanelURL = "https://panel.example.com:8443"
	if h.DefaultPHP == "" {
		h.DefaultPHP = "8.4"
	}
	if err := e.st.SetSetting(ctx, settingHosting, h); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetSetting(ctx, settingOIDCClient, OIDCClient{ID: "emailzit", RedirectURI: "https://mail.example.com:8444/login/hostzit/callback?x=1"}); err != nil {
		t.Fatal(err)
	}
	e.srv.cspForget()
	got = formAction(e.panel.URL)
	if got != "'self' https://panel.example.com:8443 https://mail.example.com:8444" {
		t.Fatalf("form-action %q", got)
	}
	// a broken redirect address never reaches the header
	_ = e.st.SetSetting(ctx, settingOIDCClient, OIDCClient{ID: "emailzit", RedirectURI: "javascript:alert(1)"})
	e.srv.cspForget()
	if got = formAction(e.admin.URL); strings.Contains(got, "javascript") || strings.Contains(got, "mail.example.com") {
		t.Fatalf("form-action %q", got)
	}
}

// Found on h1: with restore points in a folder of the server, every
// customer's restore point page showed the error "choose SFTP or S3".
func TestRestorePointPageLocalNoError(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin()
	a.ok("/packages/new", url.Values{"name": {"P"}, "slug": {"p"}, "max_sites": {"1"}, "max_dbs": {"1"}, "max_zones": {"1"}, "disk_mb": {"100"}, "inodes": {"0"},
		"cpu_percent": {"0"}, "memory_mb": {"0"}, "processes": {"0"}, "io_weight": {"100"}, "php_workers": {"2"}, "php_memory_mb": {"128"}, "upload_mb": {"8"}, "mail_per_hour": {"0"}})
	a.ok("/customers/new", url.Values{"username": {"localrp"}, "package": {"1"}, "password": {"local restore 12"}})
	c, err := e.st.CustomerByRef(context.Background(), "localrp")
	if err != nil {
		t.Fatal(err)
	}
	page := a.page("/customers/" + strconv.FormatInt(c.ID, 10) + "/remote-backups")
	// (the tests run in development mode, whose banner is one more flash err)
	if strings.Contains(page, "choose SFTP or S3") || strings.Count(page, `class="flash err"`) > 1 {
		t.Fatalf("error on the restore point page:\n%s", page)
	}
}
