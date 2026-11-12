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
	"net/url"
	"slices"
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
