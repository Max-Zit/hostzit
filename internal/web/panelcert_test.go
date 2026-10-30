package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/max-zit/hostzit/internal/tlsutil"
)

func TestPanelCertificate(t *testing.T) {
	if n := panelNames(HostingSettings{ServerName: "Host1.Example.com.", PanelURL: "https://panel.example.com:8443"}); !slices.Equal(n, []string{"host1.example.com", "panel.example.com"}) {
		t.Fatalf("names %v", n)
	}
	if n := panelNames(HostingSettings{PanelURL: "https://192.0.2.10:8443"}); len(n) != 0 {
		t.Fatalf("an IP address got a name: %v", n)
	}
	sc, err := tlsutil.LoadOrCreate(t.TempDir(), "panel", "HostZit panel", 1)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"host1.example.com"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	ca := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k, Leaf: leaf}
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{}
	cfg := s.PanelTLS(sc)
	got, _ := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "host1.example.com"})
	if got.Leaf != nil && slices.Contains(got.Leaf.DNSNames, "host1.example.com") {
		t.Fatal("CA certificate used before one exists")
	}
	s.panelCert.Store(&ca)
	if got, _ := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "host1.example.com"}); got != &ca {
		t.Fatal("the panel certificate is not used for its name")
	}
	if got, _ := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example.com"}); got == &ca {
		t.Fatal("the panel certificate is used for another name")
	}
	if got, _ := cfg.GetCertificate(&tls.ClientHelloInfo{}); got == &ca {
		t.Fatal("the panel certificate is used without a name (IP address)")
	}
}
