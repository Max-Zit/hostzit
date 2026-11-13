package helper

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// pdnsStub answers the zone list and records NOTIFY requests.
func pdnsStub(t *testing.T, h *Helper, root string, zones []pdnsZone) (notified func() []string) {
	t.Helper()
	var mu sync.Mutex
	var notes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			_ = json.NewEncoder(w).Encode(zones)
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/notify"):
			notes = append(notes, strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/zones/"), "./notify"))
			w.WriteHeader(200)
		default:
			w.WriteHeader(204)
		}
	}))
	t.Cleanup(srv.Close)
	h.PDNS = PDNS{URL: srv.URL, KeyFile: "/etc/hostzit/pdns-api.key"}
	_ = os.MkdirAll(filepath.Join(root, "etc/hostzit"), 0o700)
	_ = os.WriteFile(filepath.Join(root, "etc/hostzit/pdns-api.key"), []byte("k\n"), 0o600)
	return func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), notes...) }
}

// Found on h1 (0.9.4): a zone signed with NSEC3 narrow is never transferred
// to the DNS-only servers, and switching DNSSEC on did not raise the serial.
func TestDNSSECPlainNSEC3AndNotify(t *testing.T) {
	h, fr, root, _ := newTest(t)
	notified := pdnsStub(t, h, root, nil)
	if r := call(t, h, "dns.dnssec", dnssecArgs{Zone: "Shop.Example.com", On: true}); !r.OK {
		t.Fatal(r.Error)
	}
	if !fr.has("pdnsutil set-nsec3 shop.example.com 1 0 0 -") || fr.has("narrow") {
		t.Fatalf("NSEC3 not plain: %v", fr.calls)
	}
	if !fr.has("pdnsutil increase-serial shop.example.com") {
		t.Fatalf("serial not raised: %v", fr.calls)
	}
	if n := notified(); len(n) != 1 || n[0] != "shop.example.com" {
		t.Fatalf("NOTIFY: %v", n)
	}
	fr.calls = nil
	if r := call(t, h, "dns.dnssec", dnssecArgs{Zone: "shop.example.com", On: false}); !r.OK {
		t.Fatal(r.Error)
	}
	if !fr.has("pdnsutil increase-serial shop.example.com") || len(notified()) != 2 {
		t.Fatalf("switching off must also reach the secondaries: %v %v", fr.calls, notified())
	}
}

func TestDNSSECNarrowZonesMoved(t *testing.T) {
	h, fr, root, _ := newTest(t)
	notified := pdnsStub(t, h, root, []pdnsZone{
		{Name: "old.test.", DNSSEC: true}, {Name: "new.test.", DNSSEC: true}, {Name: "plain.test.", DNSSEC: false},
	})
	fr.out = map[string]string{
		"get-meta old.test NSEC3NARROW": "Metadata for 'old.test'\nNSEC3NARROW = 1\n",
		"get-meta new.test NSEC3NARROW": "Metadata for 'new.test'\nNSEC3NARROW = \n",
	}
	h.dnssecNoNarrow(t.Context())
	if !fr.has("pdnsutil set-nsec3 old.test 1 0 0 -") || !fr.has("increase-serial old.test") {
		t.Fatalf("narrow zone not moved: %v", fr.calls)
	}
	if fr.has("set-nsec3 new.test") || fr.has("plain.test NSEC3") || fr.has("set-nsec3 plain.test") {
		t.Fatalf("zones without narrow touched: %v", fr.calls)
	}
	if n := notified(); len(n) != 1 || n[0] != "old.test" {
		t.Fatalf("NOTIFY: %v", n)
	}
}

// Found on h1 (0.9.4): PowerDNS also notified the NS records' IPv6
// addresses, the DNS-only servers asked for the zone over IPv6 and were
// refused (only their IPv4 addresses were entered). Only the entered
// secondaries are notified now, also after an update of an old config.
func TestSecondariesOnlyNotifyEntered(t *testing.T) {
	h, fr, root, _ := newTest(t)
	if r := call(t, h, "dns.secondaries", secondariesArgs{IPs: []string{"192.0.2.53"}}); !r.OK {
		t.Fatal(r.Error)
	}
	b, _ := os.ReadFile(filepath.Join(root, filepath.FromSlash(secondaryConf)))
	if !strings.Contains(string(b), "\nalso-notify=192.0.2.53\nonly-notify=\n") || !strings.Contains(string(b), "allow-axfr-ips=192.0.2.53") {
		t.Fatalf("config:\n%s", b)
	}
	old := "# HostZit (generated, do not edit)\n# catalog=\nprimary=yes\nallow-axfr-ips=192.0.2.53\nalso-notify=192.0.2.53\n"
	_ = os.WriteFile(filepath.Join(root, filepath.FromSlash(secondaryConf)), []byte(old), 0o644)
	fr.calls = nil
	h.secondaryConfUpgrade(t.Context())
	b, _ = os.ReadFile(filepath.Join(root, filepath.FromSlash(secondaryConf)))
	if !strings.HasSuffix(string(b), "also-notify=192.0.2.53\nonly-notify=\n") || !fr.has("restart pdns") {
		t.Fatalf("upgrade:\n%s\n%v", b, fr.calls)
	}
	fr.calls = nil
	h.secondaryConfUpgrade(t.Context())
	if fr.has("restart pdns") {
		t.Fatal("a second run must not restart PowerDNS again")
	}
}
