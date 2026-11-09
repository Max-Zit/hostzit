package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestServersOverview(t *testing.T) {
	var calls atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer hzt_other_token" || r.URL.Path != "/api/v1/server/status" {
			http.Error(w, `{"error":{"message":"unauthorized"}}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"0.9.2","customers":{"active":12,"suspended":1},"load":"0.42 0.30 0.20",
			"memory":{"total_mb":4000,"available_mb":1000},"disks":[{"mount":"/","size_mb":100000,"used_mb":93000}],
			"services":{"nginx":"active","pdns":"failed"}}`))
	}))
	defer other.Close()
	sum := sha256.Sum256(other.Certificate().Raw)
	fp := hex.EncodeToString(sum[:])

	e := newEnv(t)
	a := e.setupAdmin()
	a.ok("/settings/hosting", url.Values{"mode": {"shared"}, "server_name": {"host1.hostzit.test"}, "ipv4": {"192.0.2.10"}, "nameservers": {"ns1.hostzit.test\nns2.hostzit.test"},
		"default_php": {"8.4"}, "grace_days": {"14"}, "spf": {"v=spf1 a mx ~all"}})
	if pg := a.page("/servers"); !strings.Contains(pg, "host1.hostzit.test") || !strings.Contains(pg, "this server") {
		t.Fatal("this server is not listed")
	}
	// a wrong token format is refused before anything is sent
	if st, _, _ := a.post("/servers", url.Values{"url": {other.URL}, "token": {"secret"}}); st != http.StatusSeeOther || calls.Load() != 0 {
		t.Fatalf("bad token: %d, %d calls", st, calls.Load())
	}
	// self-signed: first the fingerprint is shown, the token is not sent
	st, body, _ := a.post("/servers", url.Values{"name": {"host2"}, "url": {other.URL}, "token": {"hzt_other_token"}})
	if st != http.StatusOK || !strings.Contains(body, fp) || calls.Load() != 0 {
		t.Fatalf("confirm step: %d, fingerprint shown %v, %d calls", st, strings.Contains(body, fp), calls.Load())
	}
	if strings.Contains(body, "hzt_other_token") {
		t.Fatal("the token is echoed in the page")
	}
	// a wrong fingerprint does not trust it either
	if st, body, _ := a.post("/servers", url.Values{"name": {"host2"}, "url": {other.URL}, "token": {"hzt_other_token"}, "fingerprint": {strings.Repeat("0", 64)}}); st != http.StatusOK || !strings.Contains(body, fp) {
		t.Fatalf("wrong fingerprint: %d", st)
	}
	// confirmed: added, pinned
	a.ok("/servers", url.Values{"name": {"host2"}, "url": {other.URL}, "token": {"hzt_other_token"}, "fingerprint": {fp}})
	l := e.srv.remoteServers(context.Background())
	if len(l) != 1 || l[0].Fingerprint != fp || l[0].Token == "hzt_other_token" {
		t.Fatalf("stored %+v", l)
	}
	pg := a.page("/servers")
	for _, want := range []string{"host2", "0.9.2", ">12 <small", "+1", "75 %", "93 %", "services stopped", "pdns"} {
		if !strings.Contains(pg, want) {
			t.Errorf("overview lacks %q", want)
		}
	}
	// the same server twice is refused
	if st, _, _ := a.post("/servers", url.Values{"url": {other.URL}, "token": {"hzt_other_token"}, "fingerprint": {fp}}); st != http.StatusSeeOther || len(e.srv.remoteServers(context.Background())) != 1 {
		t.Fatal("added twice")
	}
	// unreachable servers are shown as such, the page still loads
	other.Close()
	if pg := a.page("/servers"); !strings.Contains(pg, "not reachable") {
		t.Error("an unreachable server is not marked")
	}
	a.ok("/servers/1/delete", url.Values{})
	if len(e.srv.remoteServers(context.Background())) != 0 {
		t.Fatal("not removed")
	}
}
