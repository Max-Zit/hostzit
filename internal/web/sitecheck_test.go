package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/max-zit/hostzit/internal/store"
)

func TestSiteHealthy(t *testing.T) {
	var mode atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "shop.example.com" {
			http.Error(w, "wrong host "+r.Host, http.StatusBadRequest)
			return
		}
		switch mode.Load() {
		case 0:
			_, _ = w.Write([]byte("<h1>Shop</h1>"))
		case 1:
			http.Redirect(w, r, "https://www.shop.example.com/", http.StatusMovedPermanently)
		case 2:
			http.Error(w, "boom", http.StatusInternalServerError)
		case 3:
			_, _ = w.Write([]byte("<p>There has been a critical error on this website.</p>"))
		}
	}))
	defer srv.Close()
	old := siteProbes
	siteProbes = []string{"https://127.0.0.1:1", srv.URL} // the first answers nothing
	t.Cleanup(func() { siteProbes = old })
	s := &Server{}
	for m, want := range []bool{true, true, false, false} {
		mode.Store(int32(m))
		if got := s.siteHealthy(context.Background(), "shop.example.com"); got != want {
			t.Errorf("mode %d: healthy %v, want %v", m, got, want)
		}
	}
	siteProbes = []string{"http://127.0.0.1:1"}
	if s.siteHealthy(context.Background(), "shop.example.com") {
		t.Error("an unreachable site counts as healthy")
	}
}

// An update that breaks a working site is undone with the snapshot.
func TestWPUpdateRollback(t *testing.T) {
	var broken atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if broken.Load() {
			_, _ = w.Write([]byte("There has been a critical error on this website."))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	old := siteProbes
	siteProbes = []string{srv.URL}
	t.Cleanup(func() { siteProbes = old })

	e := newEnv(t)
	a := e.setupAdmin()
	ctx := context.Background()
	a.ok("/settings/hosting", url.Values{"mode": {"shared"}, "server_name": {"host1.hostzit.test"}, "ipv4": {"192.0.2.10"}, "nameservers": {"ns1.hostzit.test\nns2.hostzit.test"},
		"default_php": {"8.4"}, "grace_days": {"14"}, "spf": {"v=spf1 a mx ~all"}})
	a.ok("/packages/new", url.Values{"name": {"P"}, "slug": {"p"}, "max_sites": {"3"}, "max_dbs": {"3"}, "max_zones": {"3"}, "disk_mb": {"1000"}, "inodes": {"0"},
		"cpu_percent": {"100"}, "memory_mb": {"512"}, "processes": {"50"}, "io_weight": {"100"}, "php_workers": {"2"}, "php_memory_mb": {"128"}, "upload_mb": {"16"}})
	a.ok("/customers/new", url.Values{"username": {"shop"}, "package": {"1"}, "domain": {"shop.example.com"}, "password": {"shop password 123"}})
	c, err := e.st.CustomerByRef(ctx, "shop")
	if err != nil {
		t.Fatal(err)
	}
	sites, _ := e.st.Sites(ctx, c.ID)
	in := &store.WPInstall{SiteID: sites[0].ID, Path: "sites/shop.example.com/public", DBName: "shop_wp", AdminUser: "admin", Version: "6.8"}
	if err := e.st.AddWPInstall(ctx, in); err != nil {
		t.Fatal(err)
	}
	in, _ = e.st.WPInstallByID(ctx, in.ID)

	// a healthy update: no restore
	if err := e.srv.updateWP(ctx, "test", c, in, false); err != nil && strings.Contains(err.Error(), "restored") {
		t.Fatal(err)
	}
	if e.hp.called("wp.restore") {
		t.Fatal("restored after a good update")
	}
	// the update breaks the site: the snapshot from before comes back
	e.srv.wpAfterUpdate = func() { broken.Store(true) }
	err = e.srv.updateWP(ctx, "test", c, in, false)
	if err == nil || !strings.Contains(err.Error(), "snapshot from before was restored") {
		t.Fatalf("broken update: %v", err)
	}
	if !e.hp.called("wp.restore") {
		t.Fatal("not restored")
	}
	// a site that was already broken is not rolled back by an update
	e.hp.mu.Lock()
	e.hp.calls = nil
	e.hp.mu.Unlock()
	e.srv.wpAfterUpdate = nil
	_ = e.srv.updateWP(ctx, "test", c, in, false)
	if e.hp.called("wp.restore") {
		t.Fatal("rolled back a site that was broken before")
	}
}
