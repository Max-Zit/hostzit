package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// After a cPanel import the mail goes to EmailZit: the customer is made
// there with the same id, then the archive is sent to its import API.
func TestCPanelMailToEmailZit(t *testing.T) {
	var mu sync.Mutex
	var created map[string]string
	var imported string
	exists := false
	f := newFakeEZ(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/customers":
			if exists {
				http.Error(w, `{"error":"conflict"}`, http.StatusConflict)
				return
			}
			_ = json.NewDecoder(r.Body).Decode(&created)
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/import"):
			b, _ := io.ReadAll(r.Body)
			imported = r.URL.Path + "?" + r.URL.RawQuery + " " + string(b)
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"job_id":"job-7"}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	})

	e := newEnv(t)
	a := e.setupAdmin()
	ctx := context.Background()
	a.ok("/settings/hosting", url.Values{"mode": {"shared"}, "server_name": {"host1.hostzit.test"}, "ipv4": {"192.0.2.10"}, "nameservers": {"ns1.hostzit.test\nns2.hostzit.test"},
		"default_php": {"8.4"}, "grace_days": {"14"}, "spf": {"v=spf1 a mx ~all"}})
	a.ok("/packages/new", url.Values{"name": {"P"}, "slug": {"p"}, "max_sites": {"3"}, "max_dbs": {"3"}, "max_zones": {"3"}, "disk_mb": {"1000"}, "inodes": {"0"},
		"cpu_percent": {"100"}, "memory_mb": {"512"}, "processes": {"50"}, "io_weight": {"100"}, "php_workers": {"2"}, "php_memory_mb": {"128"}, "upload_mb": {"16"}})
	a.ok("/customers/new", url.Values{"username": {"shop"}, "package": {"1"}, "domain": {"shop.example.com"}, "password": {"shop password 123"}, "email": {"s@example.com"}})
	c, _ := e.st.CustomerByRef(ctx, "shop")
	dir := filepath.Join(e.root, "var", "lib", "hostzit", "import")
	_ = os.MkdirAll(dir, 0o700)
	_ = os.WriteFile(filepath.Join(dir, "cpmove-shop.tar.gz"), []byte("cpanel archive"), 0o600)

	// no link: nothing to say
	if n := e.srv.importMailToEmailZit(ctx, "test", "cpmove-shop.tar.gz", c); n != "" {
		t.Fatalf("without EmailZit: %q", n)
	}
	// linked without an import package: the report says what to do
	pairEmailZit(t, a, f)
	if n := e.srv.importMailToEmailZit(ctx, "test", "cpmove-shop.tar.gz", c); !strings.Contains(n, "choose an EmailZit package") {
		t.Fatalf("without a package: %q", n)
	}
	if st, _, loc := a.post("/settings/emailzit", url.Values{"import_package": {"Bad Slug"}}); st != http.StatusSeeOther || loc != "/settings/emailzit" {
		t.Fatalf("bad slug: %d %s", st, loc)
	}
	a.ok("/settings/emailzit", url.Values{"import_package": {"mail-basic"}})
	n := e.srv.importMailToEmailZit(ctx, "test", "cpmove-shop.tar.gz", c)
	mu.Lock()
	if !strings.Contains(n, "job job-7") || created["id"] != c.UUID || created["username"] != "shop" || created["package"] != "mail-basic" ||
		imported != "/api/v1/customers/"+c.UUID+"/import?format=cpanel cpanel archive" {
		t.Errorf("note %q, created %v, imported %q", n, created, imported)
	}
	// the customer is already in EmailZit (an earlier import): the mail still goes
	exists, imported = true, ""
	mu.Unlock()
	if n := e.srv.importMailToEmailZit(ctx, "test", "cpmove-shop.tar.gz", c); !strings.Contains(n, "job job-7") {
		t.Errorf("existing customer: %q", n)
	}
	mu.Lock()
	if imported == "" {
		t.Error("not imported for an existing customer")
	}
	mu.Unlock()
}
