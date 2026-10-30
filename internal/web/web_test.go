package web

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/max-zit/hostzit/internal/helper"
	"github.com/max-zit/hostzit/internal/store"
	"github.com/max-zit/hostzit/internal/testdb"
)

func TestMain(m *testing.M) { os.Exit(testdb.Main(m)) }

// inProc runs the real helper against a fake system.
type inProc struct {
	h     *helper.Helper
	mu    sync.Mutex
	calls []string
}

func (p *inProc) CallAs(ctx context.Context, by, reqID, op string, args, result any) error {
	p.mu.Lock()
	b, _ := json.Marshal(args)
	p.calls = append(p.calls, op+" "+string(b))
	p.mu.Unlock()
	c := &helper.Client{Dial: func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go p.h.ServeConn(ctx, b)
		return a, nil
	}}
	return c.CallAs(ctx, by, reqID, op, args, result)
}

func (p *inProc) called(prefix string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func fakeSystem(t *testing.T) (*inProc, string) {
	root := t.TempDir()
	users := map[string]string{}
	var mu sync.Mutex
	run := func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		switch name {
		case "getent":
			if id, ok := users[args[0]+":"+args[1]]; ok {
				return []byte(args[1] + ":x:" + id + ":" + id + "::/:/bin/sh\n"), nil
			}
			return nil, errors.New("not found")
		case "useradd":
			users["passwd:"+args[len(args)-1]] = args[1]
		case "groupadd":
			users["group:"+args[len(args)-1]] = args[len(args)-2]
		case "systemd-run":
			account := ""
			for _, a := range args {
				if v, ok := strings.CutPrefix(a, "User="); ok {
					account = v
				}
			}
			home := filepath.Join(root, "home", account)
			_ = os.MkdirAll(home, 0o755)
			var out bytes.Buffer
			err := helper.RunWorker(home, bytes.NewReader(stdin), &out)
			return out.Bytes(), err
		case "mariadb":
			return []byte("1\n"), nil
		}
		return nil, nil
	}
	h := helper.New(&helper.OS{Root: root, Runner: run, Mounter: func(helper.MountReq) error { return nil }})
	h.WebGID = 990
	pdns := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusNotFound)
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(pdns.Close)
	h.PDNS = helper.PDNS{URL: pdns.URL, KeyFile: "/etc/hostzit/pdns-api.key"}
	_ = os.MkdirAll(filepath.Join(root, "etc/hostzit"), 0o700)
	_ = os.WriteFile(filepath.Join(root, "etc/hostzit/pdns-api.key"), []byte("k"), 0o600)
	for _, p := range []string{"usr/sbin/php-fpm8.4", "etc/resolv.conf"} {
		_ = os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755)
		_ = os.WriteFile(filepath.Join(root, p), []byte("x"), 0o644)
	}
	return &inProc{h: h}, root
}

type env struct {
	t     *testing.T
	st    *store.Store
	srv   *Server
	hp    *inProc
	root  string
	admin *httptest.Server
	panel *httptest.Server
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.UseSecretKey(bytes.Repeat([]byte{7}, 32)); err != nil {
		t.Fatal(err)
	}
	hp, root := fakeSystem(t)
	srv, err := New(ctx, st, hp, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	srv.DataDir = t.TempDir()
	srv.ACMEChallengeDir = t.TempDir()
	srv.DevNo2FA = true
	e := &env{t: t, st: st, srv: srv, hp: hp, root: root}
	e.admin = httptest.NewServer(srv.AdminHandler())
	e.panel = httptest.NewServer(srv.CustomerHandler())
	t.Cleanup(e.admin.Close)
	t.Cleanup(e.panel.Close)
	t.Cleanup(srv.Wait)
	return e
}

type client struct {
	t    *testing.T
	base string
	c    *http.Client
}

func (e *env) client(base string) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: e.t, base: base, c: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (c *client) get(path string) (int, string, string) {
	c.t.Helper()
	resp, err := c.c.Get(c.base + path)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header.Get("Location")
}

func (c *client) post(path string, form url.Values) (int, string, string) {
	c.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, c.base+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", c.base)
	resp, err := c.c.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header.Get("Location")
}

// page fetches a page and fails on template errors or a wrong status.
func (c *client) page(path string) string {
	c.t.Helper()
	st, body, loc := c.get(path)
	if st != http.StatusOK {
		c.t.Fatalf("GET %s: %d (location %q) %s", path, st, loc, firstLine(body))
	}
	return body
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	return s
}

func (c *client) ok(path string, form url.Values) string {
	c.t.Helper()
	st, body, loc := c.post(path, form)
	if st != http.StatusSeeOther && st != http.StatusOK {
		c.t.Fatalf("POST %s: %d %s", path, st, body)
	}
	if loc != "" {
		_, flash, _ := c.get(loc)
		for _, m := range regexp.MustCompile(`(?s)class="flash err" role="alert">.*?<span>(.*?)</span>`).FindAllStringSubmatch(flash, -1) {
			if !strings.Contains(m[1], "Development mode") {
				c.t.Fatalf("POST %s: error shown: %s", path, m[1])
			}
		}
		return loc
	}
	return body
}

func (e *env) setupAdmin() *client {
	a := e.client(e.admin.URL)
	st, _, loc := a.get("/")
	if st != http.StatusSeeOther || loc != "/setup" {
		e.t.Fatalf("fresh server: %d %s", st, loc)
	}
	a.page("/setup")
	a.ok("/setup", url.Values{"username": {"root1"}, "password": {"correct horse battery"}, "password2": {"correct horse battery"}})
	a.ok("/login", url.Values{"username": {"root1"}, "password": {"correct horse battery"}})
	return a
}

func TestPanels(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin()
	a.ok("/settings/hosting", url.Values{"mode": {"shared"}, "server_name": {"host1.hostzit.test"}, "ipv4": {"192.0.2.10"}, "nameservers": {"ns1.hostzit.test\nns2.hostzit.test"},
		"default_php": {"8.4"}, "grace_days": {"14"}, "spf": {"v=spf1 a mx ~all"}})
	a.ok("/packages/new", url.Values{"name": {"WordPress Basic"}, "slug": {"wp-basic"}, "max_sites": {"3"}, "max_dbs": {"3"}, "max_zones": {"3"}, "disk_mb": {"5000"}, "inodes": {"100000"},
		"cpu_percent": {"100"}, "memory_mb": {"1024"}, "processes": {"80"}, "io_weight": {"100"}, "php_workers": {"6"}, "php_memory_mb": {"256"}, "upload_mb": {"64"}, "mail_per_hour": {"100"}})
	loc := a.ok("/customers/new", url.Values{"username": {"shop"}, "package": {"1"}, "domain": {"shop.example.com"}, "dns": {"on"}, "password": {"shop password 123"}, "email": {"s@example.com"}})
	if !strings.HasPrefix(loc, "/customers/") {
		t.Fatal(loc)
	}
	if !e.hp.called("account.apply") || !e.hp.called("site.apply") || !e.hp.called("dns.apply") {
		t.Fatal(e.hp.calls)
	}
	for _, p := range []string{"/", "/customers", loc, "/packages", "/packages/1", "/packages/new", "/sites", "/dns", "/jobs", "/server", "/settings/hosting", "/settings/network",
		"/settings/security", "/users", "/audit", "/account", "/docs", "/docs/sites", "/customers/new"} {
		a.page(p)
	}
	// the zone got the default records
	z, err := e.st.ZoneByName(context.Background(), "shop.example.com")
	if err != nil || z.Records < 4 {
		t.Fatal(z, err)
	}

	// the customer panel
	c := e.client(e.panel.URL)
	if st, _, _ := c.post("/login", url.Values{"username": {"root1"}, "password": {"correct horse battery"}}); st == http.StatusSeeOther {
		t.Fatal("an administrator signed in to the customer panel")
	}
	c.ok("/login", url.Values{"username": {"shop"}, "password": {"shop password 123"}})
	home := c.page("/")
	if !strings.Contains(home, "shop.example.com") {
		t.Fatal("home without the site")
	}
	sites, _ := e.st.Sites(context.Background(), 0)
	sid := "/sites/" + itoa(sites[0].ID)
	zid := "/dns/" + itoa(z.ID)
	for _, p := range []string{"/sites", sid, "/sites/new", sid + "/logs", "/dns", zid, "/databases", "/files", "/files?path=sites", "/access", "/usage", "/account", "/account/2fa", "/docs",
		"/files/edit?path=sites/shop.example.com/public/index.html"} {
		c.page(p)
	}
	// page cache on, then cleared
	c.ok(sid, url.Values{"php": {"8.4"}, "doc_root": {"sites/shop.example.com/public"}, "cache": {"on"}, "cache_minutes": {"30"}, "www": {"on"}, "canonical": {"bare"},
		"wordpress": {"on"}, "upload_mb": {"64"}, "redirects": {"/old /new 301"}, "auto_tls": {"on"}})
	conf, err := os.ReadFile(filepath.Join(e.root, "etc/nginx/zit.d/hostzit/sites/shop", itoa(sites[0].ID)+".conf"))
	if err != nil || !strings.Contains(string(conf), "fastcgi_cache hz") || !strings.Contains(string(conf), "location = /old") {
		t.Fatalf("nginx config: %v\n%s", err, conf)
	}
	c.ok(sid+"/cache/purge", url.Values{})
	if !e.hp.called("site.cache.purge") {
		t.Fatal("purge not called")
	}
	// DNS record, database, file
	c.ok(zid+"/records", url.Values{"name": {"mail"}, "type": {"A"}, "content": {"192.0.2.20"}, "ttl": {"3600"}})
	if st, body, _ := c.post(zid+"/records", url.Values{"name": {"x"}, "type": {"A"}, "content": {"not-an-ip"}, "ttl": {"3600"}}); st != http.StatusSeeOther || strings.Contains(body, "error") {
		t.Fatal(st)
	}
	body := c.ok("/databases", url.Values{"name": {"wp"}, "with_user": {"on"}})
	if !strings.Contains(body, "shop_wp") || !strings.Contains(body, `id="dbpw"`) {
		t.Fatal("database page without the new password")
	}
	c.ok("/files", url.Values{"dir": {"sites/shop.example.com/public"}, "action": {"newfile"}, "name": {"hello.txt"}})
	c.ok("/files/edit", url.Values{"path": {"sites/shop.example.com/public/hello.txt"}, "text": {"hi there"}})
	if b, _ := os.ReadFile(filepath.Join(e.root, "home/shop/sites/shop.example.com/public/hello.txt")); string(b) != "hi there" {
		t.Fatalf("file %q", b)
	}
	if st, _, _ := c.get("/files?path=../../etc"); st != http.StatusOK {
		t.Fatal(st)
	}

	// scheduled job: the command lands in the account's script, not in the unit
	c.page("/cron")
	c.ok("/cron", url.Values{"schedule": {"*/10 * * * *"}, "command": {"php -r 'echo 1;' ; echo $HOME"}, "note": {"test"}})
	jobs, _ := e.st.CronJobs(context.Background(), sites[0].CustomerID)
	if len(jobs) != 1 {
		t.Fatal("job not stored")
	}
	unit, err := os.ReadFile(filepath.Join(e.root, "etc/systemd/system", "hz-cron-shop-"+itoa(jobs[0].ID)+".service"))
	if err != nil || strings.Contains(string(unit), "echo") || !strings.Contains(string(unit), "User=shop") {
		t.Fatalf("cron unit: %v\n%s", err, unit)
	}
	if b, _ := os.ReadFile(filepath.Join(e.root, "home/shop/.hz-cron", itoa(jobs[0].ID)+".sh")); !strings.Contains(string(b), "echo $HOME") {
		t.Fatalf("cron script %q", b)
	}
	if st, _, _ := c.post("/cron", url.Values{"schedule": {"* * * * *\nExecStart=/bin/sh"}, "command": {"x"}}); st != http.StatusSeeOther {
		t.Fatal(st)
	}
	if jobs, _ := e.st.CronJobs(context.Background(), sites[0].CustomerID); len(jobs) != 1 {
		t.Fatal("bad schedule stored")
	}
	// SSH key
	pub, _, _ := ed25519.GenerateKey(nil)
	sk, _ := ssh.NewPublicKey(pub)
	c.ok("/access/keys", url.Values{"name": {"laptop"}, "key": {strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sk))) + " me@laptop"}})
	if b, _ := os.ReadFile(filepath.Join(e.root, "home/shop/.ssh/authorized_keys")); !strings.Contains(string(b), "ssh-ed25519 ") {
		t.Fatalf("authorized_keys %q", b)
	}
	if st, _, loc := c.post("/access/keys", url.Values{"key": {`command="rm -rf /" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl x`}}); st != http.StatusSeeOther || loc != "/access" {
		t.Fatal("key with options accepted")
	}
	c.page("/access")

	// a second customer cannot see the first one's things
	a.ok("/customers/new", url.Values{"username": {"blog"}, "package": {"1"}, "password": {"blog password 123"}})
	b := e.client(e.panel.URL)
	b.ok("/login", url.Values{"username": {"blog"}, "password": {"blog password 123"}})
	for _, p := range []string{sid, zid, sid + "/logs"} {
		if st, _, _ := b.get(p); st != http.StatusNotFound {
			t.Fatalf("customer blog reached %s: %d", p, st)
		}
	}
	if st, _, _ := b.post(sid+"/cache/purge", url.Values{}); st != http.StatusNotFound {
		t.Fatalf("purge of a foreign site: %d", st)
	}
	if st, body, _ := b.post("/sites/new", url.Values{"domain": {"www.shop.example.com"}}); st != http.StatusBadRequest || !strings.Contains(body, "another account") {
		t.Fatalf("subdomain of a foreign zone: %d", st)
	}
	if st, _, _ := b.post("/databases/shop_wp/delete", url.Values{"confirm": {"shop_wp"}}); st != http.StatusNotFound {
		t.Fatalf("foreign database: %d", st)
	}
	// the customer's cookie means nothing in the admin panel
	for _, ck := range c.c.Jar.Cookies(mustURL(e.panel.URL)) {
		a2 := e.client(e.admin.URL)
		a2.c.Jar.SetCookies(mustURL(e.admin.URL), []*http.Cookie{{Name: "hzadmin", Value: ck.Value}})
		if st, _, loc := a2.get("/customers"); st != http.StatusSeeOther || !strings.HasPrefix(loc, "/login") {
			t.Fatalf("customer session in the admin panel: %d", st)
		}
	}
	// cross-site POST refused
	req, _ := http.NewRequest(http.MethodPost, e.panel.URL+sid+"/cache/purge", nil)
	req.Header.Set("Origin", "https://evil.example")
	if resp, err := c.c.Do(req); err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatal("cross-site POST accepted")
	}

	// suspension: the customer is signed out and cannot sign in
	a.ok(loc+"/status", url.Values{"status": {"suspended"}, "reason": {"test"}})
	if st, _, _ := c.get("/"); st != http.StatusSeeOther {
		t.Fatalf("suspended customer still signed in: %d", st)
	}
	if st, _, _ := c.post("/login", url.Values{"username": {"shop"}, "password": {"shop password 123"}}); st == http.StatusSeeOther {
		t.Fatal("suspended customer signed in")
	}
	conf, _ = os.ReadFile(filepath.Join(e.root, "etc/nginx/zit.d/hostzit/sites/shop", itoa(sites[0].ID)+".conf"))
	if strings.Contains(string(conf), "fastcgi_pass") {
		t.Fatalf("suspended site still runs PHP:\n%s\n%v", conf, e.hp.calls[len(e.hp.calls)-3:])
	}
	a.ok(loc+"/status", url.Values{"status": {"active"}})
	// "log in as"
	st, _, sso := a.post(loc+"/login", url.Values{})
	if st != http.StatusSeeOther || !strings.Contains(sso, "/sso/") {
		t.Fatal(st, sso)
	}
	u, _ := url.Parse(sso)
	d := e.client(e.panel.URL)
	if st, _, _ := d.get(u.Path); st != http.StatusSeeOther {
		t.Fatal("sso link refused")
	}
	if !strings.Contains(d.page("/"), "as administrator root1") {
		t.Fatal("no banner for the administrator")
	}
	if st, _, l := e.client(e.panel.URL).get(u.Path); st != http.StatusSeeOther || !strings.HasPrefix(l, "/login") {
		t.Fatal("sso link used twice")
	}
	// delete
	a.ok(loc+"/delete", url.Values{"confirm": {"shop"}})
	if !e.hp.called("account.delete") {
		t.Fatal("account not deleted")
	}
	if _, err := os.Stat(filepath.Join(e.root, "home/shop")); !os.IsNotExist(err) {
		t.Fatal("home left behind")
	}
}

func mustURL(s string) *url.URL { u, _ := url.Parse(s); return u }

func itoa(n int64) string {
	return strings.TrimSpace(strings.Replace(time.Duration(n).String(), "ns", "", 1))
}

func TestAPI(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin()
	a.ok("/settings/hosting", url.Values{"mode": {"shared"}, "ipv4": {"192.0.2.10"}, "nameservers": {"ns1.hostzit.test"}, "default_php": {"8.4"}, "grace_days": {"0"}, "panel_url": {"https://panel.hostzit.test:8443"}})
	a.ok("/packages/new", url.Values{"name": {"Pro"}, "slug": {"pro"}, "max_sites": {"5"}, "max_dbs": {"5"}, "max_zones": {"5"}, "disk_mb": {"5000"}, "inodes": {"0"},
		"cpu_percent": {"200"}, "memory_mb": {"2048"}, "processes": {"100"}, "io_weight": {"100"}, "php_workers": {"8"}, "php_memory_mb": {"256"}, "upload_mb": {"128"}, "mail_per_hour": {"100"}})
	body := a.ok("/account/tokens", url.Values{"name": {"portal"}, "days": {"30"}, "scope_customers:read": {"1"}, "scope_customers:write": {"1"}, "scope_usage:read": {"1"}, "scope_sso:create": {"1"}})
	tok := regexp.MustCompile(`hzt_[A-Za-z0-9_-]+`).FindString(body)
	if tok == "" {
		t.Fatal("no token shown")
	}
	call := func(method, path string, in any, hdr ...string) (int, map[string]any) {
		var rd io.Reader
		if in != nil {
			b, _ := json.Marshal(in)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, e.admin.URL+path, rd)
		req.Header.Set("Authorization", "Bearer "+tok)
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	wait := func(job string) {
		for range 100 {
			_, j := call("GET", "/api/v1/jobs/"+job, nil)
			if j["status"] == "done" {
				return
			}
			if j["status"] == "failed" {
				t.Fatalf("job failed: %v", j["error"])
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("job did not finish")
	}
	in := map[string]any{"id": "0b8a9f0e-1c2d-4e5f-8a9b-0c1d2e3f4a5b", "external_id": "inv-77", "username": "acmeco", "package": "pro", "domain": "acme.example.org", "email": "a@acme.example.org", "password": "acme password 1234"}
	st, out := call("POST", "/api/v1/customers", in, "Idempotency-Key", "k1")
	if st != http.StatusAccepted || out["customer_id"] != in["id"] {
		t.Fatal(st, out)
	}
	wait(out["job_id"].(string))
	st2, out2 := call("POST", "/api/v1/customers", in, "Idempotency-Key", "k1")
	if st2 != http.StatusAccepted || out2["job_id"] != out["job_id"] {
		t.Fatal("idempotency key not honoured", out2)
	}
	if st, _ := call("POST", "/api/v1/customers", in); st != http.StatusConflict {
		t.Fatalf("duplicate without key: %d", st)
	}
	st, c := call("GET", "/api/v1/customers/ext:inv-77", nil)
	if st != 200 || c["username"] != "acmeco" || c["package"] != "pro" || c["ready"] != true {
		t.Fatal(st, c)
	}
	st, list := call("GET", "/api/v1/customers?limit=10", nil)
	if st != 200 || len(list["items"].([]any)) != 1 {
		t.Fatal(list)
	}
	st, out = call("POST", "/api/v1/customers/acmeco/suspend", map[string]string{"reason": "billing"})
	if st != http.StatusAccepted {
		t.Fatal(st, out)
	}
	wait(out["job_id"].(string))
	if _, c = call("GET", "/api/v1/customers/"+in["id"].(string), nil); c["status"] != "suspended" {
		t.Fatal(c)
	}
	if st, _ := call("POST", "/api/v1/customers/acmeco/sso", nil); st != http.StatusConflict {
		t.Fatal("sso for a suspended customer")
	}
	_, out = call("POST", "/api/v1/customers/acmeco/unsuspend", nil)
	wait(out["job_id"].(string))
	st, sso := call("POST", "/api/v1/customers/acmeco/sso", nil)
	if st != http.StatusCreated || !strings.HasPrefix(sso["url"].(string), "https://panel.hostzit.test:8443/sso/") {
		t.Fatal(st, sso)
	}
	if st, u := call("GET", "/api/v1/customers/acmeco/usage", nil); st != 200 || u["sites"].(float64) != 1 {
		t.Fatal(st, u)
	}
	// the token may not use DNS for EmailZit (scope not given)
	if st, _ := call("GET", "/api/v1/domains/acme.example.org", nil); st != http.StatusForbidden {
		t.Fatalf("scope ignored: %d", st)
	}
	// bad token, unknown package, bad username
	req, _ := http.NewRequest("GET", e.admin.URL+"/api/v1/customers", nil)
	req.Header.Set("Authorization", "Bearer hzt_nope")
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != http.StatusUnauthorized {
		t.Fatal("bad token accepted")
	}
	if st, out := call("POST", "/api/v1/customers", map[string]any{"username": "x2y", "package": "nope", "password": "long password 123"}); st != 400 || !strings.Contains(toJSON(out), "package") {
		t.Fatal(st, out)
	}
	if st, _ := call("POST", "/api/v1/customers", map[string]any{"username": "Bad;Name", "package": "pro", "password": "long password 123"}); st != 400 {
		t.Fatal(st)
	}
	_, out = call("POST", "/api/v1/customers/acmeco/terminate", nil)
	wait(out["job_id"].(string))
	if _, c = call("GET", "/api/v1/customers/acmeco", nil); c["status"] != "terminated" {
		t.Fatal(c)
	}
	e.srv.purgeTerminated(context.Background())
	if st, _ := call("GET", "/api/v1/customers/acmeco", nil); st != http.StatusNotFound {
		t.Fatal("terminated customer not deleted after the grace period")
	}
}

func toJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
