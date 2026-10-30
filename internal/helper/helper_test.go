package helper

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/max-zit/hostzit/internal/hosting"
)

type fakeRun struct {
	mu    sync.Mutex
	calls []string
	stdin []string
	// fail makes a command fail when its line contains the key
	fail map[string]bool
	// users known to getent
	users map[string]string
}

func (f *fakeRun) run(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, line)
	f.stdin = append(f.stdin, string(stdin))
	for k := range f.fail {
		if strings.Contains(line, k) {
			return nil, errors.New("failed: " + k)
		}
	}
	switch name {
	case "ip":
		if strings.Contains(line, "route show default") {
			return []byte(`[{"dst":"default","gateway":"192.168.1.1","dev":"eth0"}]`), nil
		}
	case "getent":
		if v, ok := f.users[args[0]+":"+args[1]]; ok {
			return []byte(v + "\n"), nil
		}
		if args[1] == "hostzit-web" {
			return []byte("hostzit-web:x:990:\n"), nil
		}
		return nil, errors.New("not found")
	case "useradd":
		f.users["passwd:"+args[len(args)-1]] = args[len(args)-1] + ":x:" + args[1] + ":" + args[3] + "::/home/x:/bin/bash"
	case "groupadd":
		f.users["group:"+args[len(args)-1]] = args[len(args)-1] + ":x:" + args[len(args)-2] + ":"
	case "systemd-run":
		// the worker: answer like RunWorker would
		var req WorkerReq
		if json.Unmarshal(stdin, &req) == nil {
			b, _ := json.Marshal(WorkerResp{OK: true, Count: 1})
			return b, nil
		}
	}
	return nil, nil
}

func (f *fakeRun) has(sub string) bool {
	for _, c := range f.calls {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func newTest(t *testing.T) (*Helper, *fakeRun, string, *[]MountReq) {
	t.Helper()
	root := t.TempDir()
	fr := &fakeRun{fail: map[string]bool{}, users: map[string]string{}}
	var mounts []MountReq
	var mu sync.Mutex
	o := &OS{Root: root, Runner: fr.run, Mounter: func(m MountReq) error { mu.Lock(); mounts = append(mounts, m); mu.Unlock(); return nil }}
	h := New(o)
	h.WebGID = 990
	for _, p := range []string{"/usr/sbin/php-fpm8.4", "/usr/bin/x", "/etc/resolv.conf", "/etc/hosts", "/etc/ssl/certs/x", "/etc/php/8.4/x", "/run/mysqld/x", "/dev/pts/x"} {
		full := filepath.Join(root, filepath.FromSlash(p))
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		_ = os.WriteFile(full, []byte("x"), 0o644)
	}
	return h, fr, root, &mounts
}

func call(t *testing.T, h *Helper, op string, args any) Response {
	t.Helper()
	raw, _ := json.Marshal(args)
	return h.Do(context.Background(), Request{Op: op, Args: raw})
}

func testAccount() hosting.Account {
	return hosting.Account{Name: "shop", Number: 5, PHPVersions: []string{"8.4"}, Limits: hosting.Limits{DiskMB: 1000, CPUPercent: 100, MemoryMB: 512, Processes: 50, PHPWorkers: 4, PHPMemoryMB: 128, UploadMB: 32}}
}

func read(t *testing.T, root, p string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(p)))
	if err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	return string(b)
}

func TestAccountApply(t *testing.T) {
	h, fr, root, mounts := newTest(t)
	if r := call(t, h, "account.apply", testAccount()); !r.OK {
		t.Fatal(r.Error)
	}
	for _, want := range []string{"groupadd -g 1000005 shop", "useradd -u 1000005 -g 1000005 -G hostzit-users,hostzit-sftponly", "-K SUB_UID_COUNT=0", "systemctl daemon-reload",
		"systemctl enable --now hz-cage-shop.service", "systemctl restart hz-php-shop-84.service"} {
		if !fr.has(want) {
			t.Errorf("missing call %q in %v", want, fr.calls)
		}
	}
	if !strings.Contains(read(t, root, "/etc/systemd/system/hz-shop.slice"), "MemoryMax=512M") {
		t.Fatal("slice")
	}
	if !strings.Contains(read(t, root, "/etc/systemd/system/user-1000005.slice.d/50-hostzit.conf"), "TasksMax=50") {
		t.Fatal("user slice")
	}
	if !strings.Contains(read(t, root, "/var/lib/hostzit/cages/shop/.hz/php-fpm-84.conf"), "pm.max_children = 4") {
		t.Fatal("fpm conf")
	}
	if p := read(t, root, "/var/lib/hostzit/cages/shop/etc/passwd"); strings.Contains(p, "other") || !strings.Contains(p, "shop:x:1000005") {
		t.Fatal(p)
	}
	if read(t, root, "/var/lib/hostzit/cages/shop/etc/resolv.conf") != "x" {
		t.Fatal("resolv.conf not copied")
	}
	var proc, home bool
	for _, m := range *mounts {
		if m.Proc {
			proc = true
		}
		if m.Source == "/home/shop" && strings.HasSuffix(m.Target, "/cages/shop/home/shop") && !m.ReadOnly {
			home = true
		}
		if m.Source == "/usr" && !m.ReadOnly {
			t.Fatal("/usr mounted writable")
		}
		if m.Source == "/home" {
			t.Fatal("all homes mounted")
		}
	}
	if !proc || !home {
		t.Fatalf("mounts %+v", *mounts)
	}
	// suspension stops PHP and locks the user
	a := testAccount()
	a.Suspended = true
	if r := call(t, h, "account.apply", a); !r.OK {
		t.Fatal(r.Error)
	}
	if !fr.has("usermod -L -e 1 shop") || !fr.has("systemctl disable --now hz-php-shop-84.service") {
		t.Fatal(fr.calls)
	}
}

// The helper can start before the package's setup creates the web group:
// the group is looked up later, and root is never used in its place.
func TestWebGroupLookedUpLate(t *testing.T) {
	h, fr, _, _ := newTest(t)
	h.WebGID = 0
	fr.fail["getent group hostzit-web"] = true
	if r := call(t, h, "account.apply", testAccount()); r.OK {
		t.Fatal("account applied without the web group")
	}
	delete(fr.fail, "getent group hostzit-web")
	if gid, err := h.webGID(context.Background()); err != nil || gid != 990 {
		t.Fatalf("web group: %d %v", gid, err)
	}
	if r := call(t, h, "account.apply", testAccount()); !r.OK {
		t.Fatalf("apply: %+v", r)
	}
}

func TestAccountApplyRefuses(t *testing.T) {
	h, fr, _, _ := newTest(t)
	fr.users["passwd:shop"] = "shop:x:1001:1001::/home/shop:/bin/bash"
	if r := call(t, h, "account.apply", testAccount()); r.OK || !strings.Contains(r.Error, "another id") {
		t.Fatalf("existing system user taken over: %+v", r)
	}
	a := testAccount()
	a.Name = "../etc"
	if r := call(t, h, "account.apply", a); r.OK {
		t.Fatal("bad name accepted")
	}
	a = testAccount()
	a.PHPVersions = []string{"7.4"}
	if r := call(t, h, "account.apply", a); r.OK {
		t.Fatal("missing PHP accepted")
	}
	if r := h.Do(context.Background(), Request{Op: "account.apply", Args: json.RawMessage(`{"name":"shop","number":5,"evil":1}`)}); r.OK {
		t.Fatal("unknown field accepted")
	}
	if r := h.Do(context.Background(), Request{Op: "shell", Args: json.RawMessage(`{}`)}); r.OK {
		t.Fatal("unknown op accepted")
	}
}

func TestWriteAllowList(t *testing.T) {
	o := &OS{Root: t.TempDir()}
	for _, p := range []string{"/etc/passwd", "/home/shop/x", "/etc/nginx/nginx.conf", "/var/lib/hostzit/../../etc/shadow", "/root/.ssh/authorized_keys"} {
		if err := o.WriteFile(p, []byte("x"), 0o644, 0, 0); err == nil {
			t.Errorf("wrote %s", p)
		}
	}
	if err := o.RemoveAll("/etc"); err == nil {
		t.Fatal("removed /etc")
	}
}

func TestSiteApplyRollsBack(t *testing.T) {
	h, fr, root, _ := newTest(t)
	if r := call(t, h, "account.apply", testAccount()); !r.OK {
		t.Fatal(r.Error)
	}
	s := hosting.Site{ID: 3, Account: "shop", Domain: "shop.test.com", DocRoot: "sites/shop.test.com/public", PHPVersion: "8.4", WordPress: true, UploadMB: 32, Cache: true, CacheMinutes: 30}
	if r := call(t, h, "site.apply", siteApplyArgs{Site: s}); !r.OK {
		t.Fatal(r.Error)
	}
	conf := read(t, root, "/etc/nginx/zit.d/hostzit/sites/shop/3.conf")
	if !strings.Contains(conf, "server_name shop.test.com;") || !strings.Contains(conf, "fastcgi_cache hz3;") {
		t.Fatal(conf)
	}
	if !strings.Contains(read(t, root, "/etc/nginx/zit.d/hostzit/cache/3.conf"), "keys_zone=hz3") {
		t.Fatal("cache zone")
	}
	if !fr.has("systemctl reload nginx") || !fr.has("files-worker") {
		t.Fatal(fr.calls)
	}
	// a configuration nginx refuses is rolled back
	fr.fail["nginx -t"] = true
	s.Cache = false
	if r := call(t, h, "site.apply", siteApplyArgs{Site: s}); r.OK || !strings.Contains(r.Error, "nothing was changed") {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(read(t, root, "/etc/nginx/zit.d/hostzit/sites/shop/3.conf"), "fastcgi_cache hz3;") {
		t.Fatal("old configuration not restored")
	}
	if _, err := os.Stat(filepath.Join(root, "etc/nginx/zit.d/hostzit/cache/3.conf")); err != nil {
		t.Fatal("cache zone not restored")
	}
	delete(fr.fail, "nginx -t")
	// clear cache
	_ = os.MkdirAll(filepath.Join(root, "var/cache/hostzit/pages/3/a/bc"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "var/cache/hostzit/pages/3/a/bc/x"), []byte("page"), 0o644)
	if r := call(t, h, "site.cache.purge", siteRef{Account: "shop", ID: 3}); !r.OK || !strings.Contains(string(r.Result), `"removed":1`) {
		t.Fatalf("%+v", r)
	}
	if _, err := os.Stat(filepath.Join(root, "var/cache/hostzit/pages/3/a")); !os.IsNotExist(err) {
		t.Fatal("cache not cleared")
	}
	if _, err := os.Stat(filepath.Join(root, "var/cache/hostzit/pages/3")); err != nil {
		t.Fatal("cache folder removed")
	}
}

func TestDBSQL(t *testing.T) {
	h, fr, _, _ := newTest(t)
	if r := call(t, h, "db.create", dbArgs{Account: "shop", Name: "shop_wp"}); !r.OK {
		t.Fatal(r.Error)
	}
	for _, bad := range []string{"other_wp", "shop_wp`; DROP DATABASE x; --", "shop_wp'", "shop_"} {
		if r := call(t, h, "db.create", dbArgs{Account: "shop", Name: bad}); r.OK {
			t.Errorf("%q accepted", bad)
		}
	}
	if r := call(t, h, "db.user", dbUserArgs{Account: "shop", User: "shop_wp", Password: "x'); DROP USER root; --aaaa", Databases: []string{"shop_wp"}}); !r.OK {
		t.Fatal(r.Error)
	}
	last := fr.calls[len(fr.calls)-1]
	if strings.Contains(last, "DROP USER root") || !strings.Contains(last, "IDENTIFIED BY PASSWORD '*") || !strings.Contains(last, "ON `shop\\_wp`.*") {
		t.Fatal(last)
	}
	if NativeHash("password") != "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19" {
		t.Fatal(NativeHash("password"))
	}
}

func TestDNSApply(t *testing.T) {
	h, _, root, _ := newTest(t)
	var mu sync.Mutex
	zones := map[string]*pdnsZone{}
	var patches []pdnsZone
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("X-API-Key") != "k" {
			w.WriteHeader(401)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/zones/")
		switch {
		case r.Method == "POST" && r.URL.Path == "/zones":
			var z pdnsZone
			_ = json.NewDecoder(r.Body).Decode(&z)
			zones[z.Name] = &z
			_ = json.NewEncoder(w).Encode(z)
		case r.Method == "GET":
			z, ok := zones[name]
			if !ok {
				w.WriteHeader(404)
				return
			}
			_ = json.NewEncoder(w).Encode(z)
		case r.Method == "PATCH":
			var z pdnsZone
			_ = json.NewDecoder(r.Body).Decode(&z)
			patches = append(patches, z)
			w.WriteHeader(204)
		default:
			w.WriteHeader(204)
		}
	}))
	defer srv.Close()
	h.PDNS = PDNS{URL: srv.URL, KeyFile: "/etc/hostzit/pdns-api.key"}
	_ = os.MkdirAll(filepath.Join(root, "etc/hostzit"), 0o700)
	_ = os.WriteFile(filepath.Join(root, "etc/hostzit/pdns-api.key"), []byte("k\n"), 0o600)
	args := zoneArgs{Zone: "Shop.Example.com", Nameservers: []string{"ns1.host.test", "ns2.host.test"}, Records: []hosting.Record{
		{Name: "@", Type: "A", Content: "192.0.2.1"}, {Name: "www", Type: "CNAME", Content: "shop.example.com"}, {Name: "@", Type: "MX", Content: "10 mail.shop.example.com"},
		{Name: "@", Type: "TXT", Content: `v=spf1 a mx -all`},
	}}
	if r := call(t, h, "dns.apply", args); !r.OK {
		t.Fatal(r.Error)
	}
	if _, ok := zones["shop.example.com."]; !ok || len(patches) != 1 {
		t.Fatal(zones, patches)
	}
	got := map[string]string{}
	for _, s := range patches[0].RRSets {
		if len(s.Records) > 0 {
			got[s.Name+" "+s.Type] = s.Records[0].Content
		}
	}
	if got["www.shop.example.com. CNAME"] != "shop.example.com." || got["shop.example.com. TXT"] != `"v=spf1 a mx -all"` || got["shop.example.com. MX"] != "10 mail.shop.example.com." {
		t.Fatal(got)
	}
	// records no longer wanted are deleted
	zones["shop.example.com."].RRSets = append(zones["shop.example.com."].RRSets, pdnsRRSet{Name: "old.shop.example.com.", Type: "A"})
	args.Records = args.Records[:1]
	if r := call(t, h, "dns.apply", args); !r.OK {
		t.Fatal(r.Error)
	}
	var deleted bool
	for _, s := range patches[1].RRSets {
		if s.Name == "old.shop.example.com." && s.ChangeType == "DELETE" {
			deleted = true
		}
	}
	if !deleted {
		t.Fatal(patches[1])
	}
	for _, bad := range []hosting.Record{{Name: "x", Type: "A", Content: "1.2.3"}, {Name: "@", Type: "CNAME", Content: "a.com"}, {Name: "a b", Type: "A", Content: "1.2.3.4"},
		{Name: "x", Type: "TXT", Content: "a\nb"}, {Name: "x", Type: "MX", Content: "10 a.com; rm"}, {Name: "x", Type: "LOC", Content: "x"}} {
		args.Records = []hosting.Record{bad}
		if r := call(t, h, "dns.apply", args); r.OK {
			t.Errorf("%+v accepted", bad)
		}
	}
	args.Records = []hosting.Record{{Name: "www", Type: "CNAME", Content: "a.com"}, {Name: "www", Type: "A", Content: "1.2.3.4"}}
	if r := call(t, h, "dns.apply", args); r.OK {
		t.Fatal("CNAME next to A accepted")
	}
}

func TestWorker(t *testing.T) {
	home := t.TempDir()
	do := func(r WorkerReq) WorkerResp {
		in, _ := json.Marshal(r)
		pr, pw := io.Pipe()
		go func() { _ = RunWorker(home, strings.NewReader(string(in)), pw); pw.Close() }()
		var resp WorkerResp
		_ = json.NewDecoder(pr).Decode(&resp)
		return resp
	}
	if r := do(WorkerReq{Op: "ensure-site", Path: "sites/a.com/public", Index: "<h1>hi</h1>"}); !r.OK || r.Count != 1 {
		t.Fatal(r)
	}
	if r := do(WorkerReq{Op: "write", Path: "sites/a.com/public/x.txt", Data: []byte("hello")}); !r.OK {
		t.Fatal(r)
	}
	if r := do(WorkerReq{Op: "read", Path: "sites/a.com/public/x.txt"}); string(r.Data) != "hello" {
		t.Fatal(r)
	}
	if r := do(WorkerReq{Op: "list", Path: "sites/a.com/public"}); len(r.Files) != 2 {
		t.Fatal(r)
	}
	for _, bad := range []WorkerReq{{Op: "read", Path: "../etc/passwd"}, {Op: "delete", Path: ""}, {Op: "rename", Path: "sites", To: "../x"}, {Op: "chmod", Path: "sites", Mode: "4755"}, {Op: "nope"}} {
		if r := do(bad); r.OK {
			t.Errorf("%+v accepted", bad)
		}
	}
	if r := do(WorkerReq{Op: "read", Path: "sites/a.com/public/missing"}); r.OK || strings.Contains(r.Error, home) {
		t.Fatal("path leaked:", r.Error)
	}
}

func TestServePeerCheck(t *testing.T) {
	h, _, _, _ := newTest(t)
	h.PeerCheck = func(net.Conn) error { return errors.New("no") }
	a, b := net.Pipe()
	go h.serveConn(context.Background(), b)
	_, _ = a.Write([]byte(`{"op":"system.info"}` + "\n"))
	buf := make([]byte, 10)
	if n, _ := a.Read(buf); n != 0 {
		t.Fatal("refused peer got an answer")
	}
	h.PeerCheck = func(net.Conn) error { return nil }
	c := &Client{Dial: func(context.Context) (net.Conn, error) {
		x, y := net.Pipe()
		go h.serveConn(context.Background(), y)
		return x, nil
	}}
	var res struct {
		Removed int `json:"removed"`
	}
	if err := c.Call(context.Background(), "site.cache.purge", siteRef{Account: "shop", ID: 9}, &res); err != nil {
		t.Fatal(err)
	}
	if err := c.Call(context.Background(), "site.cache.purge", siteRef{Account: "Shop", ID: 9}, nil); err == nil {
		t.Fatal("bad account accepted")
	}
}

func TestApplianceNetwork(t *testing.T) {
	h, fr, root, _ := newTest(t)
	c := NetworkConfig{Address: "192.168.1.20/24", Gateway: "192.168.1.1", DNS: []string{"1.1.1.1"}, Hostname: "web1"}
	if r := call(t, h, "system.network", c); r.OK {
		t.Fatal("network changed on a server that is not the appliance")
	}
	_ = os.MkdirAll(filepath.Join(root, "var/lib/hostzit"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "var/lib/hostzit/.appliance"), nil, 0o644)
	for _, bad := range []NetworkConfig{{Address: "192.168.1.20", Gateway: "192.168.1.1", DNS: []string{"1.1.1.1"}},
		{Address: "192.168.1.20/24", Gateway: "10.0.0.1", DNS: []string{"1.1.1.1"}},
		{Address: "192.168.1.20/24", Gateway: "192.168.1.1"},
		{DHCP: true, Hostname: "web.example.com"}} {
		if r := call(t, h, "system.network", bad); r.OK {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if r := call(t, h, "system.network", c); !r.OK {
		t.Fatalf("network: %+v", r)
	}
	b, _ := os.ReadFile(filepath.Join(root, "etc/systemd/network/50-hostzit.network"))
	if !strings.Contains(string(b), "Address=192.168.1.20/24\nGateway=192.168.1.1\nDNS=1.1.1.1\n") || !fr.has("hostnamectl set-hostname web1") {
		t.Fatalf("network file:\n%s", b)
	}
	if r := call(t, h, "system.power", powerArgs{Action: "rm -rf"}); r.OK {
		t.Fatal("unknown power action accepted")
	}
}

func TestDBQuery(t *testing.T) {
	out := []byte(`<?xml version="1.0"?>
<resultset statement="SELECT id, name FROM t" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <row>
	<field name="id">1</field>
	<field name="name">a &amp; b</field>
  </row>
  <row>
	<field name="id">2</field>
	<field name="name" xsi:nil="true" />
  </row>
</resultset>
<resultset statement="UPDATE t SET x=1"></resultset>
`)
	sets, err := parseResultSets(out)
	if err != nil || len(sets) != 2 || len(sets[0].Rows) != 2 || sets[0].Columns[1] != "name" || *sets[0].Rows[0][1] != "a & b" || sets[0].Rows[1][1] != nil {
		t.Fatalf("sets %+v err %v", sets, err)
	}
	h, fr, _, _ := newTest(t)
	if r := call(t, h, "db.query", dbQueryArgs{Account: "shop", DBs: []string{"shop_wp"}, DB: "other_wp", SQL: "SELECT 1"}); r.OK {
		t.Fatal("query in a database of another account")
	}
	if r := call(t, h, "db.query", dbQueryArgs{Account: "shop", DBs: []string{"other_wp"}, SQL: "SELECT 1"}); r.OK {
		t.Fatal("grant on a database of another account")
	}
	if r := call(t, h, "db.query", dbQueryArgs{Account: "shop", DBs: []string{"shop_wp"}, DB: "shop_wp", SQL: "SELECT 1"}); !r.OK {
		t.Fatalf("query: %+v", r)
	}
	if !fr.has("GRANT ALL PRIVILEGES ON `shop\\_wp`.* TO 'hzq_shop_") || !fr.has("DROP USER IF EXISTS 'hzq_shop_") {
		t.Fatalf("temporary user not made and dropped: %v", fr.calls)
	}
}
