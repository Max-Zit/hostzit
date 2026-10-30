package web

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/max-zit/hostzit/internal/auth"
	"github.com/max-zit/hostzit/internal/helper"
	"github.com/max-zit/hostzit/internal/hosting"
	"github.com/max-zit/hostzit/internal/store"
)

// Import of cPanel backups (cpmove-USER.tar.gz). The archive is unpacked
// as the new account inside its cage; the panel only reads the small
// metadata files through the worker, so nothing in the archive is ever
// handled by root.

// cpMeta is what the panel needs from a cpmove archive.
type cpMeta struct {
	User     string
	IP       string
	Main     string
	Addons   map[string]string // addon domain → its subdomain
	Parked   []string
	Subs     []string
	DocRoots map[string]string // domain → document root relative to the old home
	DBs      []string
	DBUsers  map[string]cpDBUser
	Zones    map[string]string // domain → zone file text
	Cron     []string
}

type cpDBUser struct {
	Hash string
	DBs  []string
}

// parseUserdataMain reads userdata/main (simple YAML).
func parseUserdataMain(text string, m *cpMeta) {
	section := ""
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		l := sc.Text()
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") || t == "---" {
			continue
		}
		if !strings.HasPrefix(l, " ") && !strings.HasPrefix(l, "-") {
			k, v, _ := strings.Cut(t, ":")
			section = strings.TrimSpace(k)
			v = strings.Trim(strings.TrimSpace(v), `'"`)
			if section == "main_domain" {
				m.Main = v
			}
			continue
		}
		switch section {
		case "addon_domains":
			k, v, ok := strings.Cut(t, ":")
			if ok {
				m.Addons[strings.Trim(strings.TrimSpace(k), `'"`)] = strings.Trim(strings.TrimSpace(v), `'"`)
			}
		case "parked_domains":
			m.Parked = append(m.Parked, strings.Trim(strings.TrimSpace(strings.TrimPrefix(t, "-")), `'"`))
		case "sub_domains":
			m.Subs = append(m.Subs, strings.Trim(strings.TrimSpace(strings.TrimPrefix(t, "-")), `'"`))
		}
	}
}

var grantRE = regexp.MustCompile("(?i)GRANT\\s+(.+?)\\s+ON\\s+`?([^`.\\s]+)`?\\.\\*\\s+TO\\s+'([^']+)'@'([^']+)'(?:\\s+IDENTIFIED BY PASSWORD\\s+'([^']+)')?")
var createUserRE = regexp.MustCompile(`(?i)CREATE USER\s+'([^']+)'@'([^']+)'\s+IDENTIFIED (?:WITH\s+'?mysql_native_password'?\s+AS|BY PASSWORD)\s+'(\*[0-9A-F]{40})'`)

// parseGrants reads mysql.sql: users with their native hashes and databases.
func parseGrants(text string, m *cpMeta) {
	for _, line := range strings.Split(text, ";") {
		if c := createUserRE.FindStringSubmatch(line); c != nil && c[2] == "localhost" {
			u := m.DBUsers[c[1]]
			u.Hash = c[3]
			m.DBUsers[c[1]] = u
			continue
		}
		g := grantRE.FindStringSubmatch(line)
		if g == nil || g[4] != "localhost" {
			continue
		}
		u := m.DBUsers[g[3]]
		if g[5] != "" {
			u.Hash = g[5]
		}
		if g[2] != "*" {
			u.DBs = append(u.DBs, strings.ReplaceAll(g[2], `\_`, "_"))
		}
		m.DBUsers[g[3]] = u
	}
}

// parseZone reads the records of a BIND zone file that HostZit can host;
// the old server's address is replaced by the new one.
func parseZone(text, zone, oldIP, newIP string) []hosting.Record {
	origin := zone + "."
	ttl := 3600
	var out []hosting.Record
	last := "@"
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l := sc.Text()
		if i := strings.Index(l, ";"); i >= 0 && !strings.Contains(l[:i], `"`) {
			l = l[:i]
		}
		if strings.TrimSpace(l) == "" {
			continue
		}
		f := strings.Fields(l)
		switch {
		case f[0] == "$TTL" && len(f) > 1:
			ttl, _ = strconv.Atoi(f[1])
			continue
		case f[0] == "$ORIGIN" && len(f) > 1:
			origin = f[1]
			continue
		case strings.HasPrefix(f[0], "$"):
			continue
		}
		name := last
		if l[0] != ' ' && l[0] != '\t' {
			name, f = f[0], f[1:]
			last = name
		}
		recTTL := ttl
		for len(f) > 0 {
			if n, err := strconv.Atoi(f[0]); err == nil {
				recTTL = n
				f = f[1:]
				continue
			}
			if strings.EqualFold(f[0], "IN") {
				f = f[1:]
				continue
			}
			break
		}
		if len(f) < 2 {
			continue
		}
		typ := strings.ToUpper(f[0])
		data := strings.Join(f[1:], " ")
		if typ == "SOA" || typ == "NS" && (name == "@" || name == origin || name == zone+".") {
			continue
		}
		if name == origin || name == zone+"." {
			name = "@"
		} else if strings.HasSuffix(name, ".") {
			name = hosting.RelName(name, zone)
		} else if origin != zone+"." && name != "@" {
			name = hosting.RelName(name+"."+origin, zone)
		}
		if typ == "A" && oldIP != "" && newIP != "" && data == oldIP {
			data = newIP
		}
		r, err := hosting.CleanRecord(hosting.Record{Name: name, Type: typ, TTL: max(recTTL, 60), Content: data}, zone)
		if err != nil {
			continue // record types HostZit does not host (SPF type, LOC …)
		}
		out = append(out, r)
	}
	return out
}

// readMeta reads the metadata of an unpacked cpmove archive.
func (s *Server) readMeta(ctx context.Context, by string, c *store.Customer, root string) (*cpMeta, error) {
	m := &cpMeta{Addons: map[string]string{}, DocRoots: map[string]string{}, DBUsers: map[string]cpDBUser{}, Zones: map[string]string{}}
	read := func(p string) string {
		var r helper.WorkerResp
		if err := s.call(ctx, by, "files", map[string]any{"account": c.Username, "req": helper.WorkerReq{Op: "read", Path: root + "/" + p, Limit: 8 << 20}}, &r); err != nil {
			return ""
		}
		return string(r.Data)
	}
	list := func(p string) []helper.FileInfo {
		var r helper.WorkerResp
		if err := s.call(ctx, by, "files", map[string]any{"account": c.Username, "req": helper.WorkerReq{Op: "list", Path: root + "/" + p}}, &r); err != nil {
			return nil
		}
		return r.Files
	}
	parseUserdataMain(read("userdata/main"), m)
	if m.Main == "" {
		return nil, errors.New("this is not a cPanel backup (userdata/main missing)")
	}
	for _, d := range append([]string{m.Main}, append(keys(m.Addons), m.Subs...)...) {
		for _, l := range strings.Split(read("userdata/"+d), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(l), "documentroot:"); ok {
				m.DocRoots[d] = strings.Trim(strings.TrimSpace(v), `'"`)
			}
		}
	}
	for _, l := range strings.Split(read("cp/"+path.Base(root)[len("cpmove-"):]), "\n") {
		if v, ok := strings.CutPrefix(l, "IP="); ok {
			m.IP = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(l, "USER="); ok {
			m.User = strings.TrimSpace(v)
		}
	}
	for _, f := range list("mysql") {
		if strings.HasSuffix(f.Name, ".sql") && !f.Dir {
			m.DBs = append(m.DBs, strings.TrimSuffix(f.Name, ".sql"))
		}
	}
	sort.Strings(m.DBs)
	parseGrants(read("mysql.sql"), m)
	for _, f := range list("dnszones") {
		if strings.HasSuffix(f.Name, ".db") {
			m.Zones[strings.TrimSuffix(f.Name, ".db")] = read("dnszones/" + f.Name)
		}
	}
	if m.User != "" {
		for _, l := range strings.Split(read("cron/"+m.User), "\n") {
			l = strings.TrimSpace(l)
			if l != "" && !strings.HasPrefix(l, "#") && !strings.Contains(l, "=") {
				m.Cron = append(m.Cron, l)
			}
		}
	}
	return m, nil
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// newDocRoot maps a cPanel document root to HostZit's layout:
// public_html → sites/<main>/public, any other folder → sites/<folder>.
func newDocRoot(old, oldHome, main string) (string, error) {
	rel := strings.Trim(strings.TrimPrefix(old, oldHome), "/")
	if rel == "public_html" || strings.HasPrefix(rel, "public_html/") {
		return hosting.CleanRelPath("sites/" + main + "/public" + strings.TrimPrefix(rel, "public_html"))
	}
	if rel == "" {
		return "", errors.New("document root is the home folder")
	}
	return hosting.CleanRelPath("sites/" + rel)
}

// ImportReport says what an import did.
type ImportReport struct {
	Sites, Zones, DBs, Users, Cron int
	Notes                          []string
}

// importCPanel creates the account from a cpmove archive in ImportDir.
func (s *Server) importCPanel(ctx context.Context, by, file, username string, packageID int64) (*ImportReport, error) {
	rep := &ImportReport{}
	pw := auth.RandomToken(16) + "-Hz"
	c, err := s.createAccount(ctx, by, NewAccount{NewCustomer: store.NewCustomer{Username: username, PackageID: packageID, Password: pw, DisplayName: "cPanel import " + username}})
	if err != nil {
		return nil, err
	}
	_ = s.store.SetPassword(ctx, c.UserID, pw, true, "")
	if err := s.call(ctx, by, "import.stage", map[string]string{"account": c.Username, "file": file}, nil); err != nil {
		return nil, err
	}
	var top helper.WorkerResp
	if err := s.call(ctx, by, "files", map[string]any{"account": c.Username, "req": helper.WorkerReq{Op: "list", Path: ".hz-import"}}, &top); err != nil || len(top.Files) != 1 || !strings.HasPrefix(top.Files[0].Name, "cpmove-") {
		return nil, errors.New("the archive must contain one folder cpmove-USER")
	}
	root := ".hz-import/" + top.Files[0].Name
	m, err := s.readMeta(ctx, by, c, root)
	if err != nil {
		return nil, err
	}
	oldUser := strings.TrimPrefix(top.Files[0].Name, "cpmove-")
	oldHome := "/home/" + oldUser
	hs := s.hostingSettings(ctx)
	// files: the whole old home goes into ~/cpanel-home first, then the
	// document roots are moved into sites/
	moves := map[string]string{} // new doc root → old relative path
	domains := append([]string{m.Main}, keys(m.Addons)...)
	domains = append(domains, m.Subs...)
	for _, d := range domains {
		old := m.DocRoots[d]
		if old == "" {
			if d == m.Main {
				old = oldHome + "/public_html"
			} else {
				continue
			}
		}
		nr, err := newDocRoot(old, oldHome, m.Main)
		if err != nil {
			rep.Notes = append(rep.Notes, d+": "+err.Error())
			continue
		}
		moves[nr] = strings.Trim(strings.TrimPrefix(old, oldHome), "/")
		m.DocRoots[d] = nr
	}
	var r helper.WorkerResp
	if err := s.call(ctx, by, "files", map[string]any{"account": c.Username, "req": helper.WorkerReq{Op: "rename", Path: root + "/homedir", To: "sites/" + m.Main + ".old"}}, &r); err != nil {
		return nil, fmt.Errorf("files: %w", err)
	}
	// public_html becomes the main site's public folder; other roots their own sites/<name>
	_ = s.call(ctx, by, "files", map[string]any{"account": c.Username, "req": helper.WorkerReq{Op: "mkdir", Path: "sites/" + m.Main}}, &r)
	if err := s.call(ctx, by, "files", map[string]any{"account": c.Username, "req": helper.WorkerReq{Op: "rename", Path: "sites/" + m.Main + ".old/public_html", To: "sites/" + m.Main + "/public"}}, &r); err != nil {
		rep.Notes = append(rep.Notes, "public_html: "+storeErr(err))
	}
	for nr, old := range moves {
		if strings.HasPrefix(old, "public_html") {
			continue
		}
		if err := s.call(ctx, by, "files", map[string]any{"account": c.Username, "req": helper.WorkerReq{Op: "rename", Path: "sites/" + m.Main + ".old/" + old, To: nr}}, &r); err != nil {
			rep.Notes = append(rep.Notes, old+": "+storeErr(err))
		}
	}
	_ = s.call(ctx, by, "files", map[string]any{"account": c.Username, "req": helper.WorkerReq{Op: "rename", Path: "sites/" + m.Main + ".old", To: "cpanel-home"}}, &r)
	rep.Notes = append(rep.Notes, "The rest of the old home folder (mail, settings) is in ~/cpanel-home.")
	// sites
	for _, d := range domains {
		nr, ok := m.DocRoots[d]
		if !ok {
			continue
		}
		dom, err := hosting.NormalizeDomain(d)
		if err != nil {
			continue
		}
		x := &store.Site{CustomerID: c.ID, Account: c.Username, Domain: dom, DocRoot: nr, PHPVersion: hs.DefaultPHP, WWW: true, Canonical: "", ForceHTTPS: true, CacheMinutes: 60, UploadMB: 64, AutoTLS: true}
		if d == m.Main {
			for _, p := range m.Parked {
				if a, err := hosting.NormalizeDomain(p); err == nil {
					x.Aliases = append(x.Aliases, a)
				}
			}
		}
		if err := s.store.SaveSite(ctx, x); err != nil {
			rep.Notes = append(rep.Notes, dom+": "+err.Error())
			continue
		}
		if err := s.applySite(ctx, by, x, false); err != nil {
			rep.Notes = append(rep.Notes, dom+": "+storeErr(err))
		}
		rep.Sites++
	}
	// DNS zones (the old server's address becomes this server's)
	for zone, text := range m.Zones {
		z, err := hosting.NormalizeDomain(zone)
		if err != nil {
			continue
		}
		recs := parseZone(text, z, m.IP, hs.IPv4)
		zz, err := s.store.CreateZone(ctx, c.ID, z, recs)
		if err != nil {
			rep.Notes = append(rep.Notes, "DNS "+z+": "+err.Error())
			continue
		}
		_ = s.applyZone(ctx, by, zz)
		rep.Zones++
	}
	// databases: names stay when the account name stays (cPanel uses the same prefix)
	for _, db := range m.DBs {
		if !strings.HasPrefix(db, oldUser+"_") {
			continue
		}
		name := c.Username + strings.TrimPrefix(db, oldUser)
		if !hosting.ValidDatabase(c.Username, name) {
			rep.Notes = append(rep.Notes, "database "+db+": name not allowed")
			continue
		}
		if err := s.store.AddDatabase(ctx, c.ID, name); err != nil {
			rep.Notes = append(rep.Notes, "database "+name+": "+storeErr(err))
			continue
		}
		if err := s.call(ctx, by, "db.create", map[string]string{"account": c.Username, "name": name}, nil); err != nil {
			rep.Notes = append(rep.Notes, "database "+name+": "+storeErr(err))
			continue
		}
		if err := s.call(ctx, by, "db.import", map[string]string{"account": c.Username, "db": name, "file": root + "/mysql/" + db + ".sql"}, nil); err != nil {
			rep.Notes = append(rep.Notes, "database "+name+": "+storeErr(err))
			continue
		}
		rep.DBs++
	}
	for u, du := range m.DBUsers {
		if u == oldUser || !strings.HasPrefix(u, oldUser+"_") {
			continue
		}
		name := c.Username + strings.TrimPrefix(u, oldUser)
		var dbs []string
		for _, d := range du.DBs {
			if strings.HasPrefix(d, oldUser+"_") {
				dbs = append(dbs, c.Username+strings.TrimPrefix(d, oldUser))
			}
		}
		args := map[string]any{"account": c.Username, "user": name, "databases": dbs}
		if du.Hash != "" {
			args["hash"] = du.Hash
		} else {
			args["password"] = auth.RandomToken(20)
			rep.Notes = append(rep.Notes, "database user "+name+" got a new password (the old one could not be moved)")
		}
		if err := s.call(ctx, by, "db.user", args, nil); err != nil {
			rep.Notes = append(rep.Notes, "database user "+name+": "+storeErr(err))
			continue
		}
		_ = s.store.SaveDBUser(ctx, c.ID, name, dbs)
		rep.Users++
	}
	// cron jobs (paths of the old home are rewritten)
	for _, l := range m.Cron {
		f := strings.Fields(l)
		if len(f) < 6 {
			continue
		}
		sched, cmd := strings.Join(f[:5], " "), strings.Join(f[5:], " ")
		cmd = rewriteHome(cmd, oldHome, hosting.HomeDir(c.Username), m.Main)
		if _, err := hosting.OnCalendar(sched); err != nil || hosting.CheckCommand(cmd) != nil {
			rep.Notes = append(rep.Notes, "cron job not moved: "+l)
			continue
		}
		if err := s.store.AddCronJob(ctx, &store.CronJob{CustomerID: c.ID, Schedule: sched, Command: cmd, Enabled: true, Note: "from cPanel"}); err == nil {
			rep.Cron++
		}
	}
	if rep.Cron > 0 {
		_ = s.applyCron(ctx, by, c)
	}
	if oldUser != c.Username && rep.DBs > 0 {
		rep.Notes = append(rep.Notes, "The account name changed from "+oldUser+" to "+c.Username+": update the database names in the websites' configuration (wp-config.php).")
	}
	_ = s.call(ctx, by, "files", map[string]any{"account": c.Username, "req": helper.WorkerReq{Op: "delete", Path: ".hz-import"}}, &r)
	s.kickCerts()
	return rep, nil
}

// rewriteHome moves paths of the old cPanel home to the new layout:
// public_html → sites/<main>/public, the rest → cpanel-home.
func rewriteHome(cmd, oldHome, newHome, main string) string {
	const mark = "\x00HZPUB\x00"
	cmd = strings.ReplaceAll(cmd, oldHome+"/public_html", mark)
	cmd = strings.ReplaceAll(cmd, oldHome+"/", newHome+"/cpanel-home/")
	return strings.ReplaceAll(cmd, mark, newHome+"/sites/"+main+"/public")
}
