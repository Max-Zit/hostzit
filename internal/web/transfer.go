package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/auth"
	"github.com/max-zit/hostzit/internal/helper"
	"github.com/max-zit/hostzit/internal/hosting"
	"github.com/max-zit/hostzit/internal/store"
)

// Moving accounts between HostZit servers (like WHM's Transfer Tool) and
// restoring HostZit archives (own backups, remote backups): the source
// sends the account's archive to the target's REST API, the target
// creates the account from it with the same name, passwords, websites,
// DNS zones, databases, cron jobs, applications and settings.

// manifestExtras adds the settings that live only in the panel.
func (s *Server) manifestExtras(ctx context.Context, c *store.Customer, man *Manifest, transfer bool) {
	man.ServerIPv4 = s.hostingSettings(ctx).IPv4
	man.PHPVersion = c.PHPVersion
	_ = s.call(ctx, "system", "db.hashes", map[string]string{"account": c.Username}, &man.DBHashes)
	man.PHP = s.phpOptions(ctx, c)
	man.Redis = s.redisOn(ctx, c)
	if apps, err := s.store.Apps(ctx, c.ID); err == nil {
		for _, a := range apps {
			man.Apps = append(man.Apps, ManifestApp{App: a.Spec(), Enabled: a.Enabled})
		}
	}
	if repos, err := s.store.GitRepos(ctx, c.ID); err == nil {
		for _, g := range repos {
			man.Git = append(man.Git, gitSpec(g))
		}
	}
	if transfer {
		man.PasswordHash, _ = s.store.PasswordHash(ctx, c.UserID)
	}
}

// readManifest reads the manifest of an archive in the import folder
// (nil: not a HostZit archive).
func (s *Server) readManifest(ctx context.Context, by, file string) (*Manifest, error) {
	var res struct {
		Manifest string `json:"manifest"`
	}
	if err := s.call(ctx, by, "import.manifest", map[string]string{"file": file}, &res); err != nil {
		return nil, err
	}
	if res.Manifest == "" {
		return nil, nil
	}
	var m Manifest
	if err := json.Unmarshal([]byte(res.Manifest), &m); err != nil || m.Product != "hostzit" {
		return nil, errors.New("the archive's hostzit-manifest.json is invalid")
	}
	return &m, nil
}

// importHostZit creates an account from a HostZit archive in the import
// folder. packageID 0 takes the package of the same name.
func (s *Server) importHostZit(ctx context.Context, by, file, username string, packageID int64, m *Manifest) (*ImportReport, *store.Customer, error) {
	rep := &ImportReport{}
	oldUser := m.Customer["username"]
	if username == "" {
		username = oldUser
	}
	if err := hosting.ValidAccount(username); err != nil {
		return nil, nil, err
	}
	if packageID == 0 {
		if p, err := s.store.PackageBySlug(ctx, m.Package); err == nil {
			packageID = p.ID
		} else {
			return nil, nil, fmt.Errorf("there is no package %q on this server: choose one", m.Package)
		}
	}
	hs := s.hostingSettings(ctx)
	installed := s.phpVersions(ctx)
	php := m.PHPVersion
	if !slices.Contains(installed, php) {
		php = ""
	}
	pw := auth.RandomToken(16) + "-Hz"
	c, err := s.createAccount(ctx, by, NewAccount{NewCustomer: store.NewCustomer{Username: username, PackageID: packageID, Password: pw,
		DisplayName: m.Customer["name"], Email: m.Customer["email"], PHPVersion: php}})
	if err != nil {
		return nil, nil, err
	}
	if m.PasswordHash != "" {
		if err := s.store.SetPasswordHash(ctx, c.UserID, m.PasswordHash); err != nil {
			rep.Notes = append(rep.Notes, "the customer got a new password: "+err.Error())
		}
	} else {
		_ = s.store.SetPassword(ctx, c.UserID, pw, true, "")
		rep.Notes = append(rep.Notes, "The customer has a new password; set one under Customers.")
	}
	file = filepath.Base(file)
	if err := s.call(ctx, by, "import.stage", map[string]string{"account": c.Username, "file": file}, nil); err != nil {
		return rep, c, err
	}
	var top, home helper.WorkerResp
	if err := s.call(ctx, by, "files", map[string]any{"account": c.Username, "req": helper.WorkerReq{Op: "list", Path: ".hz-import"}}, &top); err != nil {
		return rep, c, err
	}
	_ = s.call(ctx, by, "files", map[string]any{"account": c.Username, "req": helper.WorkerReq{Op: "list", Path: "."}}, &home)
	exists := map[string]bool{}
	for _, f := range home.Files {
		exists[f.Name] = f.Dir
	}
	mv := func(from, to string) error {
		return s.call(ctx, by, "files", map[string]any{"account": c.Username, "req": helper.WorkerReq{Op: "rename", Path: from, To: to}}, nil)
	}
	// files: top-level entries move into the home; folders that exist
	// already (sites, logs …) get their contents
	for _, f := range top.Files {
		if f.Name == "hostzit-manifest.json" || strings.HasPrefix(f.Name, "mysql-") && strings.HasSuffix(f.Name, ".sql") {
			continue
		}
		src := ".hz-import/" + f.Name
		isDir, there := exists[f.Name]
		if !there {
			if err := mv(src, f.Name); err != nil {
				rep.Notes = append(rep.Notes, f.Name+": "+storeErr(err))
			}
			continue
		}
		if !isDir || !f.Dir {
			rep.Notes = append(rep.Notes, f.Name+" exists already and was not replaced")
			continue
		}
		var sub helper.WorkerResp
		_ = s.call(ctx, by, "files", map[string]any{"account": c.Username, "req": helper.WorkerReq{Op: "list", Path: src}}, &sub)
		for _, g := range sub.Files {
			if err := mv(src+"/"+g.Name, f.Name+"/"+g.Name); err != nil {
				rep.Notes = append(rep.Notes, f.Name+"/"+g.Name+": "+storeErr(err))
			}
		}
	}
	// databases and their users (names carry the account name)
	rename := func(n string) string {
		if oldUser != "" && oldUser != c.Username && strings.HasPrefix(n, oldUser+"_") {
			return c.Username + strings.TrimPrefix(n, oldUser)
		}
		return n
	}
	for _, db := range m.Databases {
		name := rename(db)
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
		if err := s.call(ctx, by, "db.import", map[string]string{"account": c.Username, "db": name, "file": ".hz-import/mysql-" + db + ".sql"}, nil); err != nil {
			rep.Notes = append(rep.Notes, "database "+name+": "+storeErr(err))
			continue
		}
		rep.DBs++
	}
	users := make([]string, 0, len(m.DBUsers))
	for u := range m.DBUsers {
		users = append(users, u)
	}
	slices.Sort(users)
	for _, u := range users {
		name := rename(u)
		var dbs []string
		for _, d := range m.DBUsers[u] {
			dbs = append(dbs, rename(d))
		}
		args := map[string]any{"account": c.Username, "user": name, "databases": dbs}
		if h := m.DBHashes[u]; h != "" {
			args["hash"] = h
		} else {
			args["password"] = auth.RandomToken(20)
			rep.Notes = append(rep.Notes, "database user "+name+" got a new password")
		}
		if err := s.call(ctx, by, "db.user", args, nil); err != nil {
			rep.Notes = append(rep.Notes, "database user "+name+": "+storeErr(err))
			continue
		}
		_ = s.store.SaveDBUser(ctx, c.ID, name, dbs)
		rep.Users++
	}
	// panel settings of the account
	if len(m.PHP) > 0 {
		_ = s.store.SetSetting(ctx, phpOptionsKey(c), m.PHP)
	}
	if m.Redis {
		_ = s.store.SetSetting(ctx, redisKey(c), true)
	}
	for _, a := range m.Apps {
		app := &store.App{CustomerID: c.ID, Name: a.Name, Kind: a.Kind, Root: a.Root, Command: a.Command, Env: a.Env, Enabled: a.Enabled}
		if err := s.store.SaveApp(ctx, app); err != nil {
			rep.Notes = append(rep.Notes, "application "+a.Name+": "+storeErr(err))
		}
	}
	// websites
	for _, x := range m.Sites {
		ver := x.PHPVersion
		if !slices.Contains(installed, ver) {
			ver = hs.DefaultPHP
			rep.Notes = append(rep.Notes, x.Domain+": PHP "+x.PHPVersion+" is not installed here, it uses "+ver)
		}
		st := &store.Site{CustomerID: c.ID, Account: c.Username, Domain: x.Domain, Aliases: x.Aliases, DocRoot: x.DocRoot, PHPVersion: ver, WWW: x.WWW,
			Canonical: x.Canonical, ForceHTTPS: x.ForceHTTPS, HSTS: x.HSTS, Cache: x.Cache, CacheMinutes: x.CacheMinutes, WordPress: x.WordPress,
			BlockXMLRPC: x.BlockXMLRPC, Redirects: x.Redirects, UploadMB: x.UploadMB, AutoTLS: true, IPAllow: x.IPAllow, IPDeny: x.IPDeny,
			Hotlink: x.Hotlink, WAF: x.WAF, WAFDetect: x.WAFDetect, WAFExclude: x.WAFExclude, Protected: x.Protected}
		if st.CacheMinutes == 0 {
			st.CacheMinutes = 60
		}
		if st.UploadMB == 0 {
			st.UploadMB = 64
		}
		if err := s.store.SaveSite(ctx, st); err != nil {
			rep.Notes = append(rep.Notes, x.Domain+": "+err.Error())
			continue
		}
		if x.App != "" {
			_ = s.store.SetSiteApp(ctx, st.ID, x.App)
			st.App = x.App
		}
		rep.Sites++
	}
	// DNS zones: the old server's address becomes this one's
	for zone, recs := range m.Zones {
		if m.ServerIPv4 != "" && hs.IPv4 != "" {
			for i := range recs {
				if recs[i].Type == "A" && recs[i].Content == m.ServerIPv4 {
					recs[i].Content = hs.IPv4
				}
			}
		}
		z, err := s.store.CreateZone(ctx, c.ID, zone, recs)
		if err != nil {
			rep.Notes = append(rep.Notes, "DNS "+zone+": "+err.Error())
			continue
		}
		_ = s.applyZone(ctx, by, z)
		rep.Zones++
	}
	// cron jobs
	for _, j := range m.Cron {
		cmd := j.Command
		if oldUser != "" && oldUser != c.Username {
			cmd = strings.ReplaceAll(cmd, hosting.HomeDir(oldUser), hosting.HomeDir(c.Username))
		}
		if err := s.store.AddCronJob(ctx, &store.CronJob{CustomerID: c.ID, Schedule: j.Schedule, Command: cmd, Enabled: j.Enabled}); err == nil {
			rep.Cron++
		}
	}
	// the account (PHP options, Redis, applications), then its sites and jobs
	if err := s.applyCustomer(ctx, by, c); err != nil {
		rep.Notes = append(rep.Notes, "account: "+storeErr(err))
	}
	if sites, err := s.store.Sites(ctx, c.ID); err == nil {
		for _, x := range sites {
			if err := s.applySite(ctx, by, x, false); err != nil {
				rep.Notes = append(rep.Notes, x.Domain+": "+storeErr(err))
			}
		}
	}
	if rep.Cron > 0 {
		_ = s.applyCron(ctx, by, c)
	}
	for _, g := range m.Git {
		repo := &store.GitRepo{CustomerID: c.ID, Name: g.Name, Branch: g.Branch, Target: g.Target, Remote: g.Remote, HookToken: auth.RandomToken(24)}
		if err := s.call(ctx, by, "git.setup", map[string]any{"account": c.Username, "repo": gitSpec(repo)}, nil); err == nil {
			_ = s.store.SaveGitRepo(ctx, repo)
		}
		if g.Remote != "" {
			rep.Notes = append(rep.Notes, "Git "+g.Name+": the webhook address changed; enter the new one at the Git host.")
		}
	}
	if oldUser != "" && oldUser != c.Username && rep.DBs > 0 {
		rep.Notes = append(rep.Notes, "The account name changed from "+oldUser+" to "+c.Username+": update the database names in the websites' configuration.")
	}
	_ = s.call(ctx, by, "files", map[string]any{"account": c.Username, "req": helper.WorkerReq{Op: "delete", Path: ".hz-import"}}, nil)
	s.kickCerts()
	return rep, c, nil
}

// ---- target: the REST API

func init() {
	apiExtra = append(apiExtra, func(s *Server, need func(scope, pattern string, h http.HandlerFunc)) {
		need("customers:write", "PUT /api/v1/transfers/{name}", s.apiTransferReceive)
		need("customers:write", "POST /api/v1/transfers/{name}/import", s.apiTransferImport)
	})
}

func (s *Server) apiTransferReceive(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !helper.TransferName(name) {
		apiError(w, http.StatusBadRequest, "invalid", "invalid archive name")
		return
	}
	if err := os.MkdirAll(helper.TransferDir, 0o700); err != nil {
		apiError(w, http.StatusInternalServerError, "internal", "the transfer folder cannot be made")
		return
	}
	part := filepath.Join(helper.TransferDir, name+".part")
	f, err := os.OpenFile(part, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- checked name in the panel's own folder
	if err != nil {
		apiError(w, http.StatusInternalServerError, "internal", "the archive cannot be stored")
		return
	}
	n, err := io.Copy(f, http.MaxBytesReader(w, r.Body, 1<<40))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil || r.ContentLength >= 0 && n != r.ContentLength {
		_ = os.Remove(part)
		apiError(w, http.StatusBadRequest, "invalid", "the archive did not arrive completely")
		return
	}
	if err := os.Rename(part, filepath.Join(helper.TransferDir, name)); err != nil {
		_ = os.Remove(part)
		apiError(w, http.StatusInternalServerError, "internal", "the archive cannot be stored")
		return
	}
	if err := s.call(r.Context(), actor(r), "import.adopt", map[string]string{"name": name}, nil); err != nil {
		apiFail(w, err)
		return
	}
	s.audit(r, "transfer.receive", "server", "archive %s received (%d bytes)", name, n)
	writeJSON(w, http.StatusCreated, map[string]any{"name": name, "size": n})
}

func (s *Server) apiTransferImport(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !helper.TransferName(name) {
		apiError(w, http.StatusBadRequest, "invalid", "invalid archive name")
		return
	}
	var in struct {
		Username string `json:"username"`
		Package  string `json:"package"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in)
	by := actor(r)
	m, err := s.readManifest(r.Context(), by, name)
	if err != nil || m == nil {
		apiError(w, http.StatusBadRequest, "invalid", "not a HostZit archive")
		return
	}
	var pkg int64
	if in.Package != "" {
		p, err := s.store.PackageBySlug(r.Context(), in.Package)
		if err != nil {
			apiError(w, http.StatusBadRequest, "invalid", "no such package")
			return
		}
		pkg = p.ID
	}
	j, err := s.runJob("transfer.import", nil, name, func(ctx context.Context) error {
		rep, c, err := s.importHostZit(ctx, by, name, in.Username, pkg, m)
		if err != nil {
			return err
		}
		_ = s.store.Audit(ctx, by, "local", "transfer.import", "customer:"+c.Username, importSummary(name, c.Username, rep))
		return nil
	})
	if err != nil {
		apiFail(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job_id": j.ID})
}

func importSummary(file, user string, rep *ImportReport) string {
	d := fmt.Sprintf("%s → %s: %d websites, %d DNS zones, %d databases, %d database users, %d cron jobs", file, user, rep.Sites, rep.Zones, rep.DBs, rep.Users, rep.Cron)
	if len(rep.Notes) > 0 {
		d += ". Notes: " + strings.Join(rep.Notes, "; ")
	}
	return d
}

// ---- source: "Move to another server" on the customer's page

func init() {
	adminExtra = append(adminExtra, func(s *Server, mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc)) {
		admin("POST /customers/{id}/transfer/check", s.handleTransferCheck)
		admin("POST /customers/{id}/transfer", s.handleTransferStart)
	})
}

// targetCert connects to the target and returns the SHA-256 of its
// certificate and whether a normal check accepts it.
func targetCert(ctx context.Context, base string) (string, bool, error) {
	host := strings.TrimPrefix(base, "https://")
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	d := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}} // #nosec G402 -- only to show the fingerprint for confirmation
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return "", false, err
	}
	defer conn.Close()
	st := conn.(*tls.Conn).ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return "", false, errors.New("no certificate")
	}
	sum := sha256.Sum256(st.PeerCertificates[0].Raw)
	name, _, _ := strings.Cut(host, ":")
	pool := x509.NewCertPool()
	for _, ic := range st.PeerCertificates[1:] {
		pool.AddCert(ic)
	}
	_, verr := st.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: name, Intermediates: pool})
	return hex.EncodeToString(sum[:]), verr == nil, nil
}

type transferData struct {
	C           *store.Customer
	URL         string
	Token       string
	Fingerprint string
	Trusted     bool
	Version     string
	Suspend     bool
}

// targetCall calls the target's API.
func targetCall(ctx context.Context, base, token, fp, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := helper.TransferClient(fp, time.Minute).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		if e.Error.Message == "" {
			e.Error.Message = resp.Status
		}
		return errors.New("the target answered: " + e.Error.Message)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func (s *Server) handleTransferCheck(w http.ResponseWriter, r *http.Request) {
	c := s.loadCustomer(w, r)
	if c == nil {
		return
	}
	back := "/customers/" + strconv.FormatInt(c.ID, 10)
	base, err := helper.CheckTargetURL(r.FormValue("url"))
	if err != nil {
		s.redirectErr(w, r, back, err.Error())
		return
	}
	d := &transferData{C: c, URL: base, Token: strings.TrimSpace(r.FormValue("token")), Suspend: r.FormValue("suspend") != ""}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	fp, trusted, err := targetCert(ctx, base)
	if err != nil {
		s.redirectErr(w, r, back, "The target cannot be reached: "+err.Error())
		return
	}
	d.Fingerprint, d.Trusted = fp, trusted
	var info map[string]any
	if err := targetCall(ctx, base, d.Token, fp, http.MethodGet, "/api/v1/zit/info", nil, &info); err != nil {
		s.redirectErr(w, r, back, err.Error())
		return
	}
	if p, _ := info["product"].(string); p != "hostzit" {
		s.redirectErr(w, r, back, "The target is not a HostZit server.")
		return
	}
	d.Version, _ = info["version"].(string)
	if err := targetCall(ctx, base, d.Token, fp, http.MethodGet, "/api/v1/packages", nil, nil); err != nil {
		s.redirectErr(w, r, back, err.Error())
		return
	}
	s.render(w, r, http.StatusOK, "transfer", &Page{Title: "Move to another server", Nav: "customers", Crumb: "Customers", CrumbURL: "/customers", Data: d})
}

func (s *Server) handleTransferStart(w http.ResponseWriter, r *http.Request) {
	c := s.loadCustomer(w, r)
	if c == nil {
		return
	}
	back := "/customers/" + strconv.FormatInt(c.ID, 10)
	base, err := helper.CheckTargetURL(r.FormValue("url"))
	if err != nil {
		s.redirectErr(w, r, back, err.Error())
		return
	}
	token, fp, suspend := strings.TrimSpace(r.FormValue("token")), r.FormValue("fingerprint"), r.FormValue("suspend") != ""
	by := actor(r)
	j, err := s.runJob("transfer.send", &c.ID, c.Username+" → "+base, func(ctx context.Context) error {
		return s.transferAccount(ctx, by, c, base, token, fp, suspend)
	})
	if err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.audit(r, "transfer.start", "customer:"+c.Username, "moving to %s (job %s)", base, j.ID)
	s.redirect(w, r, "/jobs", "The move was started. The result is in the job list and the audit log.")
}

// transferAccount sends the account, has the target import it and waits
// for the result; then the account here is suspended when asked.
func (s *Server) transferAccount(ctx context.Context, by string, c *store.Customer, base, token, fp string, suspend bool) error {
	name, dbs, manifest := s.backupRequestFor(ctx, c, true)
	var made struct {
		Name string `json:"name"`
	}
	if err := s.call(ctx, by, "backup.transfer", map[string]any{"account": c.Username, "name": name, "dbs": dbs, "manifest": manifest}, &made); err != nil {
		return fmt.Errorf("archive: %w", err)
	}
	if err := s.call(ctx, by, "transfer.send", map[string]any{"account": c.Username, "name": made.Name, "url": base, "token": token, "fingerprint": fp}, nil); err != nil {
		return err
	}
	var started struct {
		JobID string `json:"job_id"`
	}
	if err := targetCall(ctx, base, token, fp, http.MethodPost, "/api/v1/transfers/"+made.Name+"/import", map[string]string{"username": c.Username}, &started); err != nil {
		return err
	}
	deadline := time.Now().Add(6 * time.Hour)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
		var job struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		}
		if err := targetCall(ctx, base, token, fp, http.MethodGet, "/api/v1/jobs/"+started.JobID, nil, &job); err != nil {
			continue
		}
		switch job.Status {
		case "done":
			_ = s.store.Audit(ctx, by, "local", "transfer.done", "customer:"+c.Username, "moved to "+base)
			if suspend {
				if err := s.setStatus(ctx, by, c, store.StatusSuspended, "moved to "+base); err != nil {
					return fmt.Errorf("moved, but not suspended here: %w", err)
				}
			}
			return nil
		case "failed":
			return errors.New("the target could not import the account: " + job.Error)
		}
	}
	return errors.New("the target did not finish within 6 hours")
}
