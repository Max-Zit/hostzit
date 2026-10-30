package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/max-zit/hostzit/internal/helper"
	"github.com/max-zit/hostzit/internal/hosting"
	"github.com/max-zit/hostzit/internal/store"
)

// Account backups (customer panel and API) and the cPanel import (admin).

func init() {
	customerExtra = append(customerExtra, func(s *Server, mux *http.ServeMux, c func(string, http.HandlerFunc)) {
		c("GET /backups", s.handleBackups)
		c("POST /backups", s.handleBackupCreate)
		c("POST /backups/delete", s.handleBackupDelete)
	})
	adminExtra = append(adminExtra, func(s *Server, mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc)) {
		admin("GET /import", s.handleImport)
		admin("POST /import", s.handleImportStart)
	})
}

// Manifest describes an account backup (hostzit-manifest.json).
type Manifest struct {
	Product   string                      `json:"product"`
	Version   string                      `json:"version"`
	Customer  map[string]string           `json:"customer"`
	Package   string                      `json:"package"`
	Sites     []hosting.Site              `json:"sites"`
	Zones     map[string][]hosting.Record `json:"zones"`
	Databases []string                    `json:"databases"`
	DBUsers   map[string][]string         `json:"db_users"`
	Cron      []hosting.CronJob           `json:"cron"`
}

// backupAccount makes ~/backups/hostzit-<time>.tar.gz with the files, the
// databases and a manifest of the account's settings.
func (s *Server) backupAccount(ctx context.Context, by string, c *store.Customer) (string, int64, error) {
	name, dbs, manifest := s.backupRequest(ctx, c)
	var res struct {
		File string `json:"file"`
		Size int64  `json:"size"`
	}
	err := s.call(ctx, by, "backup.create", map[string]any{"account": c.Username, "name": name, "dbs": dbs, "manifest": manifest}, &res)
	return res.File, res.Size, err
}

// backupRequest is the archive name, the databases and the manifest of an
// account backup.
func (s *Server) backupRequest(ctx context.Context, c *store.Customer) (name string, dbs []string, manifest string) {
	man := Manifest{Product: "hostzit", Version: s.Version, Package: c.PackageSlug, Zones: map[string][]hosting.Record{}, DBUsers: map[string][]string{},
		Customer: map[string]string{"id": c.UUID, "username": c.Username, "name": c.DisplayName, "email": c.Email}}
	sites, _ := s.store.Sites(ctx, c.ID)
	for _, x := range sites {
		man.Sites = append(man.Sites, x.Spec(false, 0))
	}
	zones, _ := s.store.Zones(ctx, c.ID)
	for _, z := range zones {
		recs, _ := s.store.Records(ctx, z.ID)
		for _, r := range recs {
			man.Zones[z.Name] = append(man.Zones[z.Name], r.Record)
		}
	}
	dbList, _ := s.store.Databases(ctx, c.ID)
	for _, d := range dbList {
		man.Databases = append(man.Databases, d.Name)
	}
	users, _ := s.store.DBUsers(ctx, c.ID)
	for _, u := range users {
		man.DBUsers[u.Name] = u.Databases
	}
	jobs, _ := s.store.CronJobs(ctx, c.ID)
	for _, j := range jobs {
		man.Cron = append(man.Cron, hosting.CronJob{ID: j.ID, Schedule: j.Schedule, Command: j.Command, Enabled: j.Enabled})
	}
	mb, _ := json.MarshalIndent(man, "", "  ")
	name = "hostzit-" + s.now().UTC().Format("20060102-150405")
	return name, man.Databases, string(mb)
}

type backupsData struct {
	Files []helper.FileInfo
}

func (s *Server) handleBackups(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	d := &backupsData{}
	if resp, err := s.worker(r, c, helper.WorkerReq{Op: "list", Path: "backups"}); err == nil {
		for _, f := range resp.Files {
			if !f.Dir {
				d.Files = append(d.Files, f)
			}
		}
	}
	s.render(w, r, http.StatusOK, "backups", &Page{Title: "Backups", Nav: "backups", Customer: c, Data: d})
}

func (s *Server) handleBackupCreate(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	by := actor(r)
	if _, err := s.runJob("backup.create", &c.ID, c.Username, func(ctx context.Context) error {
		f, size, err := s.backupAccount(ctx, by, c)
		if err == nil {
			_ = s.store.Audit(ctx, by, "local", "backup.create", "customer:"+c.Username, fmt.Sprintf("%s (%d bytes)", f, size))
		}
		return err
	}); err != nil {
		s.redirectErr(w, r, "/backups", storeErr(err))
		return
	}
	s.redirect(w, r, "/backups", "The backup is being made. Reload this page in a minute.")
}

var backupFileRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,120}$`)

func (s *Server) handleBackupDelete(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	name := r.FormValue("name")
	if !backupFileRE.MatchString(name) {
		s.notFound(w, r)
		return
	}
	if _, err := s.worker(r, c, helper.WorkerReq{Op: "delete", Path: "backups/" + name}); err != nil {
		s.redirectErr(w, r, "/backups", storeErr(err))
		return
	}
	s.audit(r, "backup.delete", "customer:"+c.Username, "%s deleted", name)
	s.redirect(w, r, "/backups", "Deleted.")
}

// ---- cPanel import (admin)

type importData struct {
	Files    []helper.ImportFile
	Packages []*store.Package
	Err      string
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	d := &importData{}
	if err := s.call(r.Context(), actor(r), "import.list", struct{}{}, &d.Files); err != nil {
		d.Err = storeErr(err)
	}
	d.Packages, _ = s.store.Packages(r.Context())
	s.render(w, r, http.StatusOK, "import", &Page{Title: "Import", Nav: "import", Data: d})
}

func (s *Server) handleImportStart(w http.ResponseWriter, r *http.Request) {
	file := r.FormValue("file")
	user := strings.ToLower(strings.TrimSpace(r.FormValue("username")))
	if user == "" {
		user = strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(file, "cpmove-"), ".tar.gz"), ".tgz")
	}
	if err := hosting.ValidAccount(user); err != nil {
		s.redirectErr(w, r, "/import", err.Error())
		return
	}
	pkg, _ := strconv.ParseInt(r.FormValue("package"), 10, 64)
	by := actor(r)
	j, err := s.runJob("import.cpanel", nil, file+" → "+user, func(ctx context.Context) error {
		rep, err := s.importCPanel(ctx, by, file, user, pkg)
		if err != nil {
			return err
		}
		detail := fmt.Sprintf("%s → %s: %d websites, %d DNS zones, %d databases, %d database users, %d cron jobs", file, user, rep.Sites, rep.Zones, rep.DBs, rep.Users, rep.Cron)
		if len(rep.Notes) > 0 {
			detail += ". Notes: " + strings.Join(rep.Notes, "; ")
		}
		_ = s.store.Audit(ctx, by, "local", "import.cpanel", "customer:"+user, detail)
		return nil
	})
	if err != nil {
		s.redirectErr(w, r, "/import", storeErr(err))
		return
	}
	s.audit(r, "import.start", "customer:"+user, "cPanel import of %s started (job %s)", file, j.ID)
	s.redirect(w, r, "/jobs", "The import was started. The result is in the audit log.")
}

func init() {
	apiExtra = append(apiExtra, func(s *Server, need func(scope, pattern string, h http.HandlerFunc)) {
		need("customers:write", "POST /api/v1/customers/{id}/export", s.apiExport)
		need("customers:read", "GET /api/v1/customers/{id}/backups", s.apiBackups)
	})
}

// apiExport makes an account backup in ~/backups (BackupZit or the portal
// fetch it with SFTP or through the agent).
func (s *Server) apiExport(w http.ResponseWriter, r *http.Request) {
	c := s.apiLoad(w, r)
	if c == nil {
		return
	}
	by := apiActor(r)
	j, err := s.runJob("backup.create", &c.ID, c.Username, func(ctx context.Context) error {
		f, size, err := s.backupAccount(ctx, by, c)
		if err == nil {
			_ = s.store.Audit(ctx, by, "api", "backup.create", "customer:"+c.Username, fmt.Sprintf("%s (%d bytes)", f, size))
		}
		return err
	})
	if err != nil {
		apiFail(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job_id": j.ID, "status": j.Status})
}

func (s *Server) apiBackups(w http.ResponseWriter, r *http.Request) {
	c := s.apiLoad(w, r)
	if c == nil {
		return
	}
	var resp helper.WorkerResp
	_ = s.call(r.Context(), apiActor(r), "files", map[string]any{"account": c.Username, "req": helper.WorkerReq{Op: "list", Path: "backups"}}, &resp)
	items := []map[string]any{}
	for _, f := range resp.Files {
		if !f.Dir {
			items = append(items, map[string]any{"name": f.Name, "size": f.Size, "time": f.ModTime, "path": "~/backups/" + f.Name})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
