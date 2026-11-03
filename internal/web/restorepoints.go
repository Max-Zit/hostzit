package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/helper"
	"github.com/max-zit/hostzit/internal/store"
)

// Restore points: the nightly backups of the server are
// restic snapshots per account. Customers (and administrators through the
// customer panel) list them, browse the files and put back files and
// folders, databases, DNS zones and scheduled jobs.

// rbDest is the backup destination with its secrets readable, when the
// backups are switched on.
func (s *Server) rbDest(ctx context.Context) (helper.RemoteDest, bool) {
	rb := s.remoteBackup(ctx)
	if !rb.Enabled {
		return helper.RemoteDest{}, false
	}
	d, err := s.openDest(rb)
	return d, err == nil
}

func init() {
	customerExtra = append(customerExtra, func(s *Server, mux *http.ServeMux, c func(string, http.HandlerFunc)) {
		c("POST /backups/now", s.handleRestorePointNow)
		c("GET /backups/points/{snap}", s.handleRestorePoint)
		c("POST /backups/points/{snap}/files", s.handleRestoreFiles)
		c("POST /backups/points/{snap}/db", s.handleRestoreDB)
		c("POST /backups/points/{snap}/zone", s.handleRestoreZone)
		c("POST /backups/points/{snap}/cron", s.handleRestoreCron)
	})
}

// restorePoints lists the customer's restore points ("" error when backups are off).
func (s *Server) restorePoints(ctx context.Context, c *store.Customer) ([]helper.RestorePoint, bool, error) {
	d, ok := s.rbDest(ctx)
	if !ok {
		return nil, false, nil
	}
	var pts []helper.RestorePoint
	err := s.call(ctx, "system", "rbackup.points", map[string]any{"dest": d, "account": c.Username}, &pts)
	return pts, true, err
}

// handleRestorePointNow makes a restore point of the account now (at most once an hour).
func (s *Server) handleRestorePointNow(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	d, ok := s.rbDest(r.Context())
	if !ok {
		s.redirectErr(w, r, "/backups", "The server's backups are switched off.")
		return
	}
	if !s.store.NoticeDue(r.Context(), "rbnow:"+c.Username, time.Hour) {
		s.redirectErr(w, r, "/backups", "A restore point was made less than an hour ago.")
		return
	}
	by := actor(r)
	if _, err := s.runJob("backup.point", &c.ID, c.Username, func(ctx context.Context) error {
		return s.backupPoint(ctx, by, d, c)
	}); err != nil {
		s.redirectErr(w, r, "/backups", storeErr(err))
		return
	}
	s.audit(r, "backup.point", "customer:"+c.Username, "restore point requested")
	s.redirect(w, r, "/backups", "The restore point is being made; it appears here in a few minutes.")
}

// backupPoint makes one restore point of an account.
func (s *Server) backupPoint(ctx context.Context, by string, d helper.RemoteDest, c *store.Customer) error {
	_, dbs, manifest := s.backupRequest(ctx, c)
	cctx, cancel := context.WithTimeout(ctx, 6*time.Hour)
	defer cancel()
	return s.call(cctx, by, "rbackup.run", map[string]any{"dest": d, "account": c.Username, "dbs": dbs, "manifest": manifest}, nil)
}

type restorePointData struct {
	ID, Short string
	Time      time.Time
	Path      string
	Crumbs    []crumb
	Entries   []helper.RestoreEntry
	DBs       []restoreDB
	Zones     []string
	Cron      int
	Err       string
}

type restoreDB struct {
	Name   string
	Exists bool
}

// point loads the restore point of the request (it must belong to the customer).
func (s *Server) point(w http.ResponseWriter, r *http.Request, c *store.Customer) (helper.RemoteDest, *helper.RestorePoint) {
	d, ok := s.rbDest(r.Context())
	if !ok {
		s.redirectErr(w, r, "/backups", "The server's backups are switched off.")
		return d, nil
	}
	pts, _, err := s.restorePoints(r.Context(), c)
	if err != nil {
		s.redirectErr(w, r, "/backups", storeErr(err))
		return d, nil
	}
	id := r.PathValue("snap")
	for i := range pts {
		if pts[i].ID == id {
			return d, &pts[i]
		}
	}
	s.notFound(w, r)
	return d, nil
}

func (s *Server) handleRestorePoint(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	d, p := s.point(w, r, c)
	if p == nil {
		return
	}
	ctx := r.Context()
	rel := strings.Trim(path.Clean("/"+r.URL.Query().Get("path")), "/")
	v := &restorePointData{ID: p.ID, Short: p.ID[:8], Time: p.Time, Path: rel}
	acc := ""
	for _, part := range strings.Split(rel, "/") {
		if part == "" {
			continue
		}
		acc = strings.TrimPrefix(acc+"/"+part, "/")
		v.Crumbs = append(v.Crumbs, crumb{Name: part, Path: acc})
	}
	args := map[string]any{"dest": d, "account": c.Username, "snapshot": p.ID, "path": rel}
	if err := s.call(ctx, "system", "rbackup.ls", args, &v.Entries); err != nil {
		v.Err = storeErr(err)
	}
	if rel == "" {
		var names []string
		_ = s.call(ctx, "system", "rbackup.dbs", args, &names)
		mine, _ := s.store.Databases(ctx, c.ID)
		for _, n := range names {
			ex := slices.ContainsFunc(mine, func(x *store.Database) bool { return x.Name == n })
			v.DBs = append(v.DBs, restoreDB{Name: n, Exists: ex})
		}
		if m, err := s.pointManifest(ctx, d, c, p.ID); err == nil {
			for z := range m.Zones {
				v.Zones = append(v.Zones, z)
			}
			slices.Sort(v.Zones)
			v.Cron = len(m.Cron)
		}
	}
	s.render(w, r, http.StatusOK, "restorepoint", &Page{Title: "Restore point", Nav: "backups", Customer: c, Crumb: "Backups", CrumbURL: "/backups", Data: v})
}

func (s *Server) pointManifest(ctx context.Context, d helper.RemoteDest, c *store.Customer, snap string) (*Manifest, error) {
	var res struct {
		Manifest string `json:"manifest"`
	}
	if err := s.call(ctx, "system", "rbackup.manifest", map[string]any{"dest": d, "account": c.Username, "snapshot": snap}, &res); err != nil {
		return nil, err
	}
	var m Manifest
	return &m, json.Unmarshal([]byte(res.Manifest), &m)
}

func pointURL(snap, rel string) string {
	u := "/backups/points/" + snap
	if rel != "" {
		u += "?path=" + url.QueryEscape(rel)
	}
	return u
}

// handleRestoreFiles puts a file or folder back (in the background).
func (s *Server) handleRestoreFiles(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	d, p := s.point(w, r, c)
	if p == nil {
		return
	}
	rel := strings.Trim(path.Clean("/"+r.FormValue("path")), "/")
	toFolder := r.FormValue("to") != "place"
	by := actor(r)
	if _, err := s.runJob("backup.restore", &c.ID, c.Username+" "+rel, func(ctx context.Context) error {
		return s.call(ctx, by, "rbackup.restore.files", map[string]any{"dest": d, "account": c.Username, "snapshot": p.ID, "path": rel, "to_folder": toFolder}, nil)
	}); err != nil {
		s.redirectErr(w, r, pointURL(p.ID, path.Dir(rel)), storeErr(err))
		return
	}
	where := "into its place"
	if toFolder {
		where = "into ~/restored-…"
	}
	s.audit(r, "backup.restore", "customer:"+c.Username, "restore point %s: /%s %s", p.ID[:8], rel, where)
	msg := "The restore runs in the background; the files are back in their place in a minute."
	if toFolder {
		msg = "The restore runs in the background; the files appear in a folder restored-DATE in your home."
	}
	s.redirect(w, r, pointURL(p.ID, parentRel(rel)), msg)
}

func parentRel(rel string) string {
	if p := path.Dir(rel); p != "." {
		return p
	}
	return ""
}

// handleRestoreDB loads a database of the restore point back (replaces its tables).
func (s *Server) handleRestoreDB(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	d, p := s.point(w, r, c)
	if p == nil {
		return
	}
	db := r.FormValue("db")
	mine, _ := s.store.Databases(r.Context(), c.ID)
	if !slices.ContainsFunc(mine, func(x *store.Database) bool { return x.Name == db }) {
		s.redirectErr(w, r, pointURL(p.ID, ""), "Create the database again first (Databases), then restore it.")
		return
	}
	by := actor(r)
	if _, err := s.runJob("backup.restore", &c.ID, c.Username+" "+db, func(ctx context.Context) error {
		return s.call(ctx, by, "rbackup.restore.db", map[string]any{"dest": d, "account": c.Username, "snapshot": p.ID, "db": db}, nil)
	}); err != nil {
		s.redirectErr(w, r, pointURL(p.ID, ""), storeErr(err))
		return
	}
	s.audit(r, "backup.restore", "customer:"+c.Username, "restore point %s: database %s", p.ID[:8], db)
	s.redirect(w, r, pointURL(p.ID, ""), "The database is being restored; it is done in a minute (see Jobs on the overview).")
}

// handleRestoreZone puts the customer's records of a DNS zone back.
func (s *Server) handleRestoreZone(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	d, p := s.point(w, r, c)
	if p == nil {
		return
	}
	back := pointURL(p.ID, "")
	m, err := s.pointManifest(r.Context(), d, c, p.ID)
	if err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	name := r.FormValue("zone")
	recs, ok := m.Zones[name]
	z, zerr := s.store.ZoneByName(r.Context(), name)
	if !ok || zerr != nil || z.CustomerID != c.ID {
		s.redirectErr(w, r, back, "The zone is not in your account any more: add the domain again first.")
		return
	}
	if err := s.store.ReplaceRecords(r.Context(), z, recs); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	if err := s.applyZone(r.Context(), actor(r), z); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.audit(r, "backup.restore", "zone:"+name, "records restored from restore point %s", p.ID[:8])
	s.redirect(w, r, back, "The DNS records were restored.")
}

// handleRestoreCron replaces the scheduled jobs with those of the restore point.
func (s *Server) handleRestoreCron(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	d, p := s.point(w, r, c)
	if p == nil {
		return
	}
	back := pointURL(p.ID, "")
	m, err := s.pointManifest(r.Context(), d, c, p.ID)
	if err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	old, _ := s.store.CronJobs(r.Context(), c.ID)
	for _, j := range old {
		_ = s.store.DeleteCronJob(r.Context(), c.ID, j.ID)
	}
	for _, j := range m.Cron {
		_ = s.store.AddCronJob(r.Context(), &store.CronJob{CustomerID: c.ID, Schedule: j.Schedule, Command: j.Command, Enabled: j.Enabled})
	}
	if err := s.applyCron(r.Context(), actor(r), c); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.audit(r, "backup.restore", "customer:"+c.Username, "%d scheduled jobs restored from restore point %s", len(m.Cron), p.ID[:8])
	s.redirect(w, r, back, "The scheduled jobs were restored.")
}
