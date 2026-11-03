package web

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/max-zit/hostzit/internal/helper"
	"github.com/max-zit/hostzit/internal/store"
)

// Remote backups: every night each
// active account is archived (files, databases, settings) and uploaded to
// an SFTP server or an S3 bucket; the newest N per account are kept. A
// backup is restored by fetching it into the import folder (Import page).

const settingRemoteBackup = "remotebackup"

// RemoteBackup are the settings; secrets are sealed.
type RemoteBackup struct {
	Enabled bool              `json:"enabled"`
	Dest    helper.RemoteDest `json:"dest"`
	// PublicKey is the SFTP key of this server (its private part is sealed
	// in Dest.Key).
	PublicKey string    `json:"public_key"`
	Hour      int       `json:"hour"`
	Keep      int       `json:"keep"` // daily restore points
	KeepWeek  int       `json:"keep_weekly"`
	KeepMonth int       `json:"keep_monthly"`
	LastRun   time.Time `json:"last_run"`
	LastOK    int       `json:"last_ok"`
	LastFail  int       `json:"last_fail"`
	LastError string    `json:"last_error"`
	Running   bool      `json:"running"`
}

func (s *Server) remoteBackup(ctx context.Context) RemoteBackup {
	rb := RemoteBackup{Hour: 2, Keep: 7, KeepWeek: 4, KeepMonth: 3, Dest: helper.RemoteDest{Type: "local", Port: 22, Path: "/var/backups/hostzit"}}
	_ = s.store.GetSetting(ctx, settingRemoteBackup, &rb)
	return rb
}

// openDest is the destination with its secrets readable (for the helper).
func (s *Server) openDest(rb RemoteBackup) (helper.RemoteDest, error) {
	d := rb.Dest
	var err error
	for _, f := range []struct {
		p    *string
		name string
	}{{&d.Password, "remotebackup.password"}, {&d.Key, "remotebackup.key"}, {&d.SecretKey, "remotebackup.secret"}} {
		if *f.p != "" {
			if *f.p, err = s.store.OpenSecret(f.name, *f.p); err != nil {
				return d, err
			}
		}
	}
	return d, nil
}

func init() {
	adminExtra = append(adminExtra, func(s *Server, mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc)) {
		admin("GET /settings/remote-backup", s.handleRemoteBackup)
		admin("POST /settings/remote-backup", s.handleRemoteBackupSave)
		admin("POST /settings/remote-backup/test", s.handleRemoteBackupTest)
		admin("POST /settings/remote-backup/run", s.handleRemoteBackupRun)
		admin("POST /settings/remote-backup/key", s.handleRemoteBackupKey)
		admin("GET /customers/{id}/remote-backups", s.handleRemoteBackupList)
		admin("POST /customers/{id}/remote-backups/fetch", s.handleRemoteBackupFetch)
		admin("POST /customers/{id}/remote-backups/now", s.handleAdminPointNow)
	})
}

type remoteBackupData struct {
	R           RemoteBackup
	HasPassword bool
	HasSecret   bool
	Key         string // the repository key, when asked for
}

func (s *Server) handleRemoteBackup(w http.ResponseWriter, r *http.Request) {
	rb := s.remoteBackup(r.Context())
	d := &remoteBackupData{R: rb, HasPassword: rb.Dest.Password != "", HasSecret: rb.Dest.SecretKey != ""}
	d.R.Dest.Password, d.R.Dest.SecretKey, d.R.Dest.Key = "", "", ""
	p := &Page{Title: "Backups", Nav: "settings", Data: d}
	if rb.Running {
		p.Refresh = 20
	}
	s.render(w, r, http.StatusOK, "remotebackup", p)
}

func (s *Server) handleRemoteBackupSave(w http.ResponseWriter, r *http.Request) {
	rb := s.remoteBackup(r.Context())
	old := rb.Dest
	d := helper.RemoteDest{Type: r.FormValue("type"), Host: strings.TrimSpace(r.FormValue("host")), User: strings.TrimSpace(r.FormValue("user")),
		Endpoint: strings.TrimRight(strings.TrimSpace(r.FormValue("endpoint")), "/"), Region: strings.TrimSpace(r.FormValue("region")),
		Bucket: strings.TrimSpace(r.FormValue("bucket")), AccessKey: strings.TrimSpace(r.FormValue("access_key")),
		Path: strings.Trim(strings.TrimSpace(r.FormValue("path")), "/")}
	d.Port, _ = strconv.Atoi(r.FormValue("port"))
	if d.Port == 0 {
		d.Port = 22
	}
	if d.Type != "sftp" && d.Type != "s3" && d.Type != "local" {
		s.redirectErr(w, r, "/settings/remote-backup", "Choose a folder on this server, SFTP or S3.")
		return
	}
	if d.Type == "local" {
		d.Path = "/" + d.Path
		if d.Path == "/" || strings.HasPrefix(d.Path, "/home") {
			s.redirectErr(w, r, "/settings/remote-backup", "Choose another folder for the backups (not / or /home).")
			return
		}
	}
	if d.Endpoint != "" && !strings.HasPrefix(d.Endpoint, "https://") && !strings.HasPrefix(d.Endpoint, "http://") {
		s.redirectErr(w, r, "/settings/remote-backup", "The address must start with https://")
		return
	}
	if strings.Contains(d.Path, "..") {
		s.redirectErr(w, r, "/settings/remote-backup", "Invalid name.")
		return
	}
	// secrets: a new value replaces the old, empty keeps it
	d.Password, d.SecretKey, d.Key = old.Password, old.SecretKey, old.Key
	if v := r.FormValue("password"); v != "" {
		d.Password = s.store.SealSecret("remotebackup.password", v)
	}
	if v := r.FormValue("secret_key"); v != "" {
		d.SecretKey = s.store.SealSecret("remotebackup.secret", v)
	}
	// a different server: its host key is learned again
	if d.Host == old.Host && d.Port == old.Port {
		d.HostKey = old.HostKey
	}
	if d.Type == "sftp" && d.Key == "" {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		blk, err := ssh.MarshalPrivateKey(priv, "hostzit-backup")
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		sp, _ := ssh.NewPublicKey(pub)
		rb.PublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))) + " hostzit-backup"
		d.Key = s.store.SealSecret("remotebackup.key", string(pem.EncodeToMemory(blk)))
	}
	rb.Dest = d
	rb.Enabled = r.FormValue("enabled") != ""
	rb.Hour = min(max(formInt(r, "hour"), 0), 23)
	rb.Keep = min(max(formInt(r, "keep"), 1), 365)
	rb.KeepWeek = min(max(formInt(r, "keep_weekly"), 0), 104)
	rb.KeepMonth = min(max(formInt(r, "keep_monthly"), 0), 120)
	if err := s.store.SetSetting(r.Context(), settingRemoteBackup, rb); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.remotebackup", "settings", "remote backups %v: %s %s%s/%s, at %d:00, keep %d", rb.Enabled, d.Type, d.Host, d.Endpoint, d.Path, rb.Hour, rb.Keep)
	s.redirect(w, r, "/settings/remote-backup", "Saved.")
}

func (s *Server) handleRemoteBackupTest(w http.ResponseWriter, r *http.Request) {
	rb := s.remoteBackup(r.Context())
	d, err := s.openDest(rb)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	// installs restic when needed and creates the repository
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	if err := s.call(ctx, actor(r), "rbackup.init", map[string]any{"dest": d}, nil); err != nil {
		s.redirectErr(w, r, "/settings/remote-backup", storeErr(err))
		return
	}
	s.redirect(w, r, "/settings/remote-backup", "The connection works and the backup repository is ready.")
}

func (s *Server) handleRemoteBackupRun(w http.ResponseWriter, r *http.Request) {
	go s.remoteBackupRound(context.WithoutCancel(r.Context()), true)
	s.audit(r, "backup.remote", "server", "backup of all accounts started")
	s.redirect(w, r, "/settings/remote-backup", "The backup was started. It runs in the background; this page shows the result.")
}

// handleRemoteBackupKey shows the repository key: needed to restore the
// backups on another server when this one is lost.
func (s *Server) handleRemoteBackupKey(w http.ResponseWriter, r *http.Request) {
	var res struct {
		Key string `json:"key"`
	}
	if err := s.call(r.Context(), actor(r), "rbackup.key", nil, &res); err != nil {
		s.redirectErr(w, r, "/settings/remote-backup", storeErr(err))
		return
	}
	s.audit(r, "backup.key", "settings", "backup repository key shown")
	rb := s.remoteBackup(r.Context())
	d := &remoteBackupData{R: rb, HasPassword: rb.Dest.Password != "", HasSecret: rb.Dest.SecretKey != "", Key: res.Key}
	d.R.Dest.Password, d.R.Dest.SecretKey, d.R.Dest.Key = "", "", ""
	s.render(w, r, http.StatusOK, "remotebackup", &Page{Title: "Backups", Nav: "settings", Data: d})
}

var remoteBackupMu sync.Mutex

// remoteBackupRound makes a restore point of every active account when it
// is time (or now), then removes the ones beyond the retention.
func (s *Server) remoteBackupRound(ctx context.Context, now bool) {
	if !remoteBackupMu.TryLock() {
		return
	}
	defer remoteBackupMu.Unlock()
	rb := s.remoteBackup(ctx)
	if !now && (!rb.Enabled || s.now().Hour() != rb.Hour || s.now().Sub(rb.LastRun) < 20*time.Hour) {
		return
	}
	dest, err := s.openDest(rb)
	if err != nil {
		return
	}
	rb.Running, rb.LastRun, rb.LastOK, rb.LastFail, rb.LastError = true, s.now(), 0, 0, ""
	_ = s.store.SetSetting(ctx, settingRemoteBackup, rb)
	finish := func() {
		rb.Running = false
		_ = s.store.SetSetting(ctx, settingRemoteBackup, rb)
		_ = s.store.Audit(ctx, "system", "local", "backup.remote", "server", fmt.Sprintf("backups: %d done, %d failed", rb.LastOK, rb.LastFail))
		if rb.LastFail > 0 {
			s.notify(ctx, "remote-backup", nil, "Backups failed", fmt.Sprintf("%d of %d accounts could not be backed up. Last error: %s", rb.LastFail, rb.LastOK+rb.LastFail, rb.LastError))
		}
	}
	if err := s.call(ctx, "system", "rbackup.init", map[string]any{"dest": dest}, nil); err != nil {
		rb.LastFail, rb.LastError = 1, storeErr(err)
		finish()
		return
	}
	customers, _ := s.store.Customers(ctx, store.CustomerFilter{Status: store.StatusActive})
	for _, c := range customers {
		if err := s.backupPoint(ctx, "system", dest, c); err != nil {
			rb.LastFail++
			rb.LastError = c.Username + ": " + storeErr(err)
			_ = s.store.Audit(ctx, "system", "local", "backup.remote", "customer:"+c.Username, "backup failed: "+storeErr(err))
		} else {
			rb.LastOK++
		}
	}
	if err := s.call(ctx, "system", "rbackup.forget", map[string]any{"dest": dest, "daily": rb.Keep, "weekly": rb.KeepWeek, "monthly": rb.KeepMonth}, nil); err != nil {
		rb.LastError = "retention: " + storeErr(err)
		rb.LastFail++
	}
	finish()
}

type remoteListData struct {
	C         *store.Customer
	Files     []remoteFile
	PointsOn  bool
	Points    []helper.RestorePoint
	PointsErr string
}

type remoteFile struct {
	Key  string    `json:"key"`
	Size int64     `json:"size"`
	Time time.Time `json:"time"`
}

func (s *Server) handleRemoteBackupList(w http.ResponseWriter, r *http.Request) {
	c := s.loadCustomer(w, r)
	if c == nil {
		return
	}
	d := &remoteListData{C: c}
	var perr error
	if d.Points, d.PointsOn, perr = s.restorePoints(r.Context(), c); perr != nil {
		d.PointsErr = storeErr(perr)
	}
	p := &Page{Title: c.Username, Nav: "customers", Crumb: "Customers", CrumbURL: "/customers", Data: d}
	dest, err := s.openDest(s.remoteBackup(r.Context()))
	if err == nil {
		err = s.call(r.Context(), actor(r), "backup.remote.list", map[string]any{"dest": dest, "account": c.Username}, &d.Files)
	}
	if err != nil {
		p.Error = storeErr(err)
	}
	for i, j := 0, len(d.Files)-1; i < j; i, j = i+1, j-1 {
		d.Files[i], d.Files[j] = d.Files[j], d.Files[i]
	}
	s.render(w, r, http.StatusOK, "remotelist", p)
}

func (s *Server) handleRemoteBackupFetch(w http.ResponseWriter, r *http.Request) {
	c := s.loadCustomer(w, r)
	if c == nil {
		return
	}
	back := fmt.Sprintf("/customers/%d/remote-backups", c.ID)
	dest, err := s.openDest(s.remoteBackup(r.Context()))
	var res struct {
		File string `json:"file"`
	}
	if err == nil {
		err = s.call(r.Context(), actor(r), "backup.remote.fetch", map[string]any{"dest": dest, "account": c.Username, "key": r.FormValue("key")}, &res)
	}
	if err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.audit(r, "backup.remote.fetch", "customer:"+c.Username, "fetched %s into the import folder", r.FormValue("key"))
	s.redirect(w, r, "/import", "The backup was fetched into the import folder; restore it here.")
}

// handleAdminPointNow makes a restore point of one account now.
func (s *Server) handleAdminPointNow(w http.ResponseWriter, r *http.Request) {
	c := s.loadCustomer(w, r)
	if c == nil {
		return
	}
	back := fmt.Sprintf("/customers/%d/remote-backups", c.ID)
	d, ok := s.rbDest(r.Context())
	if !ok {
		s.redirectErr(w, r, back, "The server's backups are switched off.")
		return
	}
	by := actor(r)
	if _, err := s.runJob("backup.point", &c.ID, c.Username, func(ctx context.Context) error {
		return s.backupPoint(ctx, by, d, c)
	}); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.audit(r, "backup.point", "customer:"+c.Username, "restore point requested by an administrator")
	s.redirect(w, r, back, "The restore point is being made; it appears here in a few minutes.")
}
