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

// Remote backups (like cPanel's Backup Configuration): every night each
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
	Keep      int       `json:"keep"`
	LastRun   time.Time `json:"last_run"`
	LastOK    int       `json:"last_ok"`
	LastFail  int       `json:"last_fail"`
	LastError string    `json:"last_error"`
	Running   bool      `json:"running"`
}

func (s *Server) remoteBackup(ctx context.Context) RemoteBackup {
	rb := RemoteBackup{Hour: 2, Keep: 7, Dest: helper.RemoteDest{Type: "sftp", Port: 22, Path: "hostzit"}}
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
		admin("GET /customers/{id}/remote-backups", s.handleRemoteBackupList)
		admin("POST /customers/{id}/remote-backups/fetch", s.handleRemoteBackupFetch)
	})
}

type remoteBackupData struct {
	R           RemoteBackup
	HasPassword bool
	HasSecret   bool
}

func (s *Server) handleRemoteBackup(w http.ResponseWriter, r *http.Request) {
	rb := s.remoteBackup(r.Context())
	d := &remoteBackupData{R: rb, HasPassword: rb.Dest.Password != "", HasSecret: rb.Dest.SecretKey != ""}
	d.R.Dest.Password, d.R.Dest.SecretKey, d.R.Dest.Key = "", "", ""
	p := &Page{Title: "Remote backups", Nav: "settings", Data: d}
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
	if d.Type != "sftp" && d.Type != "s3" {
		s.redirectErr(w, r, "/settings/remote-backup", "Choose SFTP or S3.")
		return
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
	var res struct {
		HostKey string `json:"host_key"`
	}
	err = s.call(r.Context(), actor(r), "backup.remote.test", map[string]any{"dest": d}, &res)
	if res.HostKey != "" && rb.Dest.HostKey == "" {
		rb.Dest.HostKey = res.HostKey
		_ = s.store.SetSetting(r.Context(), settingRemoteBackup, rb)
	}
	if err != nil {
		s.redirectErr(w, r, "/settings/remote-backup", storeErr(err))
		return
	}
	s.redirect(w, r, "/settings/remote-backup", "The connection works: a test file was written and deleted.")
}

func (s *Server) handleRemoteBackupRun(w http.ResponseWriter, r *http.Request) {
	go s.remoteBackupRound(context.WithoutCancel(r.Context()), true)
	s.audit(r, "backup.remote", "server", "remote backup of all accounts started")
	s.redirect(w, r, "/settings/remote-backup", "The backup was started. It runs in the background; this page shows the result.")
}

var remoteBackupMu sync.Mutex

// remoteBackupRound backs up every active account when it is time (or now).
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
	customers, _ := s.store.Customers(ctx, store.CustomerFilter{Status: store.StatusActive})
	for _, c := range customers {
		name, dbs, manifest := s.backupRequest(ctx, c)
		var res struct {
			HostKey string `json:"host_key"`
		}
		cctx, cancel := context.WithTimeout(ctx, 6*time.Hour)
		err := s.call(cctx, "system", "backup.remote", map[string]any{"account": c.Username, "name": name, "dbs": dbs, "manifest": manifest, "dest": dest, "keep": rb.Keep}, &res)
		cancel()
		if res.HostKey != "" && dest.HostKey == "" {
			dest.HostKey, rb.Dest.HostKey = res.HostKey, res.HostKey
		}
		if err != nil {
			rb.LastFail++
			rb.LastError = c.Username + ": " + storeErr(err)
			_ = s.store.Audit(ctx, "system", "local", "backup.remote", "customer:"+c.Username, "remote backup failed: "+storeErr(err))
		} else {
			rb.LastOK++
		}
	}
	rb.Running = false
	_ = s.store.SetSetting(ctx, settingRemoteBackup, rb)
	_ = s.store.Audit(ctx, "system", "local", "backup.remote", "server", fmt.Sprintf("remote backups: %d done, %d failed", rb.LastOK, rb.LastFail))
	if rb.LastFail > 0 {
		s.notify(ctx, "remote-backup", nil, "Remote backups failed", fmt.Sprintf("%d of %d accounts could not be backed up. Last error: %s", rb.LastFail, rb.LastOK+rb.LastFail, rb.LastError))
	}
}

type remoteListData struct {
	C     *store.Customer
	Files []remoteFile
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
