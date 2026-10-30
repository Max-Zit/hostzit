package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/auth"
	"github.com/max-zit/hostzit/internal/backup"
)

// Backup of the panel itself: its database and the secret key and
// certificates of the data directory, encrypted with a passphrase. A
// copy is made every night (seven are kept); the administrator can also
// download one. Restore: hostzit-server --restore FILE.

const settingConsoleBackup = "console_backup"

// ConsoleBackupSettings keep the passphrase of the nightly backups.
type ConsoleBackupSettings struct {
	Passphrase string `json:"passphrase"` // sealed
	Keep       int    `json:"keep"`
}

func init() {
	adminExtra = append(adminExtra, func(s *Server, mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc)) {
		admin("GET /settings/backup", s.handleConsoleBackup)
		admin("POST /settings/backup", s.handleConsoleBackupSave)
		admin("POST /settings/backup/download", s.handleConsoleBackupDownload)
	})
}

func (s *Server) consoleBackupDir() string { return filepath.Join(s.DataDir, "backups") }

type consoleBackupData struct {
	HasPass bool
	Keep    int
	Files   []os.FileInfo
	Dir     string
}

func (s *Server) handleConsoleBackup(w http.ResponseWriter, r *http.Request) {
	var cb ConsoleBackupSettings
	_ = s.store.GetSetting(r.Context(), settingConsoleBackup, &cb)
	d := &consoleBackupData{HasPass: cb.Passphrase != "", Keep: max(cb.Keep, 7), Dir: s.consoleBackupDir()}
	ents, _ := os.ReadDir(s.consoleBackupDir())
	for _, e := range ents {
		if fi, err := e.Info(); err == nil && strings.HasSuffix(e.Name(), ".hzb") {
			d.Files = append(d.Files, fi)
		}
	}
	sort.Slice(d.Files, func(i, j int) bool { return d.Files[i].ModTime().After(d.Files[j].ModTime()) })
	s.render(w, r, http.StatusOK, "consolebackup", &Page{Title: "Panel backup", Nav: "settings", Data: d})
}

func (s *Server) handleConsoleBackupSave(w http.ResponseWriter, r *http.Request) {
	pass := r.FormValue("passphrase")
	if pass != r.FormValue("passphrase2") {
		s.redirectErr(w, r, "/settings/backup", "The passphrases do not match.")
		return
	}
	if err := auth.CheckPasswordPolicy(pass); err != nil {
		s.redirectErr(w, r, "/settings/backup", err.Error())
		return
	}
	cb := ConsoleBackupSettings{Passphrase: s.store.SealSecret("console.backup", pass), Keep: 7}
	if err := s.store.SetSetting(r.Context(), settingConsoleBackup, cb); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "backup.console.settings", "settings", "nightly panel backups switched on")
	if _, err := s.consoleBackupNow(r.Context()); err != nil {
		s.redirectErr(w, r, "/settings/backup", err.Error())
		return
	}
	s.redirect(w, r, "/settings/backup", "Saved. The first backup was made; keep the passphrase in a safe place.")
}

// consoleBackupNow writes a backup into the data directory and keeps the newest ones.
func (s *Server) consoleBackupNow(ctx context.Context) (string, error) {
	var cb ConsoleBackupSettings
	if err := s.store.GetSetting(ctx, settingConsoleBackup, &cb); err != nil || cb.Passphrase == "" {
		return "", errors.New("no passphrase set")
	}
	pass, err := s.store.OpenSecret("console.backup", cb.Passphrase)
	if err != nil {
		return "", err
	}
	dir := s.consoleBackupDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := filepath.Join(dir, "hostzit-panel-"+s.now().UTC().Format("20060102-150405")+".hzb")
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- our data directory
	if err != nil {
		return "", err
	}
	_, err = backup.Create(ctx, s.store, s.DataDir, dir, s.Version, pass, f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(name)
		return "", err
	}
	ents, _ := os.ReadDir(dir)
	var names []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".hzb") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for len(names) > max(cb.Keep, 1) {
		_ = os.Remove(filepath.Join(dir, names[0]))
		names = names[1:]
	}
	return name, nil
}

func (s *Server) handleConsoleBackupDownload(w http.ResponseWriter, r *http.Request) {
	pass := r.FormValue("passphrase")
	if err := auth.CheckPasswordPolicy(pass); err != nil {
		s.redirectErr(w, r, "/settings/backup", "The backup passphrase must be at least 12 characters.")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="hostzit-panel-%s.hzb"`, time.Now().UTC().Format("20060102-150405")))
	if _, err := backup.Create(r.Context(), s.store, s.DataDir, os.TempDir(), s.Version, pass, w); err != nil {
		s.log.Error("panel backup failed", "err", err)
		return
	}
	s.audit(r, "backup.console.download", "settings", "panel backup downloaded")
}
