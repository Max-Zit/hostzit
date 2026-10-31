package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/auth"
	"github.com/max-zit/hostzit/internal/helper"
	"github.com/max-zit/hostzit/internal/hosting"
	"github.com/max-zit/hostzit/internal/store"
)

// The WordPress toolkit: install, find existing installs, check and run
// updates (with a snapshot before), one-click sign-in to wp-admin,
// hardening, snapshots and restore, automatic updates.

func init() {
	customerExtra = append(customerExtra, func(s *Server, mux *http.ServeMux, c func(string, http.HandlerFunc)) {
		c("GET /wordpress", s.handleWPList)
		c("POST /wordpress/scan", s.handleWPScan)
		c("GET /wordpress/new", s.handleWPForm)
		c("POST /wordpress/new", s.handleWPInstall)
		c("GET /wordpress/{id}", s.handleWP)
		c("POST /wordpress/{id}/check", s.handleWPCheck)
		c("POST /wordpress/{id}/update", s.handleWPUpdate)
		c("POST /wordpress/{id}/login", s.handleWPLogin)
		c("POST /wordpress/{id}/harden", s.handleWPHarden)
		c("POST /wordpress/{id}/auto", s.handleWPAuto)
		c("POST /wordpress/{id}/snapshot", s.handleWPSnapshot)
		c("POST /wordpress/{id}/snapshots/{sid}/restore", s.handleWPRestore)
		c("POST /wordpress/{id}/snapshots/{sid}/delete", s.handleWPSnapshotDelete)
		c("POST /wordpress/{id}/forget", s.handleWPForget)
	})
}

func (s *Server) wpcli(ctx context.Context, by, account, path, secret string, args ...string) (helper.WPResult, error) {
	var res helper.WPResult
	err := s.call(ctx, by, "wp", map[string]any{"account": account, "path": path, "args": args}, &res)
	if secret != "" {
		// WP-CLI repeats its command line in some messages
		res.Output = strings.ReplaceAll(res.Output, secret, "…")
		if err != nil {
			err = errors.New(strings.ReplaceAll(err.Error(), secret, "…"))
		}
	}
	if err == nil && !res.OK {
		err = errors.New(lastLines(res.Output, 3))
	}
	return res, err
}

func lastLines(s string, n int) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, " ")
}

type wpListData struct {
	Installs []*store.WPInstall
	Sites    []*store.Site
}

func (s *Server) handleWPList(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	d := &wpListData{}
	d.Installs, _ = s.store.WPInstalls(r.Context(), c.ID)
	d.Sites, _ = s.store.Sites(r.Context(), c.ID)
	s.render(w, r, http.StatusOK, "wordpress", &Page{Title: "WordPress", Nav: "wordpress", Customer: c, Data: d})
}

// handleWPScan finds WordPress in the document roots (uploaded by SFTP or
// imported from cPanel).
func (s *Server) handleWPScan(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	sites, _ := s.store.Sites(r.Context(), c.ID)
	n := 0
	for _, x := range sites {
		if _, err := s.store.WPInstallForSite(r.Context(), x.ID); err == nil {
			continue
		}
		if _, err := s.worker(r, c, helper.WorkerReq{Op: "stat", Path: x.DocRoot + "/wp-config.php"}); err != nil {
			continue
		}
		in := &store.WPInstall{SiteID: x.ID, Path: x.DocRoot}
		if res, err := s.wpcli(r.Context(), actor(r), c.Username, x.DocRoot, "", "core", "version"); err == nil {
			in.Version = strings.TrimSpace(res.Output)
		}
		if res, err := s.wpcli(r.Context(), actor(r), c.Username, x.DocRoot, "", "config", "get", "DB_NAME"); err == nil {
			in.DBName = strings.TrimSpace(res.Output)
		}
		if err := s.store.AddWPInstall(r.Context(), in); err == nil {
			n++
			if !x.WordPress {
				x.WordPress = true
				if s.store.SaveSite(r.Context(), x) == nil {
					_ = s.applySite(r.Context(), actor(r), x, false)
				}
			}
		}
	}
	s.audit(r, "wp.scan", "customer:"+c.Username, "%d WordPress sites found", n)
	s.redirect(w, r, "/wordpress", translate(s.lang(r, userFrom(r)), "%d WordPress sites found.", n))
}

type wpFormData struct {
	Sites []*store.Site
	F     map[string]string
}

func (s *Server) wpFreeSites(ctx context.Context, c *store.Customer) []*store.Site {
	sites, _ := s.store.Sites(ctx, c.ID)
	var free []*store.Site
	for _, x := range sites {
		if _, err := s.store.WPInstallForSite(ctx, x.ID); err != nil {
			free = append(free, x)
		}
	}
	return free
}

func (s *Server) handleWPForm(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	f := map[string]string{"site": r.FormValue("site"), "lang": wpLocale(s.lang(r, userFrom(r))), "email": c.Email, "user": "admin"}
	s.render(w, r, http.StatusOK, "wpform", &Page{Title: "Install WordPress", Nav: "wordpress", Customer: c, Crumb: "WordPress", CrumbURL: "/wordpress",
		Data: &wpFormData{Sites: s.wpFreeSites(r.Context(), c), F: f}})
}

var wpLocales = map[string]string{"en": "en_US", "de": "de_DE", "fr": "fr_FR", "es": "es_ES", "it": "it_IT", "pt": "pt_PT", "nl": "nl_NL", "pl": "pl_PL",
	"cs": "cs_CZ", "sr": "sr_RS", "tr": "tr_TR", "ru": "ru_RU", "zh": "zh_CN", "ja": "ja"}

func wpLocale(lang string) string {
	if l, ok := wpLocales[lang]; ok {
		return l
	}
	return "en_US"
}

var wpUserRE = regexp.MustCompile(`^[A-Za-z0-9._@-]{3,60}$`)
var wpLocaleRE = regexp.MustCompile(`^[a-z]{2,3}(_[A-Z]{2})?$`)

func (s *Server) handleWPInstall(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	f := formMap(r, "site", "title", "user", "email", "lang")
	fail := func(msg string) {
		p := &Page{Title: "Install WordPress", Nav: "wordpress", Customer: c, Crumb: "WordPress", CrumbURL: "/wordpress", Data: &wpFormData{Sites: s.wpFreeSites(r.Context(), c), F: f}}
		p.Error = translate(s.lang(r, userFrom(r)), msg)
		s.render(w, r, http.StatusBadRequest, "wpform", p)
	}
	sid, _ := strconv.ParseInt(f["site"], 10, 64)
	x, err := s.store.SiteByID(r.Context(), sid)
	if err != nil || x.CustomerID != c.ID {
		fail("Choose a website.")
		return
	}
	if _, err := s.store.WPInstallForSite(r.Context(), x.ID); err == nil {
		fail("WordPress is already installed on this website.")
		return
	}
	if !wpUserRE.MatchString(f["user"]) || strings.EqualFold(f["user"], "admin") && r.FormValue("allow_admin") == "" {
		fail("Choose an administrator name other than admin (3–60 letters, digits, . _ @ -).")
		return
	}
	if _, err := store.CleanEmail(f["email"]); err != nil || f["email"] == "" {
		fail("Enter the administrator's e-mail address.")
		return
	}
	if !wpLocaleRE.MatchString(f["lang"]) {
		f["lang"] = "en_US"
	}
	title := strings.TrimSpace(f["title"])
	if title == "" || len(title) > 200 || strings.ContainsAny(title, "\r\n") {
		fail("Enter the title of the website.")
		return
	}
	pw := r.FormValue("password")
	if pw == "" {
		pw = auth.RandomToken(18)
	} else if err := auth.CheckPasswordPolicy(pw); err != nil {
		fail(err.Error())
		return
	}
	in, err := s.installWP(r.Context(), actor(r), c, x, title, f["user"], f["email"], f["lang"], pw)
	if err != nil {
		fail(storeErr(err))
		return
	}
	s.audit(r, "wp.install", "site:"+x.Domain, "WordPress %s installed (%s)", in.Version, f["lang"])
	p := &Page{Title: x.Domain, Nav: "wordpress", Customer: c, Crumb: "WordPress", CrumbURL: "/wordpress", Data: s.wpData(r.Context(), in)}
	p.Data.(*wpData).NewPassword = pw
	p.Flash = translate(s.lang(r, userFrom(r)), "WordPress is installed.")
	s.render(w, r, http.StatusOK, "wp", p)
}

// installWP makes the database, downloads WordPress, writes wp-config.php
// and runs the installer, all as the account inside its cage.
func (s *Server) installWP(ctx context.Context, by string, c *store.Customer, x *store.Site, title, user, email, locale, pw string) (*store.WPInstall, error) {
	p, _ := s.store.PackageByID(ctx, c.PackageID)
	_, dbs, _, _ := s.store.CountFor(ctx, c.ID)
	if p != nil && s.hostingSettings(ctx).Mode != "dedicated" && dbs >= p.MaxDBs {
		return nil, fmt.Errorf("the package allows %d databases; WordPress needs one more", p.MaxDBs)
	}
	// a free database name: <account>_wp, _wp2 …
	var dbName string
	own, _ := s.store.Databases(ctx, c.ID)
	for i := 1; i < 100 && dbName == ""; i++ {
		suffix := "wp"
		if i > 1 {
			suffix += strconv.Itoa(i)
		}
		n, err := hosting.DatabaseName(c.Username, suffix)
		if err != nil {
			return nil, err
		}
		taken := false
		for _, d := range own {
			taken = taken || d.Name == n
		}
		if !taken {
			dbName = n
		}
	}
	if err := s.store.AddDatabase(ctx, c.ID, dbName); err != nil {
		return nil, err
	}
	dbPW := auth.RandomToken(24)
	if err := s.call(ctx, by, "db.create", map[string]string{"account": c.Username, "name": dbName}, nil); err != nil {
		return nil, err
	}
	if err := s.call(ctx, by, "db.user", map[string]any{"account": c.Username, "user": dbName, "password": dbPW, "databases": []string{dbName}}, nil); err != nil {
		return nil, err
	}
	_ = s.store.SaveDBUser(ctx, c.ID, dbName, []string{dbName})
	// the welcome page of a new site goes
	var req helper.WorkerResp
	_ = s.call(ctx, by, "files", map[string]any{"account": c.Username, "req": helper.WorkerReq{Op: "delete", Path: x.DocRoot + "/index.html"}}, &req)
	if _, err := s.wpcli(ctx, by, c.Username, x.DocRoot, "", "core", "download", "--locale="+locale, "--skip-content"); err != nil && !strings.Contains(err.Error(), "already be present") {
		if _, err2 := s.wpcli(ctx, by, c.Username, x.DocRoot, "", "core", "download", "--locale=en_US", "--skip-content"); err2 != nil {
			return nil, fmt.Errorf("download: %w", err)
		}
	}
	if _, err := s.wpcli(ctx, by, c.Username, x.DocRoot, dbPW, "config", "create", "--dbname="+dbName, "--dbuser="+dbName, "--dbpass="+dbPW, "--dbhost=localhost", "--locale="+locale, "--force"); err != nil {
		return nil, fmt.Errorf("wp-config.php: %w", err)
	}
	// only the account itself may read the database password (nginx never needs it)
	_ = s.call(ctx, by, "files", map[string]any{"account": c.Username, "req": helper.WorkerReq{Op: "chmod", Path: x.DocRoot + "/wp-config.php", Mode: "600"}}, &req)
	for _, kv := range [][2]string{{"DISALLOW_FILE_EDIT", "true"}, {"WP_AUTO_UPDATE_CORE", "'minor'"}, {"FORCE_SSL_ADMIN", "false"}} {
		_, _ = s.wpcli(ctx, by, c.Username, x.DocRoot, "", "config", "set", kv[0], kv[1], "--raw")
	}
	scheme := "http"
	if x.CertStatus == "ok" || x.CertStatus == "uploaded" {
		scheme = "https"
	}
	if _, err := s.wpcli(ctx, by, c.Username, x.DocRoot, pw, "core", "install", "--url="+scheme+"://"+x.Domain, "--title="+title, "--admin_user="+user,
		"--admin_email="+email, "--admin_password="+pw, "--skip-email"); err != nil {
		return nil, fmt.Errorf("install: %w", err)
	}
	_, _ = s.wpcli(ctx, by, c.Username, x.DocRoot, "", "theme", "install", "twentytwentyfive", "--activate")
	_, _ = s.wpcli(ctx, by, c.Username, x.DocRoot, "", "rewrite", "structure", "/%postname%/")
	in := &store.WPInstall{SiteID: x.ID, Path: x.DocRoot, DBName: dbName, AdminUser: user}
	if res, err := s.wpcli(ctx, by, c.Username, x.DocRoot, "", "core", "version"); err == nil {
		in.Version = strings.TrimSpace(res.Output)
	}
	if err := s.store.AddWPInstall(ctx, in); err != nil {
		return nil, err
	}
	x.WordPress = true
	if err := s.store.SaveSite(ctx, x); err == nil {
		_ = s.applySite(ctx, by, x, false)
	}
	return s.store.WPInstallByID(ctx, in.ID)
}

type wpData struct {
	W           *store.WPInstall
	Site        *store.Site
	Snapshots   []*store.WPSnapshot
	NewPassword string
	Staging     *store.WPInstall // the staging copy of this site
	Live        *store.WPInstall // the live site of this staging copy
	RedisOn     bool             // the account's Redis runs
	Verify      *WPVerify
}

func (s *Server) wpData(ctx context.Context, in *store.WPInstall) *wpData {
	d := &wpData{W: in}
	if c, err := s.store.CustomerByID(ctx, in.CustomerID); err == nil {
		d.RedisOn = s.redisOn(ctx, c)
	}
	d.Site, _ = s.store.SiteByID(ctx, in.SiteID)
	d.Snapshots, _ = s.store.WPSnapshots(ctx, in.ID)
	var v WPVerify
	if s.store.GetSetting(ctx, wpVerifyKey(in.ID), &v) == nil && !v.At.IsZero() {
		d.Verify = &v
	}
	d.Staging, _ = s.store.StagingOf(ctx, in.ID)
	if in.StagingOf != nil {
		d.Live, _ = s.store.WPInstallByID(ctx, *in.StagingOf)
	}
	return d
}

func (s *Server) myWP(w http.ResponseWriter, r *http.Request, c *store.Customer) *store.WPInstall {
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return nil
	}
	in, err := s.store.WPInstallByID(r.Context(), id)
	if err != nil || in.CustomerID != c.ID {
		s.notFound(w, r)
		return nil
	}
	return in
}

func (s *Server) handleWP(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	if in := s.myWP(w, r, c); in != nil {
		s.render(w, r, http.StatusOK, "wp", &Page{Title: in.Domain, Nav: "wordpress", Customer: c, Crumb: "WordPress", CrumbURL: "/wordpress", Data: s.wpData(r.Context(), in)})
	}
}

// checkWP asks WP-CLI for the version and pending updates.
func (s *Server) checkWP(ctx context.Context, by string, account string, in *store.WPInstall) error {
	var u store.WPUpdates
	ver := ""
	if res, err := s.wpcli(ctx, by, account, in.Path, "", "core", "version"); err == nil {
		ver = strings.TrimSpace(res.Output)
	} else {
		_ = s.store.SetWPCheck(ctx, in.ID, "", u, err.Error())
		return err
	}
	if res, err := s.wpcli(ctx, by, account, in.Path, "", "core", "check-update", "--format=json"); err == nil {
		var list []struct {
			Version string `json:"version"`
		}
		if json.Unmarshal([]byte(jsonPart(res.Output)), &list) == nil && len(list) > 0 {
			u.Core = list[0].Version
		}
	}
	if res, err := s.wpcli(ctx, by, account, in.Path, "", "plugin", "list", "--update=available", "--fields=name,version,update_version", "--format=json"); err == nil {
		_ = json.Unmarshal([]byte(jsonPart(res.Output)), &u.Plugins)
	}
	if res, err := s.wpcli(ctx, by, account, in.Path, "", "theme", "list", "--update=available", "--fields=name,version,update_version", "--format=json"); err == nil {
		_ = json.Unmarshal([]byte(jsonPart(res.Output)), &u.Themes)
	}
	return s.store.SetWPCheck(ctx, in.ID, ver, u, "")
}

// jsonPart skips warnings WP-CLI prints before its JSON.
func jsonPart(s string) string {
	if i := strings.IndexAny(s, "[{"); i >= 0 {
		return s[i:]
	}
	return "[]"
}

func (s *Server) handleWPCheck(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	in := s.myWP(w, r, c)
	if in == nil {
		return
	}
	back := "/wordpress/" + strconv.FormatInt(in.ID, 10)
	if err := s.checkWP(r.Context(), actor(r), c.Username, in); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.redirect(w, r, back, "Checked.")
}

// snapshotWP saves a copy before a risky change.
func (s *Server) snapshotWP(ctx context.Context, by string, c *store.Customer, in *store.WPInstall, note string) error {
	name := fmt.Sprintf("wp-%d-%s", in.ID, s.now().UTC().Format("20060102-150405"))
	var res struct {
		File string `json:"file"`
		Size int64  `json:"size"`
	}
	if err := s.call(ctx, by, "wp.snapshot", map[string]string{"account": c.Username, "path": in.Path, "name": name}, &res); err != nil {
		return err
	}
	return s.store.AddWPSnapshot(ctx, &store.WPSnapshot{InstallID: in.ID, File: res.File, SizeB: res.Size, Note: note})
}

// updateWP makes a snapshot and updates core (minor or all), plugins and
// themes; the page cache is cleared afterwards.
func (s *Server) updateWP(ctx context.Context, by string, c *store.Customer, in *store.WPInstall, minorOnly bool) error {
	if err := s.snapshotWP(ctx, by, c, in, "before update"); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	args := []string{"core", "update"}
	if minorOnly {
		args = append(args, "--minor")
	}
	var errs []error
	if _, err := s.wpcli(ctx, by, c.Username, in.Path, "", args...); err != nil {
		errs = append(errs, err)
	}
	_, _ = s.wpcli(ctx, by, c.Username, in.Path, "", "core", "update-db")
	if !minorOnly {
		if _, err := s.wpcli(ctx, by, c.Username, in.Path, "", "plugin", "update", "--all"); err != nil {
			errs = append(errs, err)
		}
		if _, err := s.wpcli(ctx, by, c.Username, in.Path, "", "theme", "update", "--all"); err != nil {
			errs = append(errs, err)
		}
	}
	_ = s.store.MarkWPUpdated(ctx, in.ID)
	_ = s.call(ctx, by, "site.cache.purge", map[string]any{"account": c.Username, "id": in.SiteID}, nil)
	_ = s.checkWP(ctx, by, c.Username, in)
	return errors.Join(errs...)
}

func (s *Server) handleWPUpdate(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	in := s.myWP(w, r, c)
	if in == nil {
		return
	}
	back := "/wordpress/" + strconv.FormatInt(in.ID, 10)
	err := s.updateWP(r.Context(), actor(r), c, in, false)
	s.audit(r, "wp.update", "site:"+in.Domain, "core, plugins and themes updated (snapshot made)")
	if err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.redirect(w, r, back, "Updated. A snapshot from before the update is listed below.")
}

// The one-time sign-in uses a small must-use plugin (our own code) and a
// hashed token in an option; the link works once, for 60 seconds.
const wpLoginPlugin = `<?php
/**
 * Plugin Name: HostZit one-time sign-in
 * Description: Lets the HostZit control panel open wp-admin with a one-time link. Installed and used by the panel only.
 */
defined('ABSPATH') || exit;
add_action('init', function () {
	if (empty($_GET['hostzit_login'])) {
		return;
	}
	$v = get_option('hostzit_login');
	delete_option('hostzit_login');
	if (!$v) {
		wp_die('This sign-in link is invalid or expired.', 'Sign-in', array('response' => 403));
	}
	$p = explode('|', $v, 3);
	if (count($p) !== 3 || time() > (int) $p[1] || !hash_equals($p[0], hash('sha256', (string) $_GET['hostzit_login']))) {
		wp_die('This sign-in link is invalid or expired.', 'Sign-in', array('response' => 403));
	}
	$u = get_user_by('login', $p[2]);
	if (!$u || !user_can($u, 'manage_options')) {
		wp_die('The administrator account was not found.', 'Sign-in', array('response' => 403));
	}
	wp_set_auth_cookie($u->ID, false, is_ssl());
	wp_safe_redirect(admin_url());
	exit;
}, 1);
`

func (s *Server) handleWPLogin(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	in := s.myWP(w, r, c)
	if in == nil {
		return
	}
	back := "/wordpress/" + strconv.FormatInt(in.ID, 10)
	user := in.AdminUser
	if user == "" {
		res, err := s.wpcli(r.Context(), actor(r), c.Username, in.Path, "", "user", "list", "--role=administrator", "--field=user_login", "--number=1")
		if err != nil || strings.TrimSpace(res.Output) == "" {
			s.redirectErr(w, r, back, "No WordPress administrator found.")
			return
		}
		user = strings.TrimSpace(strings.Split(strings.TrimSpace(res.Output), "\n")[0])
		_ = s.store.SetWPAdmin(r.Context(), in.ID, user)
	}
	if !wpUserRE.MatchString(user) {
		s.redirectErr(w, r, back, "Invalid administrator name.")
		return
	}
	var resp helper.WorkerResp
	if err := s.call(r.Context(), actor(r), "files", map[string]any{"account": c.Username, "req": helper.WorkerReq{Op: "mkdir", Path: in.Path + "/wp-content/mu-plugins"}}, &resp); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	if err := s.call(r.Context(), actor(r), "files", map[string]any{"account": c.Username, "req": helper.WorkerReq{Op: "write", Path: in.Path + "/wp-content/mu-plugins/hostzit-login.php", Data: []byte(wpLoginPlugin)}}, &resp); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	tok := auth.RandomToken(32)
	sum := sha256.Sum256([]byte(tok))
	val := hex.EncodeToString(sum[:]) + "|" + strconv.FormatInt(s.now().Add(60*time.Second).Unix(), 10) + "|" + user
	if _, err := s.wpcli(r.Context(), actor(r), c.Username, in.Path, "", "option", "update", "hostzit_login", val, "--autoload=no"); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	x, _ := s.store.SiteByID(r.Context(), in.SiteID)
	scheme := "http"
	if x != nil && (x.CertStatus == "ok" || x.CertStatus == "uploaded") {
		scheme = "https"
	}
	s.audit(r, "wp.login", "site:"+in.Domain, "one-time sign-in to wp-admin as %s", user)
	http.Redirect(w, r, scheme+"://"+in.Domain+"/?hostzit_login="+tok, http.StatusSeeOther)
}

func (s *Server) handleWPHarden(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	in := s.myWP(w, r, c)
	if in == nil {
		return
	}
	back := "/wordpress/" + strconv.FormatInt(in.ID, 10)
	bool01 := func(k string) string {
		if r.FormValue(k) != "" {
			return "true"
		}
		return "false"
	}
	var errs []error
	for _, kv := range [][2]string{{"DISALLOW_FILE_EDIT", bool01("file_edit")}, {"WP_DEBUG", map[string]string{"true": "false", "false": "true"}[bool01("debug_off")]}} {
		if _, err := s.wpcli(r.Context(), actor(r), c.Username, in.Path, "", "config", "set", kv[0], kv[1], "--raw"); err != nil {
			errs = append(errs, err)
		}
	}
	if x, err := s.store.SiteByID(r.Context(), in.SiteID); err == nil {
		x.BlockXMLRPC = r.FormValue("xmlrpc") != ""
		x.WordPress = true
		if err := s.store.SaveSite(r.Context(), x); err == nil {
			if err := s.applySite(r.Context(), actor(r), x, false); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if r.FormValue("salts") != "" {
		if _, err := s.wpcli(r.Context(), actor(r), c.Username, in.Path, "", "config", "shuffle-salts"); err != nil {
			errs = append(errs, err)
		}
	}
	s.audit(r, "wp.harden", "site:"+in.Domain, "file editor off %v, debug off %v, xmlrpc blocked %v, new keys %v", r.FormValue("file_edit") != "", r.FormValue("debug_off") != "", r.FormValue("xmlrpc") != "", r.FormValue("salts") != "")
	if err := errors.Join(errs...); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.redirect(w, r, back, "Saved.")
}

func (s *Server) handleWPAuto(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	in := s.myWP(w, r, c)
	if in == nil {
		return
	}
	p := r.FormValue("policy")
	if p != "off" && p != "minor" && p != "all" {
		p = "minor"
	}
	_ = s.store.SetWPAutoUpdate(r.Context(), in.ID, p)
	s.audit(r, "wp.auto", "site:"+in.Domain, "automatic updates: %s", p)
	s.redirect(w, r, "/wordpress/"+strconv.FormatInt(in.ID, 10), "Saved.")
}

func (s *Server) handleWPSnapshot(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	in := s.myWP(w, r, c)
	if in == nil {
		return
	}
	back := "/wordpress/" + strconv.FormatInt(in.ID, 10)
	if err := s.snapshotWP(r.Context(), actor(r), c, in, "by hand"); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.audit(r, "wp.snapshot", "site:"+in.Domain, "snapshot made")
	s.redirect(w, r, back, "Snapshot made.")
}

func (s *Server) mySnapshot(w http.ResponseWriter, r *http.Request, in *store.WPInstall) *store.WPSnapshot {
	sid, _ := pathID(r, "sid")
	list, _ := s.store.WPSnapshots(r.Context(), in.ID)
	for _, x := range list {
		if x.ID == sid {
			return x
		}
	}
	s.notFound(w, r)
	return nil
}

func snapName(file string) string {
	return strings.TrimSuffix(strings.TrimPrefix(file, "backups/"), ".tar.gz")
}

func (s *Server) handleWPRestore(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	in := s.myWP(w, r, c)
	if in == nil {
		return
	}
	snap := s.mySnapshot(w, r, in)
	if snap == nil {
		return
	}
	back := "/wordpress/" + strconv.FormatInt(in.ID, 10)
	if err := s.call(r.Context(), actor(r), "wp.restore", map[string]string{"account": c.Username, "path": in.Path, "name": snapName(snap.File)}, nil); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	_ = s.call(r.Context(), actor(r), "site.cache.purge", map[string]any{"account": c.Username, "id": in.SiteID}, nil)
	_ = s.checkWP(r.Context(), actor(r), c.Username, in)
	s.audit(r, "wp.restore", "site:"+in.Domain, "snapshot of %s restored", snap.CreatedAt.Format(time.RFC3339))
	s.redirect(w, r, back, "The snapshot was restored.")
}

func (s *Server) handleWPSnapshotDelete(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	in := s.myWP(w, r, c)
	if in == nil {
		return
	}
	snap := s.mySnapshot(w, r, in)
	if snap == nil {
		return
	}
	_, _ = s.worker(r, c, helper.WorkerReq{Op: "delete", Path: snap.File})
	_ = s.store.DeleteWPSnapshot(r.Context(), snap.ID)
	s.redirect(w, r, "/wordpress/"+strconv.FormatInt(in.ID, 10), "Snapshot deleted.")
}

func (s *Server) handleWPForget(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	if in := s.myWP(w, r, c); in != nil {
		_ = s.store.DeleteWPInstall(r.Context(), in.ID)
		s.redirect(w, r, "/wordpress", "Removed from the list (the files stay).")
	}
}

// autoUpdateWP runs the update policies once a day.
func (s *Server) autoUpdateWP(ctx context.Context) {
	list, err := s.store.WPInstalls(ctx, 0)
	if err != nil {
		return
	}
	for _, in := range list {
		if in.UpdatedAt != nil && s.now().Sub(*in.UpdatedAt) < 20*time.Hour {
			continue
		}
		c, err := s.store.CustomerByID(ctx, in.CustomerID)
		if err != nil || c.Status != store.StatusActive {
			continue
		}
		if err := s.checkWP(ctx, "system", c.Username, in); err != nil {
			continue
		}
		in, _ = s.store.WPInstallByID(ctx, in.ID)
		if in.AutoUpdate == "off" || in.Updates.Count() == 0 {
			continue
		}
		err = s.updateWP(ctx, "system", c, in, in.AutoUpdate == "minor")
		msg := "automatic update done"
		if err != nil {
			msg = "automatic update: " + err.Error()
			s.notify(ctx, "wp:"+in.Domain, c, "WordPress update of "+in.Domain+" failed", "The automatic update of WordPress on "+in.Domain+" failed:\n"+err.Error()+"\n\nA snapshot was made before the update; see WordPress in the panel.\n")
		}
		_ = s.store.Audit(ctx, "system", "local", "wp.autoupdate", "site:"+in.Domain, msg)
	}
}
