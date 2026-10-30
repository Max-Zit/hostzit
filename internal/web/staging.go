package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/max-zit/hostzit/internal/auth"
	"github.com/max-zit/hostzit/internal/hosting"
	"github.com/max-zit/hostzit/internal/store"
)

// WordPress staging: a full copy of a live site on staging.<domain> (own
// files and database, hidden from search engines), and "push to live",
// which first makes a snapshot of the live site.

func init() {
	customerExtra = append(customerExtra, func(s *Server, mux *http.ServeMux, c func(string, http.HandlerFunc)) {
		c("POST /wordpress/{id}/staging", s.handleStagingCreate)
		c("POST /wordpress/{id}/push", s.handleStagingPush)
		c("POST /wordpress/{id}/staging/delete", s.handleStagingDelete)
	})
}

func siteURL(x *store.Site) string {
	if x.CertStatus == "ok" || x.CertStatus == "uploaded" {
		return "https://" + x.Domain
	}
	return "http://" + x.Domain
}

// copyDatabase dumps the database of one install and loads it into
// another, then rewrites the addresses.
func (s *Server) copyDatabase(ctx context.Context, by string, c *store.Customer, from, to *store.WPInstall, fromURL, toURL string) error {
	dump := fmt.Sprintf("backups/hz-copy-%d.sql", from.ID)
	home := hosting.HomeDir(c.Username)
	if _, err := s.wpcli(ctx, by, c.Username, from.Path, "", "db", "export", home+"/"+dump); err != nil {
		return fmt.Errorf("export: %w", err)
	}
	defer func() { _, _ = s.worker2(ctx, by, c, "delete", dump) }()
	if _, err := s.wpcli(ctx, by, c.Username, to.Path, "", "db", "reset", "--yes"); err != nil {
		return fmt.Errorf("reset: %w", err)
	}
	if _, err := s.wpcli(ctx, by, c.Username, to.Path, "", "db", "import", home+"/"+dump); err != nil {
		return fmt.Errorf("import: %w", err)
	}
	for _, pair := range [][2]string{{fromURL, toURL}, {strings.Replace(fromURL, "https://", "http://", 1), toURL}} {
		if pair[0] == pair[1] {
			continue
		}
		if _, err := s.wpcli(ctx, by, c.Username, to.Path, "", "search-replace", pair[0], pair[1], "--all-tables-with-prefix", "--skip-columns=guid", "--quiet"); err != nil {
			return fmt.Errorf("addresses: %w", err)
		}
	}
	return nil
}

func (s *Server) worker2(ctx context.Context, by string, c *store.Customer, op, path string) (any, error) {
	var res map[string]any
	err := s.call(ctx, by, "files", map[string]any{"account": c.Username, "req": map[string]string{"op": op, "path": path}}, &res)
	return res, err
}

func (s *Server) createStaging(ctx context.Context, by string, c *store.Customer, live *store.WPInstall) (*store.WPInstall, error) {
	if live.StagingOf != nil {
		return nil, errors.New("this is already a staging copy")
	}
	if _, err := s.store.StagingOf(ctx, live.ID); err == nil {
		return nil, errors.New("the site already has a staging copy")
	}
	liveSite, err := s.store.SiteByID(ctx, live.SiteID)
	if err != nil {
		return nil, err
	}
	domain := "staging." + strings.TrimPrefix(liveSite.Domain, "www.")
	// the staging name in the customer's DNS zone, when it is hosted here
	if z, err := s.store.ZoneFor(ctx, liveSite.Domain); err == nil && z.CustomerID == c.ID {
		if hs := s.hostingSettings(ctx); hs.IPv4 != "" {
			rel := hosting.RelName(domain+".", z.Name)
			_, _ = s.store.AddRecord(ctx, z, hosting.Record{Name: rel, Type: "A", Content: hs.IPv4})
			_ = s.applyZone(ctx, by, z)
		}
	}
	st, err := s.store.SiteForName(ctx, domain)
	if err != nil {
		if st, err = s.addSite(ctx, by, c, domain, false); err != nil && st == nil {
			return nil, err
		}
	} else if st.CustomerID != c.ID {
		return nil, errors.New(domain + " belongs to another account")
	}
	st.WWW, st.Canonical, st.WordPress = false, "", true
	if err := s.store.SaveSite(ctx, st); err != nil {
		return nil, err
	}
	// files: a copy of the live folder, then its own wp-config.php
	if err := s.call(ctx, by, "site.copy", map[string]any{"account": c.Username, "from": live.Path, "to": st.DocRoot}, nil); err != nil {
		return nil, err
	}
	dbName, err := hosting.DatabaseName(c.Username, "stg"+strconv.FormatInt(live.ID, 10))
	if err != nil {
		return nil, err
	}
	if err := s.store.AddDatabase(ctx, c.ID, dbName); err != nil && !errors.Is(err, store.ErrConflict) {
		return nil, err
	}
	pw := auth.RandomToken(24)
	if err := s.call(ctx, by, "db.create", map[string]string{"account": c.Username, "name": dbName}, nil); err != nil {
		return nil, err
	}
	if err := s.call(ctx, by, "db.user", map[string]any{"account": c.Username, "user": dbName, "password": pw, "databases": []string{dbName}}, nil); err != nil {
		return nil, err
	}
	_ = s.store.SaveDBUser(ctx, c.ID, dbName, []string{dbName})
	for _, kv := range [][2]string{{"DB_NAME", dbName}, {"DB_USER", dbName}, {"DB_PASSWORD", pw}} {
		if _, err := s.wpcli(ctx, by, c.Username, st.DocRoot, pw, "config", "set", kv[0], kv[1]); err != nil {
			return nil, err
		}
	}
	stg := &store.WPInstall{SiteID: st.ID, Path: st.DocRoot, DBName: dbName, AdminUser: live.AdminUser, Version: live.Version, StagingOf: &live.ID}
	if err := s.copyDatabase(ctx, by, c, live, stg, siteURL(liveSite), siteURL(st)); err != nil {
		return nil, err
	}
	// staging is not for search engines
	_, _ = s.wpcli(ctx, by, c.Username, st.DocRoot, "", "option", "update", "blog_public", "0")
	if err := s.store.AddWPInstall(ctx, stg); err != nil {
		return nil, err
	}
	_ = s.applySite(ctx, by, st, false)
	s.kickCerts()
	return s.store.WPInstallByID(ctx, stg.ID)
}

// pushStaging copies the staging site over the live one (files except
// wp-config.php, and the database), after a snapshot of the live site.
func (s *Server) pushStaging(ctx context.Context, by string, c *store.Customer, stg *store.WPInstall) error {
	if stg.StagingOf == nil {
		return errors.New("this is not a staging copy")
	}
	live, err := s.store.WPInstallByID(ctx, *stg.StagingOf)
	if err != nil {
		return err
	}
	if err := s.snapshotWP(ctx, by, c, live, "before push from staging"); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	liveSite, err := s.store.SiteByID(ctx, live.SiteID)
	if err != nil {
		return err
	}
	stgSite, err := s.store.SiteByID(ctx, stg.SiteID)
	if err != nil {
		return err
	}
	if err := s.call(ctx, by, "site.copy", map[string]any{"account": c.Username, "from": stg.Path, "to": live.Path, "keep": []string{"wp-config.php"}}, nil); err != nil {
		return err
	}
	if err := s.copyDatabase(ctx, by, c, stg, live, siteURL(stgSite), siteURL(liveSite)); err != nil {
		return err
	}
	_, _ = s.wpcli(ctx, by, c.Username, live.Path, "", "option", "update", "blog_public", "1")
	_ = s.call(ctx, by, "site.cache.purge", map[string]any{"account": c.Username, "id": live.SiteID}, nil)
	_ = s.checkWP(ctx, by, c.Username, live)
	return nil
}

func (s *Server) handleStagingCreate(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	in := s.myWP(w, r, c)
	if in == nil {
		return
	}
	back := "/wordpress/" + strconv.FormatInt(in.ID, 10)
	stg, err := s.createStaging(r.Context(), actor(r), c, in)
	if err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.audit(r, "wp.staging", "site:"+in.Domain, "staging copy on %s", stg.Domain)
	s.redirect(w, r, "/wordpress/"+strconv.FormatInt(stg.ID, 10), "The staging copy is ready.")
}

func (s *Server) handleStagingPush(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	in := s.myWP(w, r, c)
	if in == nil {
		return
	}
	back := "/wordpress/" + strconv.FormatInt(in.ID, 10)
	if err := s.pushStaging(r.Context(), actor(r), c, in); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.audit(r, "wp.push", "site:"+in.Domain, "staging pushed to live (snapshot made first)")
	s.redirect(w, r, "/wordpress/"+strconv.FormatInt(*in.StagingOf, 10), "The staging copy is live now. A snapshot from before is listed below.")
}

func (s *Server) handleStagingDelete(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	in := s.myWP(w, r, c)
	if in == nil {
		return
	}
	if in.StagingOf == nil {
		s.redirectErr(w, r, "/wordpress/"+strconv.FormatInt(in.ID, 10), "This is not a staging copy.")
		return
	}
	x, err := s.store.SiteByID(r.Context(), in.SiteID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.call(r.Context(), actor(r), "site.delete", map[string]any{"account": c.Username, "id": x.ID, "remove_files": hosting.SiteDir(x.Domain)}, nil); err != nil {
		s.redirectErr(w, r, "/wordpress/"+strconv.FormatInt(in.ID, 10), storeErr(err))
		return
	}
	_ = s.store.DeleteSite(r.Context(), x.ID)
	if in.DBName != "" {
		_ = s.call(r.Context(), actor(r), "db.drop", map[string]string{"account": c.Username, "name": in.DBName}, nil)
		_ = s.call(r.Context(), actor(r), "db.user.drop", map[string]string{"account": c.Username, "user": in.DBName}, nil)
		_ = s.store.DeleteDatabase(r.Context(), c.ID, in.DBName)
		_ = s.store.DeleteDBUser(r.Context(), c.ID, in.DBName)
	}
	s.audit(r, "wp.staging.delete", "site:"+x.Domain, "staging copy deleted")
	s.redirect(w, r, "/wordpress/"+strconv.FormatInt(*in.StagingOf, 10), "The staging copy was deleted.")
}
