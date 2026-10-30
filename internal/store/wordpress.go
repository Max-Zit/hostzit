package store

import (
	"context"
	"encoding/json"
	"time"
)

// WPUpdates is what a check found.
type WPUpdates struct {
	Core    string     `json:"core,omitempty"` // new core version
	Plugins []WPUpdate `json:"plugins,omitempty"`
	Themes  []WPUpdate `json:"themes,omitempty"`
}

// WPUpdate is one plugin or theme with a newer version.
type WPUpdate struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	New     string `json:"update_version"`
}

// Count is the number of pending updates.
func (u WPUpdates) Count() int {
	n := len(u.Plugins) + len(u.Themes)
	if u.Core != "" {
		n++
	}
	return n
}

// WPInstall is a WordPress site of a customer.
type WPInstall struct {
	ID         int64
	SiteID     int64
	CustomerID int64
	Domain     string
	Path       string // relative to the home
	DBName     string
	AdminUser  string
	Version    string
	AutoUpdate string
	Updates    WPUpdates
	CheckedAt  *time.Time
	UpdatedAt  *time.Time
	LastError  string
	CreatedAt  time.Time
	StagingOf  *int64
}

const wpCols = `w.id, w.site_id, s.customer_id, s.domain, w.path, w.db_name, w.admin_user, w.version, w.auto_update, w.updates, w.checked_at, w.updated_at, w.last_error, w.created_at, w.staging_of`

func (s *Store) queryWP(ctx context.Context, where string, args ...any) ([]*WPInstall, error) {
	rows, err := s.db.Query(ctx, `SELECT `+wpCols+` FROM wp_installs w JOIN sites s ON s.id=w.site_id WHERE `+where+` ORDER BY s.domain`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*WPInstall
	for rows.Next() {
		w := &WPInstall{}
		var up []byte
		if err := rows.Scan(&w.ID, &w.SiteID, &w.CustomerID, &w.Domain, &w.Path, &w.DBName, &w.AdminUser, &w.Version, &w.AutoUpdate, &up, &w.CheckedAt, &w.UpdatedAt, &w.LastError, &w.CreatedAt, &w.StagingOf); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(up, &w.Updates)
		out = append(out, w)
	}
	return out, rows.Err()
}

// WPInstalls lists the WordPress sites of a customer (0 = all).
func (s *Store) WPInstalls(ctx context.Context, customerID int64) ([]*WPInstall, error) {
	return s.queryWP(ctx, `($1=0 OR s.customer_id=$1)`, customerID)
}

// WPInstallByID loads one.
func (s *Store) WPInstallByID(ctx context.Context, id int64) (*WPInstall, error) {
	l, err := s.queryWP(ctx, `w.id=$1`, id)
	if err == nil && len(l) == 0 {
		err = ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return l[0], nil
}

// WPInstallForSite finds the install of a site.
func (s *Store) WPInstallForSite(ctx context.Context, siteID int64) (*WPInstall, error) {
	l, err := s.queryWP(ctx, `w.site_id=$1`, siteID)
	if err == nil && len(l) == 0 {
		err = ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return l[0], nil
}

// AddWPInstall records an install.
func (s *Store) AddWPInstall(ctx context.Context, w *WPInstall) error {
	err := s.db.QueryRow(ctx, `INSERT INTO wp_installs(site_id, path, db_name, admin_user, version, staging_of) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT (site_id) DO UPDATE SET path=$2, db_name=$3, admin_user=$4, version=$5, staging_of=$6 RETURNING id`,
		w.SiteID, w.Path, w.DBName, w.AdminUser, w.Version, w.StagingOf).Scan(&w.ID)
	return err
}

// SetWPCheck stores the result of an update check.
func (s *Store) SetWPCheck(ctx context.Context, id int64, version string, u WPUpdates, checkErr string) error {
	b, _ := json.Marshal(u)
	_, err := s.db.Exec(ctx, `UPDATE wp_installs SET version=CASE WHEN $2='' THEN version ELSE $2 END, updates=$3, checked_at=$4, last_error=$5 WHERE id=$1`, id, version, b, s.now(), truncate(checkErr, 500))
	return err
}

// MarkWPUpdated notes an update run.
func (s *Store) MarkWPUpdated(ctx context.Context, id int64) error {
	_, err := s.db.Exec(ctx, `UPDATE wp_installs SET updated_at=$2 WHERE id=$1`, id, s.now())
	return err
}

// SetWPAutoUpdate sets the policy (off, minor, all).
func (s *Store) SetWPAutoUpdate(ctx context.Context, id int64, policy string) error {
	_, err := s.db.Exec(ctx, `UPDATE wp_installs SET auto_update=$2 WHERE id=$1`, id, policy)
	return err
}

// SetWPAdmin stores the administrator user name.
func (s *Store) SetWPAdmin(ctx context.Context, id int64, user string) error {
	_, err := s.db.Exec(ctx, `UPDATE wp_installs SET admin_user=$2 WHERE id=$1`, id, truncate(user, 60))
	return err
}

// DeleteWPInstall forgets an install.
func (s *Store) DeleteWPInstall(ctx context.Context, id int64) error {
	_, err := s.db.Exec(ctx, `DELETE FROM wp_installs WHERE id=$1`, id)
	return err
}

// WPSnapshot is a saved copy of a WordPress site.
type WPSnapshot struct {
	ID        int64
	InstallID int64
	File      string
	SizeB     int64
	Note      string
	CreatedAt time.Time
}

// AddWPSnapshot records a snapshot.
func (s *Store) AddWPSnapshot(ctx context.Context, x *WPSnapshot) error {
	return s.db.QueryRow(ctx, `INSERT INTO wp_snapshots(install_id, file, size_b, note) VALUES($1,$2,$3,$4) RETURNING id, created_at`, x.InstallID, x.File, x.SizeB, truncate(x.Note, 200)).Scan(&x.ID, &x.CreatedAt)
}

// WPSnapshots lists the snapshots of an install, newest first.
func (s *Store) WPSnapshots(ctx context.Context, installID int64) ([]*WPSnapshot, error) {
	rows, err := s.db.Query(ctx, `SELECT id, install_id, file, size_b, note, created_at FROM wp_snapshots WHERE install_id=$1 ORDER BY created_at DESC`, installID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*WPSnapshot
	for rows.Next() {
		x := &WPSnapshot{}
		if err := rows.Scan(&x.ID, &x.InstallID, &x.File, &x.SizeB, &x.Note, &x.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// DeleteWPSnapshot forgets a snapshot.
func (s *Store) DeleteWPSnapshot(ctx context.Context, id int64) error {
	_, err := s.db.Exec(ctx, `DELETE FROM wp_snapshots WHERE id=$1`, id)
	return err
}

// StagingOf finds the staging copy of an install.
func (s *Store) StagingOf(ctx context.Context, liveID int64) (*WPInstall, error) {
	l, err := s.queryWP(ctx, `w.staging_of=$1`, liveID)
	if err == nil && len(l) == 0 {
		err = ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return l[0], nil
}
