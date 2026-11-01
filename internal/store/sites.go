package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/max-zit/hostzit/internal/hosting"
)

// Site is a website of a customer.
type Site struct {
	ID           int64
	CustomerID   int64
	Account      string // the customer's username
	Domain       string
	Aliases      []string
	DocRoot      string
	PHPVersion   string
	WWW          bool
	Canonical    string
	ForceHTTPS   bool
	HSTS         bool
	Cache        bool
	CacheMinutes int
	WordPress    bool
	BlockXMLRPC  bool
	Redirects    []hosting.Redirect
	UploadMB     int
	AutoTLS      bool
	IPAllow      []string
	IPDeny       []string
	Hotlink      bool
	WAF          bool
	WAFDetect    bool
	WAFExclude   []int
	App          string
	Protected    []hosting.Protected
	CertStatus   string // "", "ok", "pending", "failed", "uploaded"
	CertError    string
	CertNotAfter *time.Time
	CertNames    []string
	CertTriedAt  *time.Time
	Applied      bool
	ApplyError   string
	CreatedAt    time.Time
}

// Spec is the helper's view of the site.
func (s *Site) Spec(suspended bool, maxUpload int) hosting.Site {
	up := s.UploadMB
	if maxUpload > 0 && up > maxUpload {
		up = maxUpload
	}
	return hosting.Site{ID: s.ID, Account: s.Account, Domain: s.Domain, Aliases: s.Aliases, DocRoot: s.DocRoot, PHPVersion: s.PHPVersion, WWW: s.WWW,
		Canonical: s.Canonical, TLS: s.CertStatus == "ok" || s.CertStatus == "uploaded", ForceHTTPS: s.ForceHTTPS, HSTS: s.HSTS, Cache: s.Cache,
		CacheMinutes: s.CacheMinutes, WordPress: s.WordPress, BlockXMLRPC: s.BlockXMLRPC, Redirects: s.Redirects, Suspended: suspended, UploadMB: up,
		IPAllow: s.IPAllow, IPDeny: s.IPDeny, Hotlink: s.Hotlink, WAF: s.WAF, WAFDetect: s.WAFDetect, WAFExclude: s.WAFExclude, App: s.App, Protected: s.Protected}
}

const siteCols = `s.id, s.customer_id, c.username, s.domain, s.aliases, s.doc_root, s.php_version, s.www, s.canonical, s.force_https, s.hsts, s.cache, s.cache_minutes,
	s.wordpress, s.block_xmlrpc, s.redirects, s.upload_mb, s.auto_tls, s.cert_status, s.cert_error, s.cert_not_after, s.cert_names, s.cert_tried_at, s.applied, s.apply_error, s.created_at, s.ip_allow, s.ip_deny, s.hotlink, s.waf, s.protected, s.waf_detect, s.waf_exclude, s.app`

const siteFrom = ` FROM sites s JOIN customers c ON c.id=s.customer_id`

func scanSite(row pgx.Row) (*Site, error) {
	s := &Site{}
	var red, prot []byte
	err := row.Scan(&s.ID, &s.CustomerID, &s.Account, &s.Domain, &s.Aliases, &s.DocRoot, &s.PHPVersion, &s.WWW, &s.Canonical, &s.ForceHTTPS, &s.HSTS, &s.Cache, &s.CacheMinutes,
		&s.WordPress, &s.BlockXMLRPC, &red, &s.UploadMB, &s.AutoTLS, &s.CertStatus, &s.CertError, &s.CertNotAfter, &s.CertNames, &s.CertTriedAt, &s.Applied, &s.ApplyError, &s.CreatedAt, &s.IPAllow, &s.IPDeny, &s.Hotlink, &s.WAF, &prot, &s.WAFDetect, &s.WAFExclude, &s.App)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(prot, &s.Protected)
	return s, json.Unmarshal(red, &s.Redirects)
}

func (s *Store) querySites(ctx context.Context, where string, args ...any) ([]*Site, error) {
	rows, err := s.db.Query(ctx, `SELECT `+siteCols+siteFrom+` WHERE `+where+` ORDER BY s.domain`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Site
	for rows.Next() {
		x, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// Sites lists the sites of a customer (0 = all).
func (s *Store) Sites(ctx context.Context, customerID int64) ([]*Site, error) {
	return s.querySites(ctx, `($1=0 OR s.customer_id=$1)`, customerID)
}

// SiteByID loads a site.
func (s *Store) SiteByID(ctx context.Context, id int64) (*Site, error) {
	l, err := s.querySites(ctx, `s.id=$1`, id)
	if err != nil {
		return nil, err
	}
	if len(l) == 0 {
		return nil, ErrNotFound
	}
	return l[0], nil
}

// SiteForName finds the site serving a host name.
func (s *Store) SiteForName(ctx context.Context, name string) (*Site, error) {
	var id int64
	if err := s.db.QueryRow(ctx, `SELECT site_id FROM site_names WHERE name=$1`, name).Scan(&id); err != nil {
		return nil, notFound(err)
	}
	return s.SiteByID(ctx, id)
}

// SaveSite creates (ID 0) or updates a site after validating it; every
// host name must be free on the server.
func (s *Store) SaveSite(ctx context.Context, x *Site) error {
	if x.Aliases == nil {
		x.Aliases = []string{}
	}
	if x.Redirects == nil {
		x.Redirects = []hosting.Redirect{}
	}
	if x.CertNames == nil {
		x.CertNames = []string{}
	}
	tmpID := x.ID
	if tmpID == 0 {
		tmpID = 1
	}
	spec := x.Spec(false, 0)
	spec.ID = tmpID
	if err := spec.Validate(); err != nil {
		return err
	}
	red, _ := json.Marshal(x.Redirects)
	if x.Protected == nil {
		x.Protected = []hosting.Protected{}
	}
	if x.IPAllow == nil {
		x.IPAllow = []string{}
	}
	if x.IPDeny == nil {
		x.IPDeny = []string{}
	}
	if x.WAFExclude == nil {
		x.WAFExclude = []int{}
	}
	prot, _ := json.Marshal(x.Protected)
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if x.ID == 0 {
		err = tx.QueryRow(ctx, `INSERT INTO sites(customer_id, domain, aliases, doc_root, php_version, www, canonical, force_https, hsts, cache, cache_minutes, wordpress, block_xmlrpc, redirects, upload_mb, auto_tls)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING id, created_at`,
			x.CustomerID, x.Domain, x.Aliases, x.DocRoot, x.PHPVersion, x.WWW, x.Canonical, x.ForceHTTPS, x.HSTS, x.Cache, x.CacheMinutes, x.WordPress, x.BlockXMLRPC, red, x.UploadMB, x.AutoTLS).Scan(&x.ID, &x.CreatedAt)
	} else {
		_, err = tx.Exec(ctx, `UPDATE sites SET aliases=$2, doc_root=$3, php_version=$4, www=$5, canonical=$6, force_https=$7, hsts=$8, cache=$9, cache_minutes=$10, wordpress=$11,
			block_xmlrpc=$12, redirects=$13, upload_mb=$14, auto_tls=$15, ip_allow=$16, ip_deny=$17, hotlink=$18, waf=$19, protected=$20, waf_detect=$21, waf_exclude=$22, applied=false WHERE id=$1`,
			x.ID, x.Aliases, x.DocRoot, x.PHPVersion, x.WWW, x.Canonical, x.ForceHTTPS, x.HSTS, x.Cache, x.CacheMinutes, x.WordPress, x.BlockXMLRPC, red, x.UploadMB, x.AutoTLS,
			x.IPAllow, x.IPDeny, x.Hotlink, x.WAF, prot, x.WAFDetect, x.WAFExclude)
	}
	if isUnique(err) {
		return fmt.Errorf("%s is already used on this server", x.Domain)
	}
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM site_names WHERE site_id=$1`, x.ID); err != nil {
		return err
	}
	for _, n := range x.Spec(false, 0).Names() {
		if _, err := tx.Exec(ctx, `INSERT INTO site_names(name, site_id) VALUES($1,$2)`, n, x.ID); err != nil {
			if isUnique(err) {
				return fmt.Errorf("%s is already used by another site on this server", n)
			}
			return err
		}
	}
	return tx.Commit(ctx)
}

// MarkSiteApplied stores the result of the last system change.
func (s *Store) MarkSiteApplied(ctx context.Context, id int64, applyErr error) error {
	msg := ""
	if applyErr != nil {
		msg = truncate(applyErr.Error(), 500)
	}
	_, err := s.db.Exec(ctx, `UPDATE sites SET applied=$2, apply_error=$3 WHERE id=$1`, id, applyErr == nil, msg)
	return err
}

// SetCert stores the certificate state of a site.
func (s *Store) SetCert(ctx context.Context, id int64, status, msg string, notAfter *time.Time, names []string) error {
	if names == nil {
		names = []string{}
	}
	_, err := s.db.Exec(ctx, `UPDATE sites SET cert_status=$2, cert_error=$3, cert_not_after=COALESCE($4, cert_not_after), cert_names=CASE WHEN $4::timestamptz IS NULL THEN cert_names ELSE $5 END, cert_tried_at=$6 WHERE id=$1`,
		id, status, truncate(msg, 500), notAfter, names, s.now())
	return err
}

// DeleteSite removes a site.
func (s *Store) DeleteSite(ctx context.Context, id int64) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM sites WHERE id=$1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// CertsDue lists sites whose automatic certificate is missing, failed a
// while ago or expires within 30 days.
func (s *Store) CertsDue(ctx context.Context) ([]*Site, error) {
	now := s.now()
	return s.querySites(ctx, `s.auto_tls AND c.status='active' AND s.cert_status<>'uploaded' AND (
		(s.cert_status IN ('', 'pending')) OR
		(s.cert_status='failed' AND (s.cert_tried_at IS NULL OR s.cert_tried_at < $1)) OR
		(s.cert_status='ok' AND s.cert_not_after < $2) OR
		(s.cert_status='ok' AND NOT (s.cert_names @> (SELECT array_agg(n.name) FROM site_names n WHERE n.site_id=s.id))))`,
		now.Add(-6*time.Hour), now.Add(30*24*time.Hour))
}

// ---- DNS zones

// Zone is a DNS zone of a customer.
type Zone struct {
	ID         int64
	CustomerID int64
	Account    string
	Name       string
	DNSSEC     bool
	DS         []string
	Applied    bool
	ApplyError string
	ChangedAt  time.Time
	CreatedAt  time.Time
	Records    int
}

const zoneCols = `z.id, z.customer_id, c.username, z.name, z.dnssec, z.ds, z.applied, z.apply_error, z.changed_at, z.created_at, (SELECT count(*) FROM records r WHERE r.zone_id=z.id)`

func (s *Store) queryZones(ctx context.Context, where string, args ...any) ([]*Zone, error) {
	rows, err := s.db.Query(ctx, `SELECT `+zoneCols+` FROM zones z JOIN customers c ON c.id=z.customer_id WHERE `+where+` ORDER BY z.name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Zone
	for rows.Next() {
		z := &Zone{}
		if err := rows.Scan(&z.ID, &z.CustomerID, &z.Account, &z.Name, &z.DNSSEC, &z.DS, &z.Applied, &z.ApplyError, &z.ChangedAt, &z.CreatedAt, &z.Records); err != nil {
			return nil, err
		}
		out = append(out, z)
	}
	return out, rows.Err()
}

// Zones lists the zones of a customer (0 = all).
func (s *Store) Zones(ctx context.Context, customerID int64) ([]*Zone, error) {
	return s.queryZones(ctx, `($1=0 OR z.customer_id=$1)`, customerID)
}

// ZoneByID loads a zone.
func (s *Store) ZoneByID(ctx context.Context, id int64) (*Zone, error) {
	l, err := s.queryZones(ctx, `z.id=$1`, id)
	if err == nil && len(l) == 0 {
		err = ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return l[0], nil
}

// ZoneByName loads a zone by its name.
func (s *Store) ZoneByName(ctx context.Context, name string) (*Zone, error) {
	l, err := s.queryZones(ctx, `z.name=$1`, name)
	if err == nil && len(l) == 0 {
		err = ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return l[0], nil
}

// ZoneFor finds the hosted zone a name belongs to (longest match).
func (s *Store) ZoneFor(ctx context.Context, name string) (*Zone, error) {
	l, err := s.queryZones(ctx, `$1=z.name OR $1 LIKE '%.'||z.name`, name)
	if err != nil {
		return nil, err
	}
	var best *Zone
	for _, z := range l {
		if best == nil || len(z.Name) > len(best.Name) {
			best = z
		}
	}
	if best == nil {
		return nil, ErrNotFound
	}
	return best, nil
}

// CreateZone adds a zone with its first records.
func (s *Store) CreateZone(ctx context.Context, customerID int64, name string, recs []hosting.Record) (*Zone, error) {
	name, err := hosting.NormalizeDomain(name)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	// A zone inside another customer's zone would let one customer take
	// over names of another.
	var other int64
	err = tx.QueryRow(ctx, `SELECT customer_id FROM zones WHERE ($1 LIKE '%.'||name OR name LIKE '%.'||$1) AND customer_id<>$2 LIMIT 1`, name, customerID).Scan(&other)
	if err == nil {
		return nil, errors.New("this domain belongs to another account on this server")
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	var id int64
	err = tx.QueryRow(ctx, `INSERT INTO zones(customer_id, name) VALUES($1,$2) RETURNING id`, customerID, name).Scan(&id)
	if isUnique(err) {
		return nil, fmt.Errorf("the zone %s already exists on this server", name)
	}
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, r := range recs {
		c, err := hosting.CleanRecord(r, name)
		if err != nil {
			return nil, err
		}
		// the DNS server refuses a zone with the same record twice
		if k := c.Name + " " + c.Type + " " + c.Content; seen[k] {
			continue
		} else {
			seen[k] = true
		}
		if _, err := tx.Exec(ctx, `INSERT INTO records(zone_id, name, type, ttl, content, owner) VALUES($1,$2,$3,$4,$5,$6)`, id, c.Name, c.Type, c.TTL, c.Content, r.Owner); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.ZoneByID(ctx, id)
}

// RecordRow is a stored record.
type RecordRow struct {
	ID int64
	hosting.Record
}

// Records lists a zone's records.
func (s *Store) Records(ctx context.Context, zoneID int64) ([]RecordRow, error) {
	rows, err := s.db.Query(ctx, `SELECT id, name, type, ttl, content, owner FROM records WHERE zone_id=$1 ORDER BY owner, CASE WHEN name='@' THEN '' ELSE name END, type, content`, zoneID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RecordRow
	for rows.Next() {
		var r RecordRow
		if err := rows.Scan(&r.ID, &r.Name, &r.Type, &r.TTL, &r.Content, &r.Owner); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AddRecord adds a checked record.
func (s *Store) AddRecord(ctx context.Context, z *Zone, r hosting.Record) (int64, error) {
	c, err := hosting.CleanRecord(r, z.Name)
	if err != nil {
		return 0, err
	}
	var n int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM records WHERE zone_id=$1`, z.ID).Scan(&n); err != nil {
		return 0, err
	}
	if n >= 5000 {
		return 0, errors.New("at most 5000 records per zone")
	}
	var id int64
	err = s.db.QueryRow(ctx, `SELECT id FROM records WHERE zone_id=$1 AND name=$2 AND type=$3 AND content=$4 LIMIT 1`, z.ID, c.Name, c.Type, c.Content).Scan(&id)
	if err == nil {
		return id, ErrRecordExists
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}
	err = s.db.QueryRow(ctx, `INSERT INTO records(zone_id, name, type, ttl, content, owner) VALUES($1,$2,$3,$4,$5,$6) RETURNING id`, z.ID, c.Name, c.Type, c.TTL, c.Content, r.Owner).Scan(&id)
	if err == nil {
		_, err = s.db.Exec(ctx, `UPDATE zones SET changed_at=$2, applied=false WHERE id=$1`, z.ID, s.now())
	}
	return id, err
}

// UpdateRecord changes a record of a zone (own records only).
func (s *Store) UpdateRecord(ctx context.Context, z *Zone, id int64, r hosting.Record) error {
	c, err := hosting.CleanRecord(r, z.Name)
	if err != nil {
		return err
	}
	var other int64
	err = s.db.QueryRow(ctx, `SELECT id FROM records WHERE zone_id=$1 AND name=$2 AND type=$3 AND content=$4 AND id<>$5 LIMIT 1`, z.ID, c.Name, c.Type, c.Content, id).Scan(&other)
	if err == nil {
		return ErrRecordExists
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	tag, err := s.db.Exec(ctx, `UPDATE records SET name=$3, type=$4, ttl=$5, content=$6 WHERE id=$1 AND zone_id=$2 AND owner=''`, id, z.ID, c.Name, c.Type, c.TTL, c.Content)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err == nil {
		_, err = s.db.Exec(ctx, `UPDATE zones SET changed_at=$2, applied=false WHERE id=$1`, z.ID, s.now())
	}
	return err
}

// DeleteRecord removes a record of a zone (own records only).
func (s *Store) DeleteRecord(ctx context.Context, zoneID, id int64) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM records WHERE id=$1 AND zone_id=$2 AND owner=''`, id, zoneID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err == nil {
		_, err = s.db.Exec(ctx, `UPDATE zones SET changed_at=$2, applied=false WHERE id=$1`, zoneID, s.now())
	}
	return err
}

// ReplaceOwnedRecords replaces the record set of an owner (e.g. emailzit)
// in a zone; records the customer made at the same name and type win and
// are reported as conflicts.
func (s *Store) ReplaceOwnedRecords(ctx context.Context, z *Zone, owner string, recs []hosting.Record) (conflicts []hosting.Record, err error) {
	if owner == "" {
		return nil, errors.New("owner missing")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM records WHERE zone_id=$1 AND owner=$2`, z.ID, owner); err != nil {
		return nil, err
	}
	for _, r := range recs {
		c, err := hosting.CleanRecord(r, z.Name)
		if err != nil {
			return nil, err
		}
		var own int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM records WHERE zone_id=$1 AND owner='' AND name=$2 AND (type=$3 OR type='CNAME' OR $3='CNAME')`, z.ID, c.Name, c.Type).Scan(&own); err != nil {
			return nil, err
		}
		if own > 0 {
			conflicts = append(conflicts, c)
			continue
		}
		if _, err := tx.Exec(ctx, `INSERT INTO records(zone_id, name, type, ttl, content, owner) VALUES($1,$2,$3,$4,$5,$6)`, z.ID, c.Name, c.Type, c.TTL, c.Content, owner); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE zones SET changed_at=$2, applied=false WHERE id=$1`, z.ID, s.now()); err != nil {
		return nil, err
	}
	return conflicts, tx.Commit(ctx)
}

// MarkZoneApplied stores the result of the last DNS change.
func (s *Store) MarkZoneApplied(ctx context.Context, id int64, applyErr error) error {
	msg := ""
	if applyErr != nil {
		msg = truncate(applyErr.Error(), 500)
	}
	_, err := s.db.Exec(ctx, `UPDATE zones SET applied=$2, apply_error=$3 WHERE id=$1`, id, applyErr == nil, msg)
	return err
}

// SetDNSSEC stores the DNSSEC state of a zone.
func (s *Store) SetDNSSEC(ctx context.Context, id int64, on bool, ds []string) error {
	if ds == nil {
		ds = []string{}
	}
	_, err := s.db.Exec(ctx, `UPDATE zones SET dnssec=$2, ds=$3 WHERE id=$1`, id, on, ds)
	return err
}

// DeleteZone removes a zone.
func (s *Store) DeleteZone(ctx context.Context, id int64) error {
	_, err := s.db.Exec(ctx, `DELETE FROM zones WHERE id=$1`, id)
	return err
}

// ---- databases

// Database is a MariaDB database of a customer.
type Database struct {
	ID         int64
	CustomerID int64
	Name       string
	SizeB      int64
	CreatedAt  time.Time
	Users      []string
}

// Databases lists a customer's databases.
func (s *Store) Databases(ctx context.Context, customerID int64) ([]*Database, error) {
	rows, err := s.db.Query(ctx, `SELECT d.id, d.customer_id, d.name, d.size_b, d.created_at, COALESCE((SELECT array_agg(u.name ORDER BY u.name) FROM db_users u WHERE d.name = ANY(u.databases)), '{}')
		FROM databases d WHERE d.customer_id=$1 ORDER BY d.name`, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Database
	for rows.Next() {
		d := &Database{}
		if err := rows.Scan(&d.ID, &d.CustomerID, &d.Name, &d.SizeB, &d.CreatedAt, &d.Users); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// AddDatabase records a database.
func (s *Store) AddDatabase(ctx context.Context, customerID int64, name string) error {
	_, err := s.db.Exec(ctx, `INSERT INTO databases(customer_id, name) VALUES($1,$2)`, customerID, name)
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

// DeleteDatabase forgets a database and removes it from user grants.
func (s *Store) DeleteDatabase(ctx context.Context, customerID int64, name string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM databases WHERE customer_id=$1 AND name=$2`, customerID, name)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err == nil {
		_, err = s.db.Exec(ctx, `UPDATE db_users SET databases=array_remove(databases,$2) WHERE customer_id=$1`, customerID, name)
	}
	return err
}

// SetDatabaseSizes stores the sizes from the server.
func (s *Store) SetDatabaseSizes(ctx context.Context, customerID int64, sizes map[string]int64) error {
	for n, b := range sizes {
		if _, err := s.db.Exec(ctx, `UPDATE databases SET size_b=$3 WHERE customer_id=$1 AND name=$2`, customerID, n, b); err != nil {
			return err
		}
	}
	return nil
}

// DBUser is a database user.
type DBUser struct {
	ID         int64
	CustomerID int64
	Name       string
	Databases  []string
	CreatedAt  time.Time
}

// DBUsers lists a customer's database users.
func (s *Store) DBUsers(ctx context.Context, customerID int64) ([]*DBUser, error) {
	rows, err := s.db.Query(ctx, `SELECT id, customer_id, name, databases, created_at FROM db_users WHERE customer_id=$1 ORDER BY name`, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*DBUser
	for rows.Next() {
		u := &DBUser{}
		if err := rows.Scan(&u.ID, &u.CustomerID, &u.Name, &u.Databases, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SaveDBUser creates or updates a database user's grants.
func (s *Store) SaveDBUser(ctx context.Context, customerID int64, name string, dbs []string) error {
	if dbs == nil {
		dbs = []string{}
	}
	_, err := s.db.Exec(ctx, `INSERT INTO db_users(customer_id, name, databases) VALUES($1,$2,$3) ON CONFLICT (name) DO UPDATE SET databases=$3 WHERE db_users.customer_id=$1`, customerID, name, dbs)
	return err
}

// DeleteDBUser forgets a database user.
func (s *Store) DeleteDBUser(ctx context.Context, customerID int64, name string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM db_users WHERE customer_id=$1 AND name=$2`, customerID, name)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// CountFor counts sites, databases and zones of a customer (package limits).
func (s *Store) CountFor(ctx context.Context, customerID int64) (sites, dbs, zones int, err error) {
	err = s.db.QueryRow(ctx, `SELECT (SELECT count(*) FROM sites WHERE customer_id=$1), (SELECT count(*) FROM databases WHERE customer_id=$1), (SELECT count(*) FROM zones WHERE customer_id=$1)`, customerID).
		Scan(&sites, &dbs, &zones)
	return
}

// cleanName checks a display name.
func cleanName(n string) (string, error) {
	n = strings.TrimSpace(n)
	if n == "" || len(n) > 100 || strings.ContainsAny(n, "\x00\r\n\t") {
		return "", errors.New("the name must be 1–100 characters on one line")
	}
	return n, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}
