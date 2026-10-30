package store

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/max-zit/hostzit/internal/auth"
	"github.com/max-zit/hostzit/internal/hosting"
)

// ---- packages

// Package is a hosting plan.
type Package struct {
	ID          int64
	Slug        string
	Name        string
	Limits      hosting.Limits
	MaxSites    int
	MaxDBs      int
	MaxZones    int
	PHPVersions []string
	CreatedAt   time.Time
	Customers   int // number of customers on it (lists)
}

var slugRE = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

func (p *Package) clean() error {
	p.Slug = strings.ToLower(strings.TrimSpace(p.Slug))
	if !slugRE.MatchString(p.Slug) {
		return errors.New("the package key may contain lowercase letters, digits and - (1–32 characters)")
	}
	var err error
	if p.Name, err = cleanName(p.Name); err != nil {
		return err
	}
	if err := p.Limits.Validate(); err != nil {
		return err
	}
	if p.MaxSites < 0 || p.MaxSites > 10000 || p.MaxDBs < 0 || p.MaxDBs > 10000 || p.MaxZones < 0 || p.MaxZones > 10000 {
		return errors.New("sites, databases and DNS zones: 0–10000")
	}
	for _, v := range p.PHPVersions {
		if !hosting.ValidPHPVersion(v) {
			return fmt.Errorf("invalid PHP version %q", v)
		}
	}
	return nil
}

const pkgCols = `p.id, p.slug, p.name, p.limits, p.max_sites, p.max_dbs, p.max_zones, p.php_versions, p.created_at, (SELECT count(*) FROM customers c WHERE c.package_id=p.id AND c.status<>'terminated')`

func scanPackage(row pgx.Row) (*Package, error) {
	p := &Package{}
	var lim []byte
	if err := row.Scan(&p.ID, &p.Slug, &p.Name, &lim, &p.MaxSites, &p.MaxDBs, &p.MaxZones, &p.PHPVersions, &p.CreatedAt, &p.Customers); err != nil {
		return nil, err
	}
	return p, json.Unmarshal(lim, &p.Limits)
}

// Packages lists the plans.
func (s *Store) Packages(ctx context.Context) ([]*Package, error) {
	rows, err := s.db.Query(ctx, `SELECT `+pkgCols+` FROM packages p ORDER BY lower(p.name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Package
	for rows.Next() {
		p, err := scanPackage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PackageByID loads a plan.
func (s *Store) PackageByID(ctx context.Context, id int64) (*Package, error) {
	p, err := scanPackage(s.db.QueryRow(ctx, `SELECT `+pkgCols+` FROM packages p WHERE p.id=$1`, id))
	return p, notFound(err)
}

// PackageBySlug loads a plan by its key.
func (s *Store) PackageBySlug(ctx context.Context, slug string) (*Package, error) {
	p, err := scanPackage(s.db.QueryRow(ctx, `SELECT `+pkgCols+` FROM packages p WHERE p.slug=$1`, slug))
	return p, notFound(err)
}

// SavePackage creates (ID 0) or updates a plan.
func (s *Store) SavePackage(ctx context.Context, p *Package) error {
	if err := p.clean(); err != nil {
		return err
	}
	lim, _ := json.Marshal(p.Limits)
	if p.PHPVersions == nil {
		p.PHPVersions = []string{}
	}
	var err error
	if p.ID == 0 {
		err = s.db.QueryRow(ctx, `INSERT INTO packages(slug, name, limits, max_sites, max_dbs, max_zones, php_versions) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
			p.Slug, p.Name, lim, p.MaxSites, p.MaxDBs, p.MaxZones, p.PHPVersions).Scan(&p.ID)
	} else {
		var tag interface{ RowsAffected() int64 }
		tag, err = s.db.Exec(ctx, `UPDATE packages SET slug=$2, name=$3, limits=$4, max_sites=$5, max_dbs=$6, max_zones=$7, php_versions=$8 WHERE id=$1`,
			p.ID, p.Slug, p.Name, lim, p.MaxSites, p.MaxDBs, p.MaxZones, p.PHPVersions)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
	}
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

// DeletePackage removes an unused plan.
func (s *Store) DeletePackage(ctx context.Context, id int64) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM packages WHERE id=$1`, id)
	if isFK(err) {
		return errors.New("the package is still used by customers")
	}
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ---- customers

// Customer statuses.
const (
	StatusActive     = "active"
	StatusSuspended  = "suspended"
	StatusTerminated = "terminated"
)

// Customer is a hosting account.
type Customer struct {
	ID            int64
	UUID          string
	ExternalID    *string
	Username      string
	Number        int
	PackageID     int64
	Package       string // name
	PackageSlug   string
	Status        string
	SuspendReason string
	DisplayName   string
	Email         string
	PHPVersion    string
	Applied       bool
	ApplyError    string
	CreatedAt     time.Time
	TerminatedAt  *time.Time
	DeleteAfter   *time.Time
	UserID        int64
	Sites         int
	DiskKB        int64 // last sample
}

const custCols = `c.id, c.uuid::text, c.external_id, c.username, c.number, c.package_id, p.name, p.slug, c.status, c.suspend_reason, c.display_name, c.email, c.php_version,
	c.applied, c.apply_error, c.created_at, c.terminated_at, c.delete_after, COALESCE((SELECT u.id FROM users u WHERE u.customer_id=c.id LIMIT 1),0),
	(SELECT count(*) FROM sites s WHERE s.customer_id=c.id),
	COALESCE((SELECT disk_kb FROM usage_samples us WHERE us.customer_id=c.id ORDER BY at DESC LIMIT 1),0)`

const custFrom = ` FROM customers c JOIN packages p ON p.id=c.package_id`

func scanCustomer(row pgx.Row) (*Customer, error) {
	c := &Customer{}
	err := row.Scan(&c.ID, &c.UUID, &c.ExternalID, &c.Username, &c.Number, &c.PackageID, &c.Package, &c.PackageSlug, &c.Status, &c.SuspendReason, &c.DisplayName, &c.Email,
		&c.PHPVersion, &c.Applied, &c.ApplyError, &c.CreatedAt, &c.TerminatedAt, &c.DeleteAfter, &c.UserID, &c.Sites, &c.DiskKB)
	return c, err
}

// CustomerFilter narrows the list.
type CustomerFilter struct {
	Query   string
	Status  string
	AfterID int64
	Limit   int
}

// Customers lists customers (ordered by id, for cursor pages).
func (s *Store) Customers(ctx context.Context, f CustomerFilter) ([]*Customer, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 1000
	}
	q := `SELECT ` + custCols + custFrom + ` WHERE c.id>$1 AND ($2='' OR c.status=$2) AND ($3='' OR c.username ILIKE '%'||$3||'%' OR c.email ILIKE '%'||$3||'%' OR c.display_name ILIKE '%'||$3||'%'
		OR EXISTS (SELECT 1 FROM sites s WHERE s.customer_id=c.id AND s.domain ILIKE '%'||$3||'%')) ORDER BY c.id LIMIT $4`
	rows, err := s.db.Query(ctx, q, f.AfterID, f.Status, strings.TrimSpace(f.Query), f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Customer
	for rows.Next() {
		c, err := scanCustomer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CustomerByID loads a customer.
func (s *Store) CustomerByID(ctx context.Context, id int64) (*Customer, error) {
	c, err := scanCustomer(s.db.QueryRow(ctx, `SELECT `+custCols+custFrom+` WHERE c.id=$1`, id))
	return c, notFound(err)
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// CustomerByRef finds a customer by number id, UUID, "ext:<external id>"
// or username.
func (s *Store) CustomerByRef(ctx context.Context, ref string) (*Customer, error) {
	ref = strings.TrimSpace(ref)
	var row pgx.Row
	switch {
	case uuidRE.MatchString(strings.ToLower(ref)):
		row = s.db.QueryRow(ctx, `SELECT `+custCols+custFrom+` WHERE c.uuid=$1::uuid`, strings.ToLower(ref))
	case strings.HasPrefix(ref, "ext:"):
		row = s.db.QueryRow(ctx, `SELECT `+custCols+custFrom+` WHERE c.external_id=$1`, strings.TrimPrefix(ref, "ext:"))
	default:
		row = s.db.QueryRow(ctx, `SELECT `+custCols+custFrom+` WHERE c.username=$1`, ref)
	}
	c, err := scanCustomer(row)
	return c, notFound(err)
}

// NewUUID makes a random (version 4) UUID.
func NewUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// NewCustomer describes a customer to create.
type NewCustomer struct {
	UUID        string
	ExternalID  string
	Username    string
	PackageID   int64
	DisplayName string
	Email       string
	Password    string
	PHPVersion  string
}

var emailRE = regexp.MustCompile(`^[^\s@<>"']{1,64}@[a-z0-9.-]{1,253}\.[a-z]{2,63}$`)

// CleanEmail checks an e-mail address ("" allowed).
func CleanEmail(e string) (string, error) {
	e = strings.ToLower(strings.TrimSpace(e))
	if e != "" && !emailRE.MatchString(e) {
		return "", errors.New("invalid e-mail address")
	}
	return e, nil
}

// CreateCustomer adds a customer and its sign-in. The account number (uid)
// is the lowest free one.
func (s *Store) CreateCustomer(ctx context.Context, n NewCustomer) (*Customer, error) {
	if err := hosting.ValidAccount(n.Username); err != nil {
		return nil, err
	}
	if n.UUID == "" {
		n.UUID = NewUUID()
	}
	n.UUID = strings.ToLower(n.UUID)
	if !uuidRE.MatchString(n.UUID) {
		return nil, errors.New("invalid customer UUID")
	}
	var ext *string
	if e := strings.TrimSpace(n.ExternalID); e != "" {
		if len(e) > 100 || strings.ContainsAny(e, "\x00\r\n") {
			return nil, errors.New("invalid external id")
		}
		ext = &e
	}
	var err error
	if n.Email, err = CleanEmail(n.Email); err != nil {
		return nil, err
	}
	if n.DisplayName = strings.TrimSpace(n.DisplayName); len(n.DisplayName) > 100 || strings.ContainsAny(n.DisplayName, "\r\n\x00") {
		return nil, errors.New("the name must be up to 100 characters on one line")
	}
	if err := auth.CheckPasswordPolicy(n.Password); err != nil {
		return nil, err
	}
	hash, err := auth.HashPassword(n.Password)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7263101)`); err != nil {
		return nil, err
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE lower(username)=lower($1))`, n.Username).Scan(&exists); err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrConflict
	}
	var number int
	if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT min(c.number+1) FROM customers c WHERE NOT EXISTS (SELECT 1 FROM customers d WHERE d.number=c.number+1)),1)`).Scan(&number); err != nil {
		return nil, err
	}
	var id int64
	err = tx.QueryRow(ctx, `INSERT INTO customers(uuid, external_id, username, number, package_id, display_name, email, php_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		n.UUID, ext, n.Username, number, n.PackageID, n.DisplayName, n.Email, n.PHPVersion).Scan(&id)
	if isUnique(err) {
		return nil, ErrConflict
	}
	if isFK(err) {
		return nil, errors.New("unknown package")
	}
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO users(username, display_name, email, password_hash, role, customer_id) VALUES($1,$2,$3,$4,'customer',$5)`,
		n.Username, n.DisplayName, n.Email, hash, id); err != nil {
		if isUnique(err) {
			return nil, ErrConflict
		}
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.CustomerByID(ctx, id)
}

// UpdateCustomer changes contact data, package and PHP version.
func (s *Store) UpdateCustomer(ctx context.Context, c *Customer) error {
	var err error
	if c.Email, err = CleanEmail(c.Email); err != nil {
		return err
	}
	if len(c.DisplayName) > 100 || strings.ContainsAny(c.DisplayName, "\r\n\x00") {
		return errors.New("the name must be up to 100 characters on one line")
	}
	tag, err := s.db.Exec(ctx, `UPDATE customers SET display_name=$2, email=$3, package_id=$4, php_version=$5 WHERE id=$1`, c.ID, strings.TrimSpace(c.DisplayName), c.Email, c.PackageID, c.PHPVersion)
	if isFK(err) {
		return errors.New("unknown package")
	}
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err == nil {
		_, err = s.db.Exec(ctx, `UPDATE users SET display_name=$2, email=$3 WHERE customer_id=$1`, c.ID, strings.TrimSpace(c.DisplayName), c.Email)
	}
	return err
}

// SetCustomerStatus suspends, unsuspends or terminates. Terminated
// customers keep their data until deleteAfter.
func (s *Store) SetCustomerStatus(ctx context.Context, id int64, status, reason string, deleteAfter *time.Time) error {
	switch status {
	case StatusActive, StatusSuspended, StatusTerminated:
	default:
		return errors.New("unknown status")
	}
	if len(reason) > 200 || strings.ContainsAny(reason, "\r\n\x00") {
		return errors.New("the reason must be up to 200 characters on one line")
	}
	var term *time.Time
	if status == StatusTerminated {
		t := s.now()
		term = &t
	}
	tag, err := s.db.Exec(ctx, `UPDATE customers SET status=$2, suspend_reason=$3, terminated_at=$4, delete_after=$5 WHERE id=$1`, id, status, reason, term, deleteAfter)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err == nil {
		// suspended and terminated customers cannot sign in
		_, err = s.db.Exec(ctx, `UPDATE users SET disabled=$2 WHERE customer_id=$1`, id, status != StatusActive)
		if status != StatusActive {
			_, _ = s.db.Exec(ctx, `DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE customer_id=$1)`, id)
		}
	}
	return err
}

// MarkCustomerApplied stores the result of the last system change.
func (s *Store) MarkCustomerApplied(ctx context.Context, id int64, applyErr error) error {
	msg := ""
	if applyErr != nil {
		msg = truncate(applyErr.Error(), 500)
	}
	_, err := s.db.Exec(ctx, `UPDATE customers SET applied=$2, apply_error=$3 WHERE id=$1`, id, applyErr == nil, msg)
	return err
}

// DeleteCustomer removes a customer from the database (after the system
// account is gone).
func (s *Store) DeleteCustomer(ctx context.Context, id int64) error {
	_, err := s.db.Exec(ctx, `DELETE FROM customers WHERE id=$1`, id)
	return err
}

// DueForDeletion lists terminated customers whose grace period is over.
func (s *Store) DueForDeletion(ctx context.Context) ([]int64, error) {
	rows, err := s.db.Query(ctx, `SELECT id FROM customers WHERE status='terminated' AND delete_after IS NOT NULL AND delete_after<$1`, s.now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// CustomerCounts counts customers by status.
func (s *Store) CustomerCounts(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.Query(ctx, `SELECT status, count(*) FROM customers GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[st] = n
	}
	return out, rows.Err()
}

// AccountOf builds what the helper needs for a customer.
func AccountOf(c *Customer, p *Package, phpDefault string) hosting.Account {
	v := c.PHPVersion
	if v == "" {
		v = phpDefault
	}
	a := hosting.Account{Name: c.Username, Number: c.Number, Suspended: c.Status != StatusActive, Limits: p.Limits, PHPVersions: []string{v}}
	return a
}
