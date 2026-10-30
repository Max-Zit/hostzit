package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

// The audit log is append-only and hash-chained: every entry stores the
// hash of the previous one, and its own hash covers all its fields. An
// entry changed or deleted later breaks the chain at that point, which
// VerifyAudit finds. (A database administrator can still rewrite the whole
// chain; anchoring the head hash outside the database comes later.)

// AuditEntry is one logged action.
type AuditEntry struct {
	ID       int64
	At       time.Time
	Username string
	IP       string
	Action   string
	Target   string
	Detail   string
	PrevHash string
	Hash     string
}

const auditGenesis = "hostzit-audit-v1"

func auditHash(e *AuditEntry) string {
	// JSON of an array: unambiguous field boundaries.
	b, _ := json.Marshal([]any{e.PrevHash, e.ID, e.At.UTC().Format(time.RFC3339Nano), e.Username, e.IP, e.Action, e.Target, e.Detail})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// maxDetail limits one entry (script output is stored elsewhere later).
const maxDetail = 16 << 10

// Audit appends an entry.
func (s *Store) Audit(ctx context.Context, username, ip, action, target, detail string) error {
	if len(detail) > maxDetail {
		detail = detail[:maxDetail] + " …"
	}
	detail = strings.ToValidUTF8(detail, "?")
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Serialize writers so the chain stays linear.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7263002)`); err != nil {
		return err
	}
	e := &AuditEntry{At: s.now().UTC().Truncate(time.Microsecond), Username: username, IP: ip, Action: action, Target: target, Detail: detail}
	err = tx.QueryRow(ctx, `SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&e.PrevHash)
	if err != nil {
		if notFound(err) != ErrNotFound {
			return err
		}
		e.PrevHash = auditGenesis
	}
	if err := tx.QueryRow(ctx, `SELECT nextval('audit_log_id_seq')`).Scan(&e.ID); err != nil {
		return err
	}
	e.Hash = auditHash(e)
	if _, err := tx.Exec(ctx, `INSERT INTO audit_log(id, at, username, ip, action, target, detail, prev_hash, hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		e.ID, e.At, e.Username, e.IP, e.Action, e.Target, e.Detail, e.PrevHash, e.Hash); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AuditFilter narrows the audit list.
type AuditFilter struct {
	Query  string
	Before int64 // entries with smaller id (paging)
	Limit  int
}

// AuditEntries lists entries newest first.
func (s *Store) AuditEntries(ctx context.Context, f AuditFilter) ([]AuditEntry, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	q := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(f.Query) + "%"
	rows, err := s.db.Query(ctx, `SELECT id, at, username, ip, action, target, detail, prev_hash, hash FROM audit_log
		WHERE ($1 = 0 OR id < $1) AND ($2 = '%%' OR username ILIKE $2 OR action ILIKE $2 OR target ILIKE $2 OR detail ILIKE $2 OR ip ILIKE $2)
		ORDER BY id DESC LIMIT $3`, f.Before, q, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.At, &e.Username, &e.IP, &e.Action, &e.Target, &e.Detail, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AuditCheck is the result of verifying the chain.
type AuditCheck struct {
	Entries int64
	OK      bool
	// BrokenAt is the first entry whose hash or link does not match.
	BrokenAt int64
	Head     string
}

// VerifyAudit walks the whole chain.
func (s *Store) VerifyAudit(ctx context.Context) (AuditCheck, error) {
	rows, err := s.db.Query(ctx, `SELECT id, at, username, ip, action, target, detail, prev_hash, hash FROM audit_log ORDER BY id`)
	if err != nil {
		return AuditCheck{}, err
	}
	defer rows.Close()
	c := AuditCheck{OK: true}
	prev := auditGenesis
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.At, &e.Username, &e.IP, &e.Action, &e.Target, &e.Detail, &e.PrevHash, &e.Hash); err != nil {
			return c, err
		}
		c.Entries++
		if c.OK && (e.PrevHash != prev || auditHash(&e) != e.Hash) {
			c.OK, c.BrokenAt = false, e.ID
		}
		prev = e.Hash
	}
	c.Head = prev
	return c, rows.Err()
}

// DBInfo describes the database for diagnostics (version and size; never
// the connection details).
func (s *Store) DBInfo(ctx context.Context) string {
	var ver, size string
	if err := s.db.QueryRow(ctx, `SELECT current_setting('server_version'), pg_size_pretty(pg_database_size(current_database()))`).Scan(&ver, &size); err != nil {
		return "unknown"
	}
	return "PostgreSQL " + ver + ", " + size
}
