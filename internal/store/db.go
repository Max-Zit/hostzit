// Package store is the PostgreSQL storage of the HostZit server.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned when a unique name is already taken.
var ErrConflict = errors.New("already exists")

// ErrRecordExists: the zone already has the same DNS record.
var ErrRecordExists = errors.New("the zone already has this record")

// Store wraps the connection pool.
type Store struct {
	db  *pgxpool.Pool
	box *box
	now func() time.Time
}

// Open connects to PostgreSQL and applies pending migrations.
func Open(ctx context.Context, url string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 20
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := pool.Ping(ctx2); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database: %w", err)
	}
	s := &Store{db: pool, now: time.Now}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the pool.
func (s *Store) Close() { s.db.Close() }

// Pool is the underlying pool (tests).
func (s *Store) Pool() *pgxpool.Pool { return s.db }

// SetClock replaces the clock (tests).
func (s *Store) SetClock(now func() time.Time) { s.now = now }

func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := migrateTx(ctx, tx, 0); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// migrationLock keeps two servers (or a restore) from migrating at once.
const migrationLock = 7263501

// migrateTx applies the pending migrations in tx, up to version upTo
// (0: all of them).
func migrateTx(ctx context.Context, tx pgx.Tx, upTo int) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationLock); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	var cur int
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&cur); err != nil {
		return err
	}
	list, err := migrationFiles()
	if err != nil {
		return err
	}
	for _, m := range list {
		if m.version <= cur || (upTo > 0 && m.version > upTo) {
			continue
		}
		sqlText, err := migrations.ReadFile(m.path)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sqlText)); err != nil {
			return fmt.Errorf("migration %s: %w", strings.TrimPrefix(m.path, "migrations/"), err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES($1)`, m.version); err != nil {
			return err
		}
	}
	return nil
}

type migrationFile struct {
	path    string
	version int
}

// migrationFiles lists the embedded migrations in order.
func migrationFiles() ([]migrationFile, error) {
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	out := make([]migrationFile, 0, len(names))
	for _, n := range names {
		base := strings.TrimPrefix(n, "migrations/")
		v, err := strconv.Atoi(strings.SplitN(base, "_", 2)[0])
		if err != nil {
			return nil, fmt.Errorf("migration %s: bad name", n)
		}
		out = append(out, migrationFile{n, v})
	}
	return out, nil
}

// SchemaVersion is the newest migration this program knows.
func SchemaVersion() int {
	list, _ := migrationFiles()
	if len(list) == 0 {
		return 0
	}
	return list[len(list)-1].version
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// isUnique reports a unique-constraint violation.
func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "SQLSTATE 23505")
}

// isFK reports a foreign-key violation.
func isFK(err error) bool {
	return err != nil && strings.Contains(err.Error(), "SQLSTATE 23503")
}
