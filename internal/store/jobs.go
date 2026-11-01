package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/max-zit/hostzit/internal/auth"
)

// Job is background work (the API answers 202 with its id).
type Job struct {
	ID         string
	Kind       string
	CustomerID *int64
	Status     string
	Detail     string
	Error      string
	CreatedAt  time.Time
	FinishedAt *time.Time
}

// CreateJob queues a job.
func (s *Store) CreateJob(ctx context.Context, kind string, customerID *int64, detail string) (*Job, error) {
	j := &Job{ID: NewUUID(), Kind: kind, CustomerID: customerID, Status: "queued", Detail: detail, CreatedAt: s.now()}
	_, err := s.db.Exec(ctx, `INSERT INTO jobs(id, kind, customer_id, status, detail, created_at) VALUES($1,$2,$3,$4,$5,$6)`, j.ID, j.Kind, j.CustomerID, j.Status, j.Detail, j.CreatedAt)
	return j, err
}

// FinishJob stores the outcome.
func (s *Store) FinishJob(ctx context.Context, id string, jobErr error) error {
	st, msg := "done", ""
	if jobErr != nil {
		st, msg = "failed", truncate(jobErr.Error(), 1000)
	}
	_, err := s.db.Exec(ctx, `UPDATE jobs SET status=$2, error=$3, finished_at=$4 WHERE id=$1`, id, st, msg, s.now())
	return err
}

// StartJob marks a job running.
func (s *Store) StartJob(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `UPDATE jobs SET status='running' WHERE id=$1`, id)
	return err
}

// JobByID loads a job.
func (s *Store) JobByID(ctx context.Context, id string) (*Job, error) {
	if !uuidRE.MatchString(id) {
		return nil, ErrNotFound
	}
	j := &Job{}
	err := s.db.QueryRow(ctx, `SELECT id::text, kind, customer_id, status, detail, error, created_at, finished_at FROM jobs WHERE id=$1::uuid`, id).
		Scan(&j.ID, &j.Kind, &j.CustomerID, &j.Status, &j.Detail, &j.Error, &j.CreatedAt, &j.FinishedAt)
	return j, notFound(err)
}

// Jobs lists the newest jobs.
func (s *Store) Jobs(ctx context.Context, limit int) ([]*Job, error) {
	rows, err := s.db.Query(ctx, `SELECT id::text, kind, customer_id, status, detail, error, created_at, finished_at FROM jobs ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Job
	for rows.Next() {
		j := &Job{}
		if err := rows.Scan(&j.ID, &j.Kind, &j.CustomerID, &j.Status, &j.Detail, &j.Error, &j.CreatedAt, &j.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// FailStaleJobs marks jobs that were running when the server stopped.
func (s *Store) FailStaleJobs(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `UPDATE jobs SET status='failed', error='the server was restarted while the job ran', finished_at=$1 WHERE status IN ('queued','running')`, s.now())
	return err
}

// ---- single sign-on links

// CreateSSOLink makes a one-time sign-in link token for a user (60 s).
func (s *Store) CreateSSOLink(ctx context.Context, userID int64, by string) (string, time.Time, error) {
	tok := auth.RandomToken(32)
	exp := s.now().Add(60 * time.Second)
	_, err := s.db.Exec(ctx, `INSERT INTO sso_links(token_hash, user_id, expires_at, created_by) VALUES($1,$2,$3,$4)`, auth.HashToken("sso", tok), userID, exp, truncate(by, 100))
	_, _ = s.db.Exec(ctx, `DELETE FROM sso_links WHERE expires_at < $1`, s.now())
	return tok, exp, err
}

// UseSSOLink consumes a link and returns its user.
func (s *Store) UseSSOLink(ctx context.Context, tok string) (*User, string, error) {
	if len(tok) > 100 {
		return nil, "", ErrNotFound
	}
	var uid int64
	var by string
	err := s.db.QueryRow(ctx, `DELETE FROM sso_links WHERE token_hash=$1 AND expires_at > $2 RETURNING user_id, created_by`, auth.HashToken("sso", tok), s.now()).Scan(&uid, &by)
	if err != nil {
		return nil, "", notFound(err)
	}
	u, err := s.UserByID(ctx, uid)
	if err != nil || u.Disabled {
		return nil, "", ErrNotFound
	}
	return u, by, nil
}

// ---- idempotency keys

// IdempotentResponse returns a stored answer for a key.
func (s *Store) IdempotentResponse(ctx context.Context, tokenID int64, key string) (int, []byte, bool) {
	var st int
	var body []byte
	err := s.db.QueryRow(ctx, `SELECT status, body FROM idempotency WHERE token_id=$1 AND key=$2 AND created_at > $3`, tokenID, key, s.now().Add(-24*time.Hour)).Scan(&st, &body)
	if err != nil {
		return 0, nil, false
	}
	return st, body, true
}

// SaveIdempotent stores the answer for a key.
func (s *Store) SaveIdempotent(ctx context.Context, tokenID int64, key string, status int, body []byte) {
	_, _ = s.db.Exec(ctx, `INSERT INTO idempotency(token_id, key, status, body, created_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, tokenID, key, status, body, s.now())
	_, _ = s.db.Exec(ctx, `DELETE FROM idempotency WHERE created_at < $1`, s.now().Add(-24*time.Hour))
}

// ---- usage

// UsageSample is a measurement of a customer.
type UsageSample struct {
	At      time.Time
	DiskKB  int64
	Inodes  int64
	DBB     int64
	MemoryB int64
	CPUUsec int64
	IOB     int64
	Tasks   int
	// counters since the slice started
	ThrottledUsec int64
	OOM           int64
}

// AddUsage stores a sample.
func (s *Store) AddUsage(ctx context.Context, customerID int64, u UsageSample) error {
	_, err := s.db.Exec(ctx, `INSERT INTO usage_samples(customer_id, at, disk_kb, inodes, db_b, memory_b, cpu_usec, io_b, tasks, throttled_usec, oom) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING`,
		customerID, u.At, u.DiskKB, u.Inodes, u.DBB, u.MemoryB, u.CPUUsec, u.IOB, u.Tasks, u.ThrottledUsec, u.OOM)
	return err
}

// Usage returns a customer's samples since a time.
func (s *Store) Usage(ctx context.Context, customerID int64, since time.Time) ([]UsageSample, error) {
	rows, err := s.db.Query(ctx, `SELECT at, disk_kb, inodes, db_b, memory_b, cpu_usec, io_b, tasks, throttled_usec, oom FROM usage_samples WHERE customer_id=$1 AND at>=$2 ORDER BY at`, customerID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UsageSample
	for rows.Next() {
		var u UsageSample
		if err := rows.Scan(&u.At, &u.DiskKB, &u.Inodes, &u.DBB, &u.MemoryB, &u.CPUUsec, &u.IOB, &u.Tasks, &u.ThrottledUsec, &u.OOM); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// LastUsage returns the newest sample.
func (s *Store) LastUsage(ctx context.Context, customerID int64) (*UsageSample, error) {
	var u UsageSample
	err := s.db.QueryRow(ctx, `SELECT at, disk_kb, inodes, db_b, memory_b, cpu_usec, io_b, tasks, throttled_usec, oom FROM usage_samples WHERE customer_id=$1 ORDER BY at DESC LIMIT 1`, customerID).
		Scan(&u.At, &u.DiskKB, &u.Inodes, &u.DBB, &u.MemoryB, &u.CPUUsec, &u.IOB, &u.Tasks, &u.ThrottledUsec, &u.OOM)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

// PruneUsage keeps 90 days of samples.
func (s *Store) PruneUsage(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `DELETE FROM usage_samples WHERE at < $1`, s.now().Add(-90*24*time.Hour))
	return err
}

// UsageAll returns the samples of every customer since a time.
func (s *Store) UsageAll(ctx context.Context, since time.Time) (map[int64][]UsageSample, error) {
	rows, err := s.db.Query(ctx, `SELECT customer_id, at, disk_kb, inodes, db_b, memory_b, cpu_usec, io_b, tasks, throttled_usec, oom FROM usage_samples WHERE at>=$1 ORDER BY customer_id, at`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]UsageSample{}
	for rows.Next() {
		var id int64
		var u UsageSample
		if err := rows.Scan(&id, &u.At, &u.DiskKB, &u.Inodes, &u.DBB, &u.MemoryB, &u.CPUUsec, &u.IOB, &u.Tasks, &u.ThrottledUsec, &u.OOM); err != nil {
			return nil, err
		}
		out[id] = append(out[id], u)
	}
	return out, rows.Err()
}

// UsageRate is what an account used between two samples.
type UsageRate struct {
	At         time.Time
	CPUPercent float64 // 100 = one core
	IOMBps     float64
	Throttled  float64 // share of the time the CPU limit held the account back, 0–1
	OOM        int64   // processes ended by the memory limit
	MemoryB    int64
	Tasks      int
}

// LimitHit reports a sample where a limit held the account back.
func (r UsageRate) LimitHit() bool { return r.OOM > 0 || r.Throttled >= 0.25 }

// Rates turns counters into rates (a restarted control group starts again
// from zero; that interval is skipped).
func Rates(samples []UsageSample) []UsageRate {
	var out []UsageRate
	for i := 1; i < len(samples); i++ {
		a, b := samples[i-1], samples[i]
		sec := b.At.Sub(a.At).Seconds()
		if sec <= 0 || b.CPUUsec < a.CPUUsec || b.IOB < a.IOB || b.ThrottledUsec < a.ThrottledUsec || b.OOM < a.OOM {
			continue
		}
		out = append(out, UsageRate{At: b.At, MemoryB: b.MemoryB, Tasks: b.Tasks,
			CPUPercent: float64(b.CPUUsec-a.CPUUsec) / sec / 1e4,
			IOMBps:     float64(b.IOB-a.IOB) / sec / 1e6,
			Throttled:  min(float64(b.ThrottledUsec-a.ThrottledUsec)/sec/1e6, 1), // summed over threads: may pass 1
			OOM:        b.OOM - a.OOM})
	}
	return out
}
