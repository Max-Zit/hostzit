package store

import (
	"context"
	"errors"
	"strings"
	"time"
)

// CronJob is a scheduled job of a customer.
type CronJob struct {
	ID         int64
	CustomerID int64
	Schedule   string
	Command    string
	Enabled    bool
	Note       string
	CreatedAt  time.Time
}

// CronJobs lists a customer's jobs.
func (s *Store) CronJobs(ctx context.Context, customerID int64) ([]*CronJob, error) {
	rows, err := s.db.Query(ctx, `SELECT id, customer_id, schedule, command, enabled, note, created_at FROM cron_jobs WHERE customer_id=$1 ORDER BY id`, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*CronJob
	for rows.Next() {
		j := &CronJob{}
		if err := rows.Scan(&j.ID, &j.CustomerID, &j.Schedule, &j.Command, &j.Enabled, &j.Note, &j.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// AddCronJob stores a job (checked by the caller).
func (s *Store) AddCronJob(ctx context.Context, j *CronJob) error {
	var n int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM cron_jobs WHERE customer_id=$1`, j.CustomerID).Scan(&n); err != nil {
		return err
	}
	if n >= 100 {
		return errors.New("at most 100 scheduled jobs")
	}
	return s.db.QueryRow(ctx, `INSERT INTO cron_jobs(customer_id, schedule, command, enabled, note) VALUES($1,$2,$3,$4,$5) RETURNING id, created_at`,
		j.CustomerID, strings.TrimSpace(j.Schedule), j.Command, j.Enabled, truncate(strings.TrimSpace(j.Note), 100)).Scan(&j.ID, &j.CreatedAt)
}

// SetCronEnabled switches a job on or off.
func (s *Store) SetCronEnabled(ctx context.Context, customerID, id int64, on bool) error {
	tag, err := s.db.Exec(ctx, `UPDATE cron_jobs SET enabled=$3 WHERE id=$1 AND customer_id=$2`, id, customerID, on)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// DeleteCronJob removes a job.
func (s *Store) DeleteCronJob(ctx context.Context, customerID, id int64) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM cron_jobs WHERE id=$1 AND customer_id=$2`, id, customerID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// SSHKey is a public key of a customer.
type SSHKey struct {
	ID          int64
	CustomerID  int64
	Name        string
	Key         string
	Fingerprint string
	CreatedAt   time.Time
}

// SSHKeys lists a customer's keys.
func (s *Store) SSHKeys(ctx context.Context, customerID int64) ([]*SSHKey, error) {
	rows, err := s.db.Query(ctx, `SELECT id, customer_id, name, key, fingerprint, created_at FROM ssh_keys WHERE customer_id=$1 ORDER BY id`, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*SSHKey
	for rows.Next() {
		k := &SSHKey{}
		if err := rows.Scan(&k.ID, &k.CustomerID, &k.Name, &k.Key, &k.Fingerprint, &k.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// AddSSHKey stores a checked key.
func (s *Store) AddSSHKey(ctx context.Context, k *SSHKey) error {
	n, err := cleanName(k.Name)
	if err != nil {
		return err
	}
	err = s.db.QueryRow(ctx, `INSERT INTO ssh_keys(customer_id, name, key, fingerprint) VALUES($1,$2,$3,$4) RETURNING id`, k.CustomerID, n, k.Key, k.Fingerprint).Scan(&k.ID)
	if isUnique(err) {
		return errors.New("this key is already there")
	}
	return err
}

// DeleteSSHKey removes a key.
func (s *Store) DeleteSSHKey(ctx context.Context, customerID, id int64) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM ssh_keys WHERE id=$1 AND customer_id=$2`, id, customerID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// NoticeDue reports whether a notice with this key may be sent again
// (once per period) and marks it as sent.
func (s *Store) NoticeDue(ctx context.Context, key string, period time.Duration) bool {
	tag, err := s.db.Exec(ctx, `INSERT INTO notices(key, sent_at) VALUES($1,$2) ON CONFLICT (key) DO UPDATE SET sent_at=$2 WHERE notices.sent_at < $3`, key, s.now(), s.now().Add(-period))
	return err == nil && tag.RowsAffected() == 1
}
