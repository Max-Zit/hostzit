package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// GetSetting reads a JSON setting into v; a missing key leaves v unchanged.
func (s *Store) GetSetting(ctx context.Context, key string, v any) error {
	var raw []byte
	err := s.db.QueryRow(ctx, `SELECT value FROM settings WHERE key=$1`, key).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// SetSetting stores v as JSON.
func (s *Store) SetSetting(ctx context.Context, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `INSERT INTO settings(key, value) VALUES($1,$2) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value`, key, raw)
	return err
}

// ---- sign-in blocks

// Block is a blocked client address.
type Block struct {
	IP      string
	Until   time.Time
	Strikes int
	Reason  string
}

// BlockIP blocks an address; strikes counts blocks within a day.
func (s *Store) BlockIP(ctx context.Context, ip string, d func(strikes int) time.Duration, reason string) (Block, error) {
	now := s.now()
	b := Block{IP: ip, Reason: reason}
	err := s.db.QueryRow(ctx, `INSERT INTO login_blocks(ip, until, strikes, reason, updated_at) VALUES($1,$2,1,$3,$2)
		ON CONFLICT (ip) DO UPDATE SET strikes = CASE WHEN login_blocks.updated_at > $2 - interval '24 hours' THEN login_blocks.strikes+1 ELSE 1 END,
		reason=EXCLUDED.reason, updated_at=$2 RETURNING strikes`, ip, now, reason).Scan(&b.Strikes)
	if err != nil {
		return b, err
	}
	b.Until = now.Add(d(b.Strikes))
	_, err = s.db.Exec(ctx, `UPDATE login_blocks SET until=$2 WHERE ip=$1`, ip, b.Until)
	return b, err
}

// BlockedUntil returns the end of an active block of ip, or zero.
func (s *Store) BlockedUntil(ctx context.Context, ip string) (time.Time, error) {
	var t time.Time
	err := s.db.QueryRow(ctx, `SELECT until FROM login_blocks WHERE ip=$1 AND until > $2`, ip, s.now()).Scan(&t)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, nil
	}
	return t, err
}

// Blocks lists active blocks.
func (s *Store) Blocks(ctx context.Context) ([]Block, error) {
	rows, err := s.db.Query(ctx, `SELECT ip, until, strikes, reason FROM login_blocks WHERE until > $1 ORDER BY until DESC`, s.now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Block
	for rows.Next() {
		var b Block
		if err := rows.Scan(&b.IP, &b.Until, &b.Strikes, &b.Reason); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// Unblock lifts the block of ip, or of all addresses for "all".
func (s *Store) Unblock(ctx context.Context, ip string) (int64, error) {
	var tag interface{ RowsAffected() int64 }
	var err error
	if ip == "all" {
		tag, err = s.db.Exec(ctx, `DELETE FROM login_blocks`)
	} else {
		tag, err = s.db.Exec(ctx, `DELETE FROM login_blocks WHERE ip=$1`, ip)
	}
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
