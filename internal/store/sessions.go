package store

import (
	"context"
	"time"

	"github.com/max-zit/hostzit/internal/auth"
)

// Session stages.
const (
	StageMFA  = "mfa"  // password verified, second factor pending
	StageFull = "full" // signed in
)

// MFATimeout is how long a password-verified sign-in waits for the code.
const MFATimeout = 5 * time.Minute

// Session is a sign-in.
type Session struct {
	Hash      string
	UserID    int64
	Stage     string
	CreatedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
	IP        string
	UserAgent string
	// ActingAdmin is the administrator working in a customer panel ("log in as").
	ActingAdmin string
}

// CreateSession starts a session and returns the cookie value.
func (s *Store) CreateSession(ctx context.Context, userID int64, stage string, life time.Duration, ip, ua string) (string, *Session, error) {
	tok := auth.RandomToken(32)
	now := s.now()
	if len(ua) > 300 {
		ua = ua[:300]
	}
	x := &Session{Hash: auth.HashToken("session", tok), UserID: userID, Stage: stage, CreatedAt: now, LastSeen: now, ExpiresAt: now.Add(life), IP: ip, UserAgent: ua}
	_, err := s.db.Exec(ctx, `INSERT INTO sessions(token_hash, user_id, stage, created_at, last_seen, expires_at, ip, user_agent) VALUES($1,$2,$3,$4,$4,$5,$6,$7)`,
		x.Hash, userID, stage, now, x.ExpiresAt, ip, ua)
	return tok, x, err
}

// CreateActingSession starts a full session of a customer user for an
// administrator ("log in as"); the panel shows a banner and every action is
// audited with both names.
func (s *Store) CreateActingSession(ctx context.Context, userID int64, admin string, life time.Duration, ip, ua string) (string, error) {
	tok, x, err := s.CreateSession(ctx, userID, StageFull, life, ip, ua)
	if err != nil {
		return "", err
	}
	_, err = s.db.Exec(ctx, `UPDATE sessions SET acting_admin=$2 WHERE token_hash=$1`, x.Hash, truncate(admin, 100))
	return tok, err
}

// SessionByToken loads a session by cookie value; expired or idle sessions
// are deleted and reported as ErrNotFound. idle 0 disables the idle check.
func (s *Store) SessionByToken(ctx context.Context, tok string, idle time.Duration) (*Session, error) {
	if tok == "" {
		return nil, ErrNotFound
	}
	x := &Session{Hash: auth.HashToken("session", tok)}
	err := s.db.QueryRow(ctx, `SELECT user_id, stage, created_at, last_seen, expires_at, ip, user_agent, acting_admin FROM sessions WHERE token_hash=$1`, x.Hash).
		Scan(&x.UserID, &x.Stage, &x.CreatedAt, &x.LastSeen, &x.ExpiresAt, &x.IP, &x.UserAgent, &x.ActingAdmin)
	if err != nil {
		return nil, notFound(err)
	}
	now := s.now()
	if now.After(x.ExpiresAt) || (idle > 0 && x.Stage == StageFull && now.Sub(x.LastSeen) > idle) {
		_ = s.DeleteSession(ctx, x.Hash)
		return nil, ErrNotFound
	}
	return x, nil
}

// TouchSession updates the last activity (at most once a minute).
func (s *Store) TouchSession(ctx context.Context, x *Session) error {
	now := s.now()
	if now.Sub(x.LastSeen) < time.Minute {
		return nil
	}
	x.LastSeen = now
	_, err := s.db.Exec(ctx, `UPDATE sessions SET last_seen=$2 WHERE token_hash=$1`, x.Hash, now)
	return err
}

// PromoteSession turns a second-factor-pending sign-in into a full session
// under a NEW token (the pre-auth token must not become a session token).
func (s *Store) PromoteSession(ctx context.Context, x *Session, life time.Duration) (string, error) {
	if err := s.DeleteSession(ctx, x.Hash); err != nil {
		return "", err
	}
	tok, _, err := s.CreateSession(ctx, x.UserID, StageFull, life, x.IP, x.UserAgent)
	return tok, err
}

// DeleteSession signs a session out.
func (s *Store) DeleteSession(ctx context.Context, hash string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM sessions WHERE token_hash=$1`, hash)
	return err
}

// UserSessions lists the sessions of a user.
func (s *Store) UserSessions(ctx context.Context, userID int64) ([]Session, error) {
	rows, err := s.db.Query(ctx, `SELECT token_hash, stage, created_at, last_seen, expires_at, ip, user_agent FROM sessions WHERE user_id=$1 AND stage='full' ORDER BY last_seen DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		x := Session{UserID: userID}
		if err := rows.Scan(&x.Hash, &x.Stage, &x.CreatedAt, &x.LastSeen, &x.ExpiresAt, &x.IP, &x.UserAgent); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// PurgeSessions deletes expired sessions.
func (s *Store) PurgeSessions(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `DELETE FROM sessions WHERE expires_at < $1`, s.now())
	return err
}
