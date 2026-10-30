package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/max-zit/hostzit/internal/auth"
)

// ---- REST API tokens

// APIToken is a token for the REST API; it acts as its user.
type APIToken struct {
	ID        int64
	UserID    int64
	Name      string
	CreatedAt time.Time
	ExpiresAt *time.Time
	LastUsed  *time.Time
	LastIP    string
	Scopes    []string
}

// Scopes of API tokens.
var Scopes = []string{"customers:read", "customers:write", "usage:read", "sso:create", "dns:mail"}

// HasScope reports whether a token may do something.
func (t *APIToken) HasScope(sc string) bool {
	for _, x := range t.Scopes {
		if x == sc {
			return true
		}
	}
	return false
}

// APITokenPrefix starts every API token (easy to recognise in secret scans).
const APITokenPrefix = "hzt_"

// ErrBadToken is returned for unknown, expired or disabled tokens.
var ErrBadToken = errors.New("invalid API token")

// CreateAPIToken makes a token for a user; the plain token is returned once.
func (s *Store) CreateAPIToken(ctx context.Context, userID int64, name string, validDays int, scopes []string) (int64, string, error) {
	for _, sc := range scopes {
		ok := false
		for _, k := range Scopes {
			ok = ok || k == sc
		}
		if !ok {
			return 0, "", errors.New("unknown scope " + sc)
		}
	}
	if len(scopes) == 0 {
		return 0, "", errors.New("choose what the token may do")
	}
	var err error
	if name, err = cleanName(name); err != nil {
		return 0, "", err
	}
	if validDays < 0 || validDays > 3650 {
		return 0, "", errors.New("a token can be valid for up to 3650 days (0 = no limit)")
	}
	var n int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_tokens WHERE user_id=$1`, userID).Scan(&n); err != nil {
		return 0, "", err
	}
	if n >= 20 {
		return 0, "", errors.New("at most 20 API tokens per user")
	}
	tok := APITokenPrefix + auth.RandomToken(30)
	var exp *time.Time
	if validDays > 0 {
		t := s.now().AddDate(0, 0, validDays)
		exp = &t
	}
	var id int64
	err = s.db.QueryRow(ctx, `INSERT INTO api_tokens(user_id, name, token_hash, expires_at, created_at, scopes) VALUES($1,$2,$3,$4,$5,$6) RETURNING id`,
		userID, name, auth.HashToken("api", tok), exp, s.now(), scopes).Scan(&id)
	return id, tok, err
}

// APITokens lists a user's tokens.
func (s *Store) APITokens(ctx context.Context, userID int64) ([]APIToken, error) {
	rows, err := s.db.Query(ctx, `SELECT id, user_id, name, created_at, expires_at, last_used, last_ip, scopes FROM api_tokens WHERE user_id=$1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		if err := rows.Scan(&t.ID, &t.UserID, &t.Name, &t.CreatedAt, &t.ExpiresAt, &t.LastUsed, &t.LastIP, &t.Scopes); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteAPIToken revokes a token of a user.
func (s *Store) DeleteAPIToken(ctx context.Context, userID, id int64) (string, error) {
	var name string
	err := s.db.QueryRow(ctx, `DELETE FROM api_tokens WHERE id=$1 AND user_id=$2 RETURNING name`, id, userID).Scan(&name)
	return name, notFound(err)
}

// UserByAPIToken finds the enabled user of a valid token and notes its use.
func (s *Store) UserByAPIToken(ctx context.Context, token, ip string) (*User, *APIToken, error) {
	if !strings.HasPrefix(token, APITokenPrefix) || len(token) > 200 {
		return nil, nil, ErrBadToken
	}
	var t APIToken
	err := s.db.QueryRow(ctx, `SELECT id, user_id, name, created_at, expires_at, scopes FROM api_tokens WHERE token_hash=$1`, auth.HashToken("api", token)).
		Scan(&t.ID, &t.UserID, &t.Name, &t.CreatedAt, &t.ExpiresAt, &t.Scopes)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrBadToken
	}
	if err != nil {
		return nil, nil, err
	}
	if t.ExpiresAt != nil && s.now().After(*t.ExpiresAt) {
		return nil, nil, ErrBadToken
	}
	u, err := s.UserByID(ctx, t.UserID)
	if err != nil || u.Disabled {
		return nil, nil, ErrBadToken
	}
	_, _ = s.db.Exec(ctx, `UPDATE api_tokens SET last_used=$2, last_ip=$3 WHERE id=$1`, t.ID, s.now(), truncate(ip, 64))
	return u, &t, nil
}

