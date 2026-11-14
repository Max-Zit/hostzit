package store

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/max-zit/hostzit/internal/auth"
	"github.com/max-zit/hostzit/internal/netacl"
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
	// AllowedIPs: the token works only from these addresses or networks
	// (empty = from everywhere the admin port may be reached).
	AllowedIPs []string
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

// AllowsIP reports whether the token may be used from ip.
func (t *APIToken) AllowsIP(ip string) bool {
	if len(t.AllowedIPs) == 0 {
		return true
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	ps, err := netacl.Parse(t.AllowedIPs)
	if err != nil {
		return false
	}
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// CleanTokenAddresses checks and normalizes the allowed addresses of a token.
func CleanTokenAddresses(list []string) ([]string, error) {
	if len(list) > 20 {
		return nil, errors.New("a token takes at most 20 addresses or networks")
	}
	ps, err := netacl.Parse(list)
	if err != nil {
		return nil, err
	}
	return netacl.Strings(ps), nil
}

// APITokenPrefix starts every API token (easy to recognise in secret scans).
const APITokenPrefix = "hzt_"

// ErrBadToken is returned for unknown, expired or disabled tokens.
var ErrBadToken = errors.New("invalid API token")

// ErrTokenAddress: the token is valid but not allowed from this address.
var ErrTokenAddress = errors.New("the token may not be used from this address")

// CreateAPIToken makes a token for a user; the plain token is returned once.
// allowed restricts the token to addresses or networks (nil = everywhere).
func (s *Store) CreateAPIToken(ctx context.Context, userID int64, name string, validDays int, scopes, allowed []string) (int64, string, error) {
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
	if allowed, err = CleanTokenAddresses(allowed); err != nil {
		return 0, "", err
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
	err = s.db.QueryRow(ctx, `INSERT INTO api_tokens(user_id, name, token_hash, expires_at, created_at, scopes, allowed_ips) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		userID, name, auth.HashToken("api", tok), exp, s.now(), scopes, allowed).Scan(&id)
	return id, tok, err
}

// APITokens lists a user's tokens.
func (s *Store) APITokens(ctx context.Context, userID int64) ([]APIToken, error) {
	rows, err := s.db.Query(ctx, `SELECT id, user_id, name, created_at, expires_at, last_used, last_ip, scopes, allowed_ips FROM api_tokens WHERE user_id=$1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		if err := rows.Scan(&t.ID, &t.UserID, &t.Name, &t.CreatedAt, &t.ExpiresAt, &t.LastUsed, &t.LastIP, &t.Scopes, &t.AllowedIPs); err != nil {
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

// DeleteAPITokenByID revokes a token whatever its user (the EmailZit link
// keeps the id of the token it handed over).
func (s *Store) DeleteAPITokenByID(ctx context.Context, id int64) error {
	_, err := s.db.Exec(ctx, `DELETE FROM api_tokens WHERE id=$1`, id)
	return err
}

// UserByAPIToken finds the enabled user of a valid token and notes its use.
// A valid token used from an address it does not allow gives
// ErrTokenAddress and is not marked as used.
func (s *Store) UserByAPIToken(ctx context.Context, token, ip string) (*User, *APIToken, error) {
	if !strings.HasPrefix(token, APITokenPrefix) || len(token) > 200 {
		return nil, nil, ErrBadToken
	}
	var t APIToken
	err := s.db.QueryRow(ctx, `SELECT id, user_id, name, created_at, expires_at, scopes, allowed_ips FROM api_tokens WHERE token_hash=$1`, auth.HashToken("api", token)).
		Scan(&t.ID, &t.UserID, &t.Name, &t.CreatedAt, &t.ExpiresAt, &t.Scopes, &t.AllowedIPs)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrBadToken
	}
	if err != nil {
		return nil, nil, err
	}
	if t.ExpiresAt != nil && s.now().After(*t.ExpiresAt) {
		return nil, nil, ErrBadToken
	}
	if !t.AllowsIP(ip) {
		return nil, &t, ErrTokenAddress
	}
	u, err := s.UserByID(ctx, t.UserID)
	if err != nil || u.Disabled {
		return nil, nil, ErrBadToken
	}
	_, _ = s.db.Exec(ctx, `UPDATE api_tokens SET last_used=$2, last_ip=$3 WHERE id=$1`, t.ID, s.now(), truncate(ip, 64))
	return u, &t, nil
}
