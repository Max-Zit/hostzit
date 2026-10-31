package store

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/auth"
)

// Roles.
const (
	RoleAdmin    = "admin"    // everything, including users and settings
	RoleOperator = "operator" // manage devices, checks, maps and alerts
	RoleViewer   = "viewer"   // view only
	RoleCustomer = "customer" // a hosting customer (customer panel only)
)

// ValidRole reports a known role.
func ValidRole(r string) bool { return r == RoleAdmin || r == RoleOperator || r == RoleViewer }

// IsStaff reports a role of the admin panel.
func (u *User) IsStaff() bool { return u != nil && u.Role != RoleCustomer }

// IsCustomer reports a customer panel user.
func (u *User) IsCustomer() bool { return u != nil && u.Role == RoleCustomer && u.CustomerID != nil }

// User is a console account.
type User struct {
	ID                 int64
	Username           string
	DisplayName        string
	Role               string
	TOTPEnabled        bool
	MustChangePassword bool
	Disabled           bool
	Lang               string
	Email              string
	CustomerID         *int64
	CreatedAt          time.Time
	LastLoginAt        *time.Time
}

// IsAdmin reports the admin role.
func (u *User) IsAdmin() bool { return u != nil && u.Role == RoleAdmin }

// CanWrite reports whether the user may change things (not a viewer).
func (u *User) CanWrite() bool { return u != nil && (u.Role == RoleAdmin || u.Role == RoleOperator) }

var usernameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{1,63}$`)

// ValidUsername checks the allowed characters of a username.
func ValidUsername(u string) error {
	if !usernameRE.MatchString(u) {
		return errors.New("the username must be 2–64 characters: letters, digits, dot, dash, underscore or @")
	}
	return nil
}

const userCols = `id, username, display_name, role, totp_enabled, must_change_password, disabled, lang, email, customer_id, created_at, last_login_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	u := &User{}
	err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role, &u.TOTPEnabled, &u.MustChangePassword,
		&u.Disabled, &u.Lang, &u.Email, &u.CustomerID, &u.CreatedAt, &u.LastLoginAt)
	return u, err
}

// UserCount is the number of accounts (0 = setup not done).
func (s *Store) UserCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM users WHERE role<>'customer'`).Scan(&n)
	return n, err
}

// NewUser describes an account to create.
type NewUser struct {
	Username, DisplayName, Password, Role string
	MustChangePassword                    bool
}

// CreateUser adds an account. The second factor is set up at the first sign-in.
func (s *Store) CreateUser(ctx context.Context, n NewUser) (*User, error) {
	n.Username = strings.TrimSpace(n.Username)
	if err := ValidUsername(n.Username); err != nil {
		return nil, err
	}
	if !ValidRole(n.Role) {
		return nil, errors.New("unknown role")
	}
	if err := auth.CheckPasswordPolicy(n.Password); err != nil {
		return nil, err
	}
	h, err := auth.HashPassword(n.Password)
	if err != nil {
		return nil, err
	}
	var id int64
	err = s.db.QueryRow(ctx, `INSERT INTO users(username, display_name, password_hash, role, must_change_password)
		VALUES($1,$2,$3,$4,$5) RETURNING id`, n.Username, strings.TrimSpace(n.DisplayName), h, n.Role, n.MustChangePassword).Scan(&id)
	if isUnique(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return s.UserByID(ctx, id)
}

// UserByID loads an account.
func (s *Store) UserByID(ctx context.Context, id int64) (*User, error) {
	u, err := scanUser(s.db.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id=$1`, id))
	if err != nil {
		return nil, notFound(err)
	}
	return u, nil
}

// Users lists all accounts.
func (s *Store) Users(ctx context.Context) ([]*User, error) {
	rows, err := s.db.Query(ctx, `SELECT `+userCols+` FROM users WHERE role<>'customer' ORDER BY lower(username)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// CheckPassword verifies a sign-in. It returns ErrNotFound for unknown or
// disabled users and for a wrong password, and spends the same time in
// every case.
func (s *Store) CheckPassword(ctx context.Context, username, password string) (*User, error) {
	var id int64
	var hash string
	var disabled bool
	err := s.db.QueryRow(ctx, `SELECT id, password_hash, disabled FROM users WHERE lower(username)=lower($1)`, strings.TrimSpace(username)).
		Scan(&id, &hash, &disabled)
	if err != nil {
		auth.BurnTime(password)
		return nil, notFound(err)
	}
	ok, err := auth.VerifyPassword(hash, password)
	if err != nil {
		return nil, err
	}
	if !ok || disabled {
		return nil, ErrNotFound
	}
	return s.UserByID(ctx, id)
}

// SetPassword changes a password and signs the user out everywhere else
// (keepSession is the hash of the session to keep, or "").
func (s *Store) SetPassword(ctx context.Context, userID int64, password string, mustChange bool, keepSession string) error {
	if err := auth.CheckPasswordPolicy(password); err != nil {
		return err
	}
	h, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	tag, err := s.db.Exec(ctx, `UPDATE users SET password_hash=$2, must_change_password=$3 WHERE id=$1`, userID, h, mustChange)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	_, err = s.db.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1 AND token_hash<>$2`, userID, keepSession)
	return err
}

// UpdateUser changes the name, role and state of an account.
func (s *Store) UpdateUser(ctx context.Context, id int64, displayName, role string, disabled bool) error {
	if !ValidRole(role) {
		return errors.New("unknown role")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE users SET display_name=$2, role=$3, disabled=$4 WHERE id=$1`,
		id, strings.TrimSpace(displayName), role, disabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	// A guard against removing the last way in.
	var admins int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM users WHERE role='admin' AND NOT disabled`).Scan(&admins); err != nil {
		return err
	}
	if admins == 0 {
		return errors.New("at least one enabled administrator must remain")
	}
	if disabled {
		if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1`, id); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// SetLang stores the console language of a user.
func (s *Store) SetLang(ctx context.Context, userID int64, lang string) error {
	_, err := s.db.Exec(ctx, `UPDATE users SET lang=$2 WHERE id=$1`, userID, lang)
	return err
}

// MarkLogin records a successful sign-in.
func (s *Store) MarkLogin(ctx context.Context, userID int64) error {
	_, err := s.db.Exec(ctx, `UPDATE users SET last_login_at=$2 WHERE id=$1`, userID, s.now())
	return err
}

// ---- second factor

// TwoFactor is a user's second factor state.
type TwoFactor struct {
	Enabled  bool
	Secret   string // decrypted
	LastStep int64
	Codes    []string // hashes of unused recovery codes
}

// GetTwoFactor loads and decrypts the TOTP state.
func (s *Store) GetTwoFactor(ctx context.Context, userID int64) (TwoFactor, error) {
	var t TwoFactor
	var sealed string
	err := s.db.QueryRow(ctx, `SELECT totp_enabled, totp_secret, totp_last_step, recovery_codes FROM users WHERE id=$1`, userID).
		Scan(&t.Enabled, &sealed, &t.LastStep, &t.Codes)
	if err != nil {
		return t, notFound(err)
	}
	t.Secret, err = s.box.open("users.totp_secret", sealed)
	return t, err
}

// SetPendingTOTP stores a new secret that is not confirmed yet. It refuses
// to replace an enabled factor (use ResetTwoFactor first).
func (s *Store) SetPendingTOTP(ctx context.Context, userID int64, secret string) error {
	tag, err := s.db.Exec(ctx, `UPDATE users SET totp_secret=$2, totp_last_step=0 WHERE id=$1 AND NOT totp_enabled`,
		userID, s.box.seal("users.totp_secret", secret))
	if err == nil && tag.RowsAffected() == 0 {
		return errors.New("two-factor sign-in is already set up")
	}
	return err
}

// EnableTOTP confirms the pending secret with a valid code and stores the
// hashes of new recovery codes.
func (s *Store) EnableTOTP(ctx context.Context, userID, step int64, recoveryHashes []string) error {
	tag, err := s.db.Exec(ctx, `UPDATE users SET totp_enabled=true, totp_last_step=$2, recovery_codes=$3 WHERE id=$1 AND NOT totp_enabled AND totp_secret<>''`,
		userID, step, recoveryHashes)
	if err == nil && tag.RowsAffected() == 0 {
		return errors.New("no pending two-factor setup")
	}
	return err
}

// UseTOTPStep records the last accepted step; it fails when another
// request used the same or a later step in the meantime (no replay).
func (s *Store) UseTOTPStep(ctx context.Context, userID, step int64) (bool, error) {
	tag, err := s.db.Exec(ctx, `UPDATE users SET totp_last_step=$2 WHERE id=$1 AND totp_last_step<$2`, userID, step)
	return err == nil && tag.RowsAffected() == 1, err
}

// UseRecoveryCode consumes a recovery code.
func (s *Store) UseRecoveryCode(ctx context.Context, userID int64, code string) (bool, error) {
	h := auth.HashRecoveryCode(code)
	tag, err := s.db.Exec(ctx, `UPDATE users SET recovery_codes=array_remove(recovery_codes,$2) WHERE id=$1 AND $2=ANY(recovery_codes)`, userID, h)
	return err == nil && tag.RowsAffected() == 1, err
}

// SetRecoveryCodes replaces the recovery codes.
func (s *Store) SetRecoveryCodes(ctx context.Context, userID int64, hashes []string) error {
	_, err := s.db.Exec(ctx, `UPDATE users SET recovery_codes=$2 WHERE id=$1 AND totp_enabled`, userID, hashes)
	return err
}

// ResetTwoFactor removes the second factor (an administrator does this for
// a user who lost the phone); the user sets it up again at the next sign-in.
func (s *Store) ResetTwoFactor(ctx context.Context, userID int64) error {
	tag, err := s.db.Exec(ctx, `UPDATE users SET totp_enabled=false, totp_secret='', totp_last_step=0, recovery_codes='{}' WHERE id=$1`, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	_, err = s.db.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1`, userID)
	return err
}

// StaffByEmail finds an administrator, operator or viewer by e-mail address.
func (s *Store) StaffByEmail(ctx context.Context, email string) (*User, error) {
	u, err := scanUser(s.db.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE role<>'customer' AND lower(email)=lower($1) AND email<>''`, strings.TrimSpace(email)))
	if err != nil {
		return nil, notFound(err)
	}
	return u, nil
}

// SetEmail stores the e-mail address of a user.
func (s *Store) SetEmail(ctx context.Context, id int64, email string) error {
	e, err := CleanEmail(email)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `UPDATE users SET email=$2 WHERE id=$1`, id, e)
	return err
}

// PasswordHash returns a user's password hash (moving a customer to
// another server keeps the password).
func (s *Store) PasswordHash(ctx context.Context, userID int64) (string, error) {
	var h string
	err := s.db.QueryRow(ctx, `SELECT password_hash FROM users WHERE id=$1`, userID).Scan(&h)
	return h, err
}

// SetPasswordHash stores a hash made on another HostZit server.
func (s *Store) SetPasswordHash(ctx context.Context, userID int64, hash string) error {
	if !strings.HasPrefix(hash, "$argon2id$v=19$") || len(hash) > 300 || strings.ContainsAny(hash, " \r\n") {
		return errors.New("invalid password hash")
	}
	_, err := s.db.Exec(ctx, `UPDATE users SET password_hash=$2, must_change_password=false WHERE id=$1`, userID, hash)
	return err
}
