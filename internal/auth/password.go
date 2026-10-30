// Package auth holds the credential primitives of the console: argon2id
// password hashes, TOTP second factors, recovery codes and random tokens.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (OWASP recommendation: m=64 MiB, t=3, p=4 is well
// above the minimum of m=19 MiB, t=2, p=1).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
)

// MinPasswordLen is the shortest password the console accepts.
const MinPasswordLen = 12

// ErrWeakPassword is returned for passwords that are too short or too long.
var ErrWeakPassword = fmt.Errorf("the password must be between %d and 256 characters", MinPasswordLen)

// CheckPasswordPolicy validates a new password.
func CheckPasswordPolicy(pw string) error {
	if n := utf8.RuneCountInString(pw); n < MinPasswordLen || len(pw) > 256 {
		return ErrWeakPassword
	}
	return nil
}

// HashPassword returns an encoded argon2id hash in the PHC string format.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword reports whether pw matches the encoded hash.
func VerifyPassword(encoded, pw string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("unknown password hash format")
	}
	var v int
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return false, errors.New("unsupported argon2 version")
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m == 0 || t == 0 || p == 0 || m > 1<<21 || t > 64 {
		return false, errors.New("bad argon2 parameters")
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) == 0 || len(want) > 64 {
		return false, errors.New("bad argon2 hash")
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want))) // #nosec G115 -- len(want) <= 64
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// dummyHash is verified against when a username does not exist, so the
// time of a failed sign-in does not tell whether the user exists.
var dummyHash, _ = HashPassword("hostzit-no-such-user")

// BurnTime spends the time of one password verification.
func BurnTime(pw string) { _, _ = VerifyPassword(dummyHash, pw) }

// RandomToken returns n random bytes, URL-safe base64 encoded.
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashToken is the stored form of a bearer token (session, enrollment):
// tokens have 256 bits of entropy, so a plain SHA-256 is enough.
func HashToken(purpose, token string) string {
	h := sha256.Sum256([]byte("hostzit:" + purpose + ":" + token))
	return hex.EncodeToString(h[:])
}
