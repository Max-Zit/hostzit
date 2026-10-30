package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// SecretKeyFile holds the key that encrypts secrets in the database
// (TOTP secrets, later SMTP passwords). It is backed up with the database.
const SecretKeyFile = "secret.key"

// LoadOrCreateSecretKey reads dir/secret.key or creates it.
func LoadOrCreateSecretKey(dir string) (key []byte, created bool, err error) {
	p := filepath.Join(dir, SecretKeyFile)
	b, err := os.ReadFile(p) // #nosec G304 -- path under the data directory
	if err == nil {
		k, err := base64.StdEncoding.DecodeString(string(b))
		if err != nil || len(k) != 32 {
			return nil, false, fmt.Errorf("%s is damaged", p)
		}
		return k, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false, err
	}
	if err := os.WriteFile(p, []byte(base64.StdEncoding.EncodeToString(k)), 0o600); err != nil {
		return nil, false, err
	}
	return k, true, nil
}

// box seals values with AES-256-GCM; the purpose ("users.totp_secret") is
// authenticated so a value cannot be moved to another column.
type box struct{ aead cipher.AEAD }

// UseSecretKey sets the 32-byte encryption key.
func (s *Store) UseSecretKey(key []byte) error {
	if len(key) != 32 {
		return errors.New("secret key must be 32 bytes")
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return err
	}
	s.box = &box{g}
	return nil
}

func (b *box) seal(purpose, plain string) string {
	if plain == "" {
		return ""
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return "v1:" + base64.StdEncoding.EncodeToString(b.aead.Seal(nonce, nonce, []byte(plain), []byte(purpose)))
}

func (b *box) open(purpose, sealed string) (string, error) {
	if sealed == "" {
		return "", nil
	}
	if len(sealed) < 3 || sealed[:3] != "v1:" {
		return "", errors.New("unknown secret format")
	}
	raw, err := base64.StdEncoding.DecodeString(sealed[3:])
	n := b.aead.NonceSize()
	if err != nil || len(raw) < n {
		return "", errors.New("damaged secret")
	}
	out, err := b.aead.Open(nil, raw[:n], raw[n:], []byte(purpose))
	if err != nil {
		return "", errors.New("cannot decrypt secret (wrong secret.key?)")
	}
	return string(out), nil
}

// SealSecret encrypts a setting value (purpose binds it to its place).
func (s *Store) SealSecret(purpose, plain string) string { return s.box.seal(purpose, plain) }

// OpenSecret decrypts a value made by SealSecret.
func (s *Store) OpenSecret(purpose, sealed string) (string, error) {
	return s.box.open(purpose, sealed)
}
