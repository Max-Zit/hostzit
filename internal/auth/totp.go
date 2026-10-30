package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6238 TOTP uses HMAC-SHA1; authenticator apps expect it
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"rsc.io/qr"
)

// TOTP (RFC 6238): 30-second steps, 6 digits, HMAC-SHA1, as used by
// Microsoft/Google Authenticator, Authy, 1Password, Bitwarden …

const totpStep = 30

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random 160-bit secret, base32 encoded.
func NewTOTPSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b32.EncodeToString(b)
}

// TOTPCode is the code of a time step.
func TOTPCode(secret string, step int64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) // #nosec G115 -- steps are positive
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000), nil
}

// TOTPVerify accepts the code of the current step or one step around it,
// but never a step at or before lastUsed (no replay). It returns the step.
func TOTPVerify(secret, code string, now time.Time, lastUsed int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return 0, false
	}
	cur := now.Unix() / totpStep
	for _, c := range []int64{cur, cur - 1, cur + 1} {
		if c <= lastUsed {
			continue
		}
		want, err := TOTPCode(secret, c)
		if err == nil && hmac.Equal([]byte(want), []byte(code)) {
			return c, true
		}
	}
	return 0, false
}

// TOTPURI is the otpauth:// link an authenticator app reads from the QR code.
func TOTPURI(secret, account string) string {
	v := url.Values{"secret": {secret}, "issuer": {"HostZit"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + url.PathEscape("HostZit:"+account) + "?" + v.Encode()
}

// QR is a QR code as squares for an inline SVG (no images, CSP friendly).
type QR struct {
	Size  int
	Cells []struct{ X, Y int }
}

// QRFor encodes text as a QR code with a 4-module quiet zone.
func QRFor(text string) (*QR, error) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return nil, err
	}
	q := &QR{Size: c.Size + 8}
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.Black(x, y) {
				q.Cells = append(q.Cells, struct{ X, Y int }{x + 4, y + 4})
			}
		}
	}
	return q, nil
}

// HashRecoveryCode is the stored form of a recovery code.
func HashRecoveryCode(c string) string {
	c = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(c), "-", ""))
	h := sha256.Sum256([]byte("hostzit-recovery-code:" + c))
	return hex.EncodeToString(h[:])
}

// NewRecoveryCodes returns 10 one-time codes (XXXX-XXXX) and their hashes.
func NewRecoveryCodes() (plain, hashed []string) {
	for i := 0; i < 10; i++ {
		b := make([]byte, 5)
		if _, err := rand.Read(b); err != nil {
			panic(err)
		}
		c := b32.EncodeToString(b) // 8 chars
		plain = append(plain, c[:4]+"-"+c[4:])
		hashed = append(hashed, HashRecoveryCode(c))
	}
	return plain, hashed
}
