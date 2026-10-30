package auth

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("unexpected hash format %q", h)
	}
	if ok, err := VerifyPassword(h, "correct horse battery"); !ok || err != nil {
		t.Fatalf("right password rejected: %v %v", ok, err)
	}
	if ok, _ := VerifyPassword(h, "correct horse batterY"); ok {
		t.Fatal("wrong password accepted")
	}
	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Fatal("salt not random")
	}
	for _, bad := range []string{"", "$argon2i$v=19$m=1,t=1,p=1$AA$AA", "$argon2id$v=19$m=99999999,t=1,p=1$AA$AA"} {
		if ok, err := VerifyPassword(bad, "x"); ok || err == nil {
			t.Errorf("bad hash %q accepted", bad)
		}
	}
}

func TestPasswordPolicy(t *testing.T) {
	if CheckPasswordPolicy("short") == nil {
		t.Error("short password accepted")
	}
	if CheckPasswordPolicy(strings.Repeat("a", 257)) == nil {
		t.Error("too long password accepted")
	}
	if CheckPasswordPolicy("twelve chars") != nil {
		t.Error("12-character password rejected")
	}
}

func TestTOTPRFC6238(t *testing.T) {
	// RFC 6238 appendix B, SHA1, secret "12345678901234567890".
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	for _, c := range []struct {
		t    int64
		code string
	}{{59, "287082"}, {1111111109, "081804"}, {1234567890, "005924"}, {2000000000, "279037"}} {
		got, err := TOTPCode(secret, c.t/30)
		if err != nil || got != c.code {
			t.Errorf("t=%d: got %s want %s (%v)", c.t, got, c.code, err)
		}
	}
}

func TestTOTPVerifyNoReplay(t *testing.T) {
	secret := NewTOTPSecret()
	now := time.Unix(1_800_000_000, 0)
	code, _ := TOTPCode(secret, now.Unix()/30)
	step, ok := TOTPVerify(secret, code, now, 0)
	if !ok {
		t.Fatal("current code rejected")
	}
	if _, ok := TOTPVerify(secret, code, now, step); ok {
		t.Fatal("replayed code accepted")
	}
	old, _ := TOTPCode(secret, now.Unix()/30-3)
	if _, ok := TOTPVerify(secret, old, now, 0); ok {
		t.Fatal("code from 90 s ago accepted")
	}
	if _, ok := TOTPVerify(secret, "12345", now, 0); ok {
		t.Fatal("5-digit code accepted")
	}
}

func TestRecoveryCodes(t *testing.T) {
	plain, hashed := NewRecoveryCodes()
	if len(plain) != 10 || len(hashed) != 10 {
		t.Fatal("want 10 codes")
	}
	if HashRecoveryCode(strings.ToLower(plain[0])) != hashed[0] {
		t.Fatal("recovery code must be case-insensitive")
	}
	if HashRecoveryCode(strings.ReplaceAll(plain[1], "-", "")) != hashed[1] {
		t.Fatal("recovery code must ignore the dash")
	}
}

func TestQR(t *testing.T) {
	q, err := QRFor(TOTPURI(NewTOTPSecret(), "admin"))
	if err != nil || q.Size < 25 || len(q.Cells) == 0 {
		t.Fatalf("qr: %v", err)
	}
}
