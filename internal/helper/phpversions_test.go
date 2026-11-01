package helper

import (
	"context"
	"testing"
)

func TestPHPCandidates(t *testing.T) {
	out := `php8.4-fpm:
  Installed: 8.4.16-1
  Candidate: 8.4.16-1
  Version table:
php8.3-fpm:
  Installed: (none)
  Candidate: 1:8.3.29-1+0~20251225.1+debian13~1.gbpabc
php7.4-fpm:
  Installed: (none)
  Candidate: (none)
php8.6-fpm:
  Installed: (none)
  Candidate: 8.6.0~rc3-1+0~20261012.3+debian13~1.gbpecfa4e
`
	h := New(&OS{Root: t.TempDir(), Runner: func(_ context.Context, _ []byte, name string, _ ...string) ([]byte, error) {
		if name == "apt-cache" {
			return []byte(out), nil
		}
		return nil, nil
	}})
	res, err := h.phpCandidates(context.Background(), struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	m := res.(map[string]string)
	if m["8.4"] != "8.4.16" || m["8.3"] != "8.3.29" || m["7.4"] != "" || m["8.6"] != "8.6.0~rc3" {
		t.Fatalf("candidates %v", m)
	}
}
