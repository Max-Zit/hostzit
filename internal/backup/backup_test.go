package backup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeDB string

func (f fakeDB) Dump(_ context.Context, w io.Writer) error {
	_, err := io.WriteString(w, string(f))
	return err
}

func TestCreateRestore(t *testing.T) {
	for _, pass := range []string{"", "correct horse battery"} {
		src := t.TempDir()
		_ = os.WriteFile(filepath.Join(src, "secret.key"), []byte("KEY"), 0o600)
		_ = os.MkdirAll(filepath.Join(src, "tls"), 0o700)
		_ = os.WriteFile(filepath.Join(src, "tls", "console.key"), []byte("AGENT"), 0o600)
		_ = os.MkdirAll(filepath.Join(src, "logs"), 0o700)
		_ = os.WriteFile(filepath.Join(src, "logs", "server.log"), []byte("not in a backup"), 0o600)
		big := strings.Repeat("database rows ", 20000) // several encryption chunks
		var buf bytes.Buffer
		m, err := Create(context.Background(), fakeDB(big), src, t.TempDir(), "0.11.0", pass, &buf)
		if err != nil {
			t.Fatal(err)
		}
		if len(m.Files) != 2 {
			t.Fatalf("files %v", m.Files)
		}
		if pass != "" {
			if bytes.Contains(buf.Bytes(), []byte("AGENT")) || !bytes.HasPrefix(buf.Bytes(), []byte(encMagic)) {
				t.Fatal("not encrypted")
			}
			if _, err := Inspect(bytes.NewReader(buf.Bytes()), "wrong"); !errors.Is(err, ErrPassphrase) {
				t.Fatalf("wrong passphrase: %v", err)
			}
			var gotDB string
			_, err := Restore(context.Background(), bytes.NewReader(buf.Bytes()[:buf.Len()-100]), pass, t.TempDir(), func(_ context.Context, r io.Reader) error {
				b, err := io.ReadAll(r)
				gotDB = string(b)
				return err
			})
			if err == nil {
				t.Fatalf("a cut file restored (%d bytes of database)", len(gotDB))
			}
		}
		dst := t.TempDir()
		var gotDB string
		m2, err := Restore(context.Background(), bytes.NewReader(buf.Bytes()), pass, dst, func(_ context.Context, r io.Reader) error {
			b, err := io.ReadAll(r)
			gotDB = string(b)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if gotDB != big || m2.ServerVersion != "0.11.0" {
			t.Fatal("database or manifest differ")
		}
		if b, _ := os.ReadFile(filepath.Join(dst, "tls", "console.key")); string(b) != "AGENT" {
			t.Fatal("tls file not restored")
		}
		if _, err := os.Stat(filepath.Join(dst, "logs")); err == nil {
			t.Fatal("logs restored")
		}
	}
}

func TestSafeRel(t *testing.T) {
	for p, ok := range map[string]bool{"secret.key": true, "tls/console.key": true, "library/a/b.msi": false,
		"../etc/passwd": false, "tls/../../x": false, "/etc/passwd": false, "logs/x": false, "tls\\x": false, "": false} {
		if safeRel(p) != ok {
			t.Errorf("safeRel(%q) = %v", p, !ok)
		}
	}
}
