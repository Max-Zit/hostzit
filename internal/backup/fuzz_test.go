package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Console backups are uploaded on the restore page: a crafted archive must
// not write outside the data directory or crash the console.

func FuzzInspect(f *testing.F) {
	var plain, enc bytes.Buffer
	src := f.TempDir()
	_ = os.WriteFile(filepath.Join(src, "secret.key"), []byte("KEY"), 0o600)
	if _, err := Create(context.Background(), fakeDB("rows"), src, f.TempDir(), "0.9.1", "", &plain); err != nil {
		f.Fatal(err)
	}
	if _, err := Create(context.Background(), fakeDB("rows"), src, f.TempDir(), "0.9.1", "pw", &enc); err != nil {
		f.Fatal(err)
	}
	f.Add(plain.Bytes(), "")
	f.Add(enc.Bytes(), "pw")
	f.Add([]byte(encMagic+"short"), "pw")
	f.Fuzz(func(t *testing.T, b []byte, pass string) {
		_, _ = Inspect(bytes.NewReader(b), pass)
	})
}

func FuzzRestoreEntries(f *testing.F) {
	f.Add("files/secret.key", "files/tls/console.key", byte(tar.TypeReg), []byte("x"))
	f.Add("files/../outside", "files/tls/../../x", byte(tar.TypeReg), []byte("x"))
	f.Add("files/tls", "files/tls/a", byte(tar.TypeSymlink), []byte("/etc"))
	f.Fuzz(func(t *testing.T, n1, n2 string, typ byte, data []byte) {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		add := func(name string, typ byte, b []byte) {
			h := &tar.Header{Name: name, Typeflag: typ, Mode: 0o600, Size: int64(len(b))}
			if typ != tar.TypeReg {
				h.Size, h.Linkname = 0, string(b)
				b = nil
			}
			if tw.WriteHeader(h) == nil {
				_, _ = tw.Write(b)
			}
		}
		add(manifestName, tar.TypeReg, []byte(`{"product":"HostZit","format":1}`))
		add(databaseName, tar.TypeReg, []byte("db"))
		add(n1, typ, data)
		add(n2, tar.TypeReg, data)
		_ = tw.Close()
		_ = gz.Close()

		root := t.TempDir()
		dataDir := filepath.Join(root, "data")
		_ = os.MkdirAll(dataDir, 0o700)
		_, _ = Restore(context.Background(), &buf, "", dataDir, func(_ context.Context, r io.Reader) error {
			_, err := io.Copy(io.Discard, r)
			return err
		})
		ents, _ := os.ReadDir(root)
		if len(ents) != 1 {
			t.Fatalf("restore of %q / %q wrote outside the data directory", n1, n2)
		}
		_ = filepath.WalkDir(dataDir, func(p string, d os.DirEntry, err error) error {
			if err == nil && d.Type()&os.ModeSymlink != 0 {
				t.Fatalf("symlink %s restored", p)
			}
			if rel, _ := filepath.Rel(dataDir, p); err == nil && rel != "." {
				top, _, _ := strings.Cut(filepath.ToSlash(rel), "/")
				if !strings.Contains(strings.Join(DataFiles, " "), top) {
					t.Fatalf("unexpected file %s", rel)
				}
			}
			return nil
		})
	})
}
