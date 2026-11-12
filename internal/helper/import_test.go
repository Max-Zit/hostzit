package helper

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTarGz(t *testing.T, p string, names ...string) {
	t.Helper()
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	z := gzip.NewWriter(f)
	tw := tar.NewWriter(z)
	for _, n := range names {
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("x"))
	}
	_ = tw.Close()
	_ = z.Close()
	_ = f.Close()
}

// A cPanel archive is recognised from its first entry, without reading the
// whole archive (6 GB took about 8 minutes on the first real import).
func TestArchiveTop(t *testing.T) {
	dir := t.TempDir()
	for want, first := range map[string]string{
		"backup-11.12.2026_11-41-01_sportiko": "backup-11.12.2026_11-41-01_sportiko/userdata/main",
		"cpmove-shop":                         "./cpmove-shop/mysql.sql",
		"hostzit-manifest.json":               "hostzit-manifest.json",
	} {
		p := filepath.Join(dir, want+".tar.gz")
		writeTarGz(t, p, first, "other")
		if got := archiveTop(p); got != want {
			t.Errorf("%s: %q", first, got)
		}
	}
	bad := filepath.Join(dir, "bad.tar.gz")
	_ = os.WriteFile(bad, []byte("not gzip"), 0o600)
	if got := archiveTop(bad); got != "" {
		t.Errorf("broken archive: %q", got)
	}
}

// An archive that changed within the last minute is probably still being
// copied: it is not offered for import.
func TestImportListSkipsFreshFiles(t *testing.T) {
	h, _, root, _ := newTest(t)
	dir := filepath.Join(root, filepath.FromSlash(ImportDir))
	_ = os.MkdirAll(dir, 0o700)
	_ = os.WriteFile(filepath.Join(dir, "cpmove-old.tar.gz"), []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "cpmove-new.tar.gz"), []byte("x"), 0o600)
	old := time.Now().Add(-2 * time.Minute)
	_ = os.Chtimes(filepath.Join(dir, "cpmove-old.tar.gz"), old, old)
	r := call(t, h, "import.list", struct{}{})
	if !r.OK {
		t.Fatal(r.Error)
	}
	var files []ImportFile
	if err := json.Unmarshal(r.Result, &files); err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Name != "cpmove-old.tar.gz" {
		t.Fatalf("listed %+v", files)
	}
}
