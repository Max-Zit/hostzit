package update

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func signed(t *testing.T, m Manifest) ([]byte, []byte, string) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw, _ := json.Marshal(m)
	return raw, Sign(raw, priv), base64.StdEncoding.EncodeToString(pub)
}

func TestVerify(t *testing.T) {
	m := Manifest{Product: "hostzit", Version: "0.3.0", Files: []File{{Name: "hostzit-server_0.3.0_amd64.deb", SHA256: strings.Repeat("a", 64), Kind: "server", Format: "deb"}}}
	raw, sig, key := signed(t, m)
	got, err := Verify(raw, sig, []string{key})
	if err != nil || got.Version != "0.3.0" || got.Find("server", "deb", "") == nil {
		t.Fatalf("good manifest: %v", err)
	}
	if _, err := Verify(append(raw, ' '), sig, []string{key}); err == nil {
		t.Fatal("changed manifest accepted")
	}
	_, _, other := signed(t, m)
	if _, err := Verify(raw, sig, []string{other}); err == nil {
		t.Fatal("manifest of another key accepted")
	}
	for _, bad := range []Manifest{
		{Product: "backupzit", Version: "0.3.0"},
		{Product: "hostzit", Version: "0.3.0; rm -rf /"},
		{Product: "hostzit", Version: "0.3.0", Files: []File{{Name: "../evil.deb", SHA256: strings.Repeat("a", 64)}}},
	} {
		raw, sig, key := signed(t, bad)
		if _, err := Verify(raw, sig, []string{key}); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestFetchAndDownload(t *testing.T) {
	pkg := []byte("package bytes")
	h := sha256.Sum256(pkg)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := Manifest{Product: "hostzit", Version: "0.4.0", Files: []File{{Name: "hostzit-server_0.4.0_amd64.deb", SHA256: hex.EncodeToString(h[:]), Size: int64(len(pkg)), Kind: "server", Format: "deb"}}}
	raw, _ := json.Marshal(m)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/manifest.json"):
			_, _ = w.Write(raw)
		case strings.HasSuffix(r.URL.Path, "/manifest.json.sig"):
			_, _ = w.Write(Sign(raw, priv))
		case strings.HasSuffix(r.URL.Path, ".deb"):
			if strings.Contains(r.URL.Path, "bad") {
				_, _ = w.Write([]byte("tampered"))
				return
			}
			_, _ = w.Write(pkg)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	old := TrustedKeys
	TrustedKeys = []string{base64.StdEncoding.EncodeToString(pub)}
	defer func() { TrustedKeys = old }()
	got, _, _, err := Fetch(context.Background(), srv.Client(), srv.URL, "")
	if err != nil || got.Version != "0.4.0" {
		t.Fatalf("fetch: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "pkg.deb")
	if err := Download(context.Background(), srv.Client(), srv.URL, "", got.Files[0], dst); err != nil {
		t.Fatalf("download: %v", err)
	}
	if b, _ := os.ReadFile(dst); string(b) != string(pkg) {
		t.Fatal("wrong content")
	}
	bad := got.Files[0]
	bad.Name = "bad.deb"
	if err := Download(context.Background(), srv.Client(), srv.URL, "", bad, dst); err == nil {
		t.Fatal("tampered package accepted")
	}
	if _, err := os.Stat(dst); err == nil {
		t.Fatal("tampered package left on disk")
	}
}

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"0.3.0", "0.2.34", true}, {"0.2.34", "0.3.0", false}, {"1.0.0", "1.0.0", false}, {"0.2.10", "0.2.9", true}, {"0.3.0", "0.3.0-dev", false}} {
		if Newer(c.a, c.b) != c.want {
			t.Errorf("Newer(%s, %s)", c.a, c.b)
		}
	}
}
