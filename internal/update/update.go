// Package update finds and verifies HostZit releases. Every release has
// a manifest.json listing its files with their SHA-256, and
// manifest.json.sig, an Ed25519 signature of the manifest made with the
// offline release key. Consoles, the root helper and install.sh trust only
// manifests signed with one of TrustedKeys, so a changed download, a
// compromised mirror or a fake release is refused.
package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// TrustedKeys are the public release keys (base64 Ed25519). A new key is
// added here one release before it signs.
var TrustedKeys = []string{"m6v0l8smmYzzu/067UcjEIa7OwhXq/npz9VngRrs/K0="}

// DefaultSource is where releases are published.
const DefaultSource = "https://github.com/Max-Zit/hostzit/releases"

// File is one file of a release.
type File struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	// Kind is server, agent or other; Format deb, rpm, msi, exe or bin;
	// Platform e.g. linux-amd64.
	Kind     string `json:"kind"`
	Format   string `json:"format,omitempty"`
	Platform string `json:"platform,omitempty"`
}

// Manifest describes a release.
type Manifest struct {
	Product  string    `json:"product"`
	Version  string    `json:"version"`
	Released time.Time `json:"released"`
	Notes    string    `json:"notes,omitempty"`
	Files    []File    `json:"files"`
}

var versionRe = regexp.MustCompile(`^\d{1,4}\.\d{1,4}\.\d{1,4}$`)

// Verify checks the signature of a manifest and parses it.
func Verify(raw, sig []byte, keys []string) (*Manifest, error) {
	s, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(s) != ed25519.SignatureSize {
		return nil, errors.New("the release signature is malformed")
	}
	ok := false
	for _, k := range keys {
		pub, err := base64.StdEncoding.DecodeString(k)
		if err == nil && len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, raw, s) {
			ok = true
			break
		}
	}
	if !ok {
		return nil, errors.New("the release is not signed with a HostZit release key")
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("the release manifest is unreadable: %w", err)
	}
	if m.Product != "hostzit" || !versionRe.MatchString(m.Version) {
		return nil, errors.New("the release manifest is not a HostZit release")
	}
	for _, f := range m.Files {
		if !SafeName(f.Name) || len(f.SHA256) != 64 {
			return nil, fmt.Errorf("the release lists a bad file %q", f.Name)
		}
	}
	return &m, nil
}

// SafeName accepts plain file names (no paths).
func SafeName(n string) bool {
	return n != "" && len(n) < 200 && !strings.ContainsAny(n, `/\`) && !strings.Contains(n, "..") && n[0] != '.'
}

// Sign signs a manifest (tools/relsign).
func Sign(raw []byte, key ed25519.PrivateKey) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw)) + "\n")
}

// Find returns the file of a kind, format and platform.
func (m *Manifest) Find(kind, format, platform string) *File {
	for i := range m.Files {
		f := &m.Files[i]
		if f.Kind == kind && (format == "" || f.Format == format) && (platform == "" || f.Platform == platform) {
			return f
		}
	}
	return nil
}

// Base is the download location of a version (latest when empty).
func Base(source, version string) string {
	source = strings.TrimRight(source, "/")
	if !strings.HasPrefix(source, "https://github.com/") {
		return source // a mirror or a local directory: files side by side
	}
	if version == "" {
		return source + "/latest/download"
	}
	return source + "/download/v" + version
}

// Fetch downloads and verifies the manifest of a version (latest when
// empty).
func Fetch(ctx context.Context, hc *http.Client, source, version string) (*Manifest, []byte, []byte, error) {
	base := Base(source, version)
	raw, err := get(ctx, hc, base+"/manifest.json", 1<<20)
	if err != nil {
		return nil, nil, nil, err
	}
	sig, err := get(ctx, hc, base+"/manifest.json.sig", 4096)
	if err != nil {
		return nil, nil, nil, err
	}
	m, err := Verify(raw, sig, TrustedKeys)
	return m, raw, sig, err
}

func get(ctx context.Context, hc *http.Client, url string, limit int64) ([]byte, error) {
	if strings.HasPrefix(url, "file://") {
		return os.ReadFile(strings.TrimPrefix(url, "file://")) // #nosec G304 -- an administrator's local release directory
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "HostZit")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err == nil && int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is too large", url)
	}
	return b, err
}

// Download saves a file of the release to path and checks its SHA-256.
func Download(ctx context.Context, hc *http.Client, source, version string, f File, path string) error {
	url := Base(source, version) + "/" + f.Name
	var src io.Reader
	if strings.HasPrefix(url, "file://") {
		in, err := os.Open(strings.TrimPrefix(url, "file://")) // #nosec G304 -- an administrator's local release directory
		if err != nil {
			return err
		}
		defer in.Close()
		src = in
	} else {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
		}
		src = resp.Body
	}
	out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- the caller's work directory
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(src, 1<<30))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != strings.ToLower(f.SHA256) || (f.Size > 0 && n != f.Size) {
		_ = os.Remove(path)
		return fmt.Errorf("%s does not match the signed release", f.Name)
	}
	return nil
}

// Newer reports whether version a is newer than b (dotted numbers).
func Newer(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(strings.SplitN(pa[i], "-", 2)[0])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(strings.SplitN(pb[i], "-", 2)[0])
		}
		if x != y {
			return x > y
		}
	}
	return false
}
