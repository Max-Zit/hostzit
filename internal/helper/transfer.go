package helper

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/hosting"
)

// Moving an account to another HostZit server: the source helper sends the
// account's archive to the target panel's API; the target panel stores it
// in its own folder and the target helper adopts it into the import folder.

// TransferDir is where the panel (user hostzit) receives archives.
const TransferDir = "/var/lib/hostzit/panel/transfer"

var transferNameRE = regexp.MustCompile(`^hostzit-[a-z0-9-]{1,80}\.tar\.gz$`)

type dbHashArgs struct {
	Account string `json:"account"`
}

// dbHashes returns the password hashes of the account's database users
// (account_…), so a move keeps the passwords.
func (h *Helper) dbHashes(ctx context.Context, a dbHashArgs) (any, error) {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return nil, userErr(err.Error())
	}
	out, err := h.sql(ctx, "SELECT User, authentication_string FROM mysql.user WHERE Host='localhost' AND User LIKE '"+strings.ReplaceAll(a.Account, "_", `\_`)+`\_%'`)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		u, hsh, ok := strings.Cut(l, "\t")
		if ok && strings.HasPrefix(u, a.Account+"_") && nativeHashRE.MatchString(hsh) {
			m[u] = hsh
		}
	}
	return m, nil
}

type adoptArgs struct {
	Name string `json:"name"`
}

// importAdopt moves an archive the panel received into the import folder.
func (h *Helper) importAdopt(_ context.Context, a adoptArgs) (any, error) {
	if !transferNameRE.MatchString(a.Name) {
		return nil, userErr("invalid archive name")
	}
	src := filepath.Join(TransferDir, a.Name)
	fi, err := os.Lstat(src)
	if err != nil || !fi.Mode().IsRegular() {
		return nil, userErr("archive not found")
	}
	if err := os.MkdirAll(ImportDir, 0o700); err != nil {
		return nil, err
	}
	dst := filepath.Join(ImportDir, a.Name)
	if err := os.Rename(src, dst); err != nil {
		return nil, err
	}
	// the panel's folder could have swapped the file meanwhile
	if fi, err := os.Lstat(dst); err != nil || !fi.Mode().IsRegular() {
		_ = os.Remove(dst)
		return nil, userErr("archive not found")
	}
	_ = os.Chown(dst, 0, 0)
	return nil, os.Chmod(dst, 0o600)
}

type sendArgs struct {
	Account     string `json:"account"`
	Name        string `json:"name"` // archive in the account's private tmp
	URL         string `json:"url"`  // the target's admin panel, https://host:8442
	Token       string `json:"token"`
	Fingerprint string `json:"fingerprint"` // SHA-256 of the target's certificate (hex), or "" for normal checks
}

// TransferClient is an HTTPS client for the target panel: with a
// fingerprint it accepts exactly that certificate (self-signed panels),
// without one the usual checks apply.
func TransferClient(fingerprint string, timeout time.Duration) *http.Client {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if fp := strings.ToLower(strings.ReplaceAll(fingerprint, ":", "")); fp != "" {
		cfg.InsecureSkipVerify = true // #nosec G402 -- replaced by the fingerprint check below
		// VerifyConnection also runs for resumed sessions
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if hex.EncodeToString(sum[:]) != fp {
				return errors.New("the target's certificate does not match the confirmed fingerprint")
			}
			return nil
		}
	}
	return &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: cfg, Proxy: http.ProxyFromEnvironment}}
}

// CheckTargetURL accepts https://host[:port] without a path.
func CheckTargetURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.User != nil || u.RawQuery != "" {
		return "", errors.New("enter the target's admin panel as https://host:port")
	}
	return "https://" + u.Host, nil
}

// transferSend streams the archive to the target and deletes it here.
func (h *Helper) transferSend(ctx context.Context, a sendArgs) (any, error) {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return nil, userErr(err.Error())
	}
	if !transferNameRE.MatchString(a.Name) {
		return nil, userErr("invalid archive name")
	}
	base, err := CheckTargetURL(a.URL)
	if err != nil {
		return nil, userErr(err.Error())
	}
	if a.Token == "" || len(a.Token) > 200 || strings.ContainsAny(a.Token, "\r\n ") {
		return nil, userErr("invalid API token")
	}
	path := filepath.Join(hosting.TmpDir(a.Account), a.Name)
	defer os.Remove(path)
	f, err := os.OpenFile(path, os.O_RDONLY|noFollowFile, 0) // #nosec G304 -- checked name in the account's tmp
	if err != nil {
		return nil, userErr("archive not found")
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, userErr("archive not found")
	}
	uid, _ := h.lookupID(ctx, "passwd", a.Account)
	if owner, ok := fileOwner(fi); !fi.Mode().IsRegular() || !ok || owner != uid {
		return nil, userErr("archive not found")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, base+"/api/v1/transfers/"+a.Name, f)
	if err != nil {
		return nil, err
	}
	req.ContentLength = fi.Size()
	req.Header.Set("Authorization", "Bearer "+a.Token)
	req.Header.Set("Content-Type", "application/gzip")
	resp, err := TransferClient(a.Fingerprint, 12*time.Hour).Do(req)
	if err != nil {
		return nil, userErr("sending failed: " + err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return nil, userErr(fmt.Sprintf("the target refused the archive (%s): %s", resp.Status, strings.TrimSpace(string(body))))
	}
	return map[string]any{"size": fi.Size()}, nil
}

func init() {
	moreOps = append(moreOps, func(h *Helper) {
		h.ops["db.hashes"] = op{handle(h.dbHashes), false}
		h.ops["import.adopt"] = op{handle(h.importAdopt), false}
		h.ops["transfer.send"] = op{handle(h.transferSend), false} // hours of upload must not block other changes
		h.ops["backup.transfer"] = op{handle(h.backupTransfer), false}
		h.ops["import.manifest"] = op{handle(h.importManifest), false}
	})
}

// backupTransfer makes the account's archive in its private tmp for
// transferSend (name = hostzit-….tar.gz).
func (h *Helper) backupTransfer(ctx context.Context, a backupArgs) (any, error) {
	a.toTmp = true
	if _, err := h.backupCreate(ctx, a); err != nil {
		return nil, err
	}
	return map[string]string{"name": a.Name + ".tar.gz"}, nil
}

type manifestArgs struct {
	File string `json:"file"`
}

// importManifest reads hostzit-manifest.json out of an archive in the
// import folder (nothing is unpacked to disk).
func (h *Helper) importManifest(ctx context.Context, a manifestArgs) (any, error) {
	if !importNameRE.MatchString(a.File) {
		return nil, userErr("invalid archive name")
	}
	p := filepath.Join(ImportDir, a.File)
	if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
		return nil, userErr("archive not found")
	}
	// the manifest is added without ./ (see backupCreate)
	out, err := h.Sys.Run(ctx, nil, "tar", "-xzOf", p, "hostzit-manifest.json")
	if err != nil || len(out) == 0 {
		return map[string]string{"manifest": ""}, nil // not a HostZit archive
	}
	if len(out) > 1<<20 {
		return nil, userErr("manifest too large")
	}
	return map[string]string{"manifest": string(out)}, nil
}

// TransferName reports a valid name of a received archive.
func TransferName(n string) bool { return transferNameRE.MatchString(n) }
