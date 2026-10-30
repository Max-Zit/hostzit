package helper

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/hosting"
)

// nginxApply writes files, tests the whole configuration and reloads. When
// the test fails every file is put back as it was, so a broken site never
// takes the server down.
func (h *Helper) nginxApply(ctx context.Context, files map[string][]byte, remove []string) error {
	type old struct {
		data   []byte
		exists bool
	}
	saved := map[string]old{}
	for p := range files {
		b, err := h.Sys.ReadFile(p)
		saved[p] = old{b, err == nil}
	}
	for _, p := range remove {
		b, err := h.Sys.ReadFile(p)
		saved[p] = old{b, err == nil}
	}
	restore := func() {
		for p, o := range saved {
			if o.exists {
				_ = h.Sys.WriteFile(p, o.data, 0o644, 0, 0)
			} else {
				_ = h.Sys.Remove(p)
			}
		}
	}
	for _, p := range hosting.SortedNames(bytesKeys(files)) {
		if err := h.Sys.WriteFile(p, files[p], 0o644, 0, 0); err != nil {
			restore()
			return err
		}
	}
	for _, p := range remove {
		_ = h.Sys.Remove(p)
	}
	if out, err := h.Sys.Run(ctx, nil, "nginx", "-t", "-q"); err != nil {
		restore()
		return fmt.Errorf("the web server refused the new configuration (nothing was changed): %v %s", err, bytes.TrimSpace(out))
	}
	return h.systemctl(ctx, "reload", "nginx")
}

func bytesKeys(m map[string][]byte) map[string]string {
	out := make(map[string]string, len(m))
	for k := range m {
		out[k] = ""
	}
	return out
}

func siteDirs(id int64) (cache, logs, cert string) {
	s := strconv.FormatInt(id, 10)
	return hosting.CacheDir + "/" + s, hosting.SiteLogDir + "/" + s, hosting.CertDir + "/" + s
}

type siteApplyArgs struct {
	Site hosting.Site `json:"site"`
	// Index is the first page of a new site (HTML, only written when the
	// document root does not exist yet).
	Index string `json:"index,omitempty"`
}

// siteApply creates or updates a site.
func (h *Helper) siteApply(ctx context.Context, a siteApplyArgs) (any, error) {
	s := a.Site
	if err := s.Validate(); err != nil {
		return nil, userErr(err.Error())
	}
	if !h.Sys.Exists(hosting.FPMConfPathHost(s.Account, s.PHPVersion)) {
		return nil, userErr("PHP " + s.PHPVersion + " is not set up for this account")
	}
	if len(a.Index) > 64<<10 {
		return nil, userErr("the first page is too large")
	}
	// The document root is created as the account (never by root inside a home).
	if _, err := h.files(ctx, filesArgs{Account: s.Account, Req: WorkerReq{Op: "ensure-site", Path: s.DocRoot, Index: a.Index}}); err != nil {
		return nil, fmt.Errorf("document root: %w", err)
	}
	cache, logs, cert := siteDirs(s.ID)
	if err := h.Sys.Mkdir(logs, 0o750, 0, h.admGID()); err != nil {
		return nil, err
	}
	if s.TLS && !(h.Sys.Exists(cert+"/fullchain.pem") && h.Sys.Exists(cert+"/privkey.pem")) {
		s.TLS = false // the certificate comes later; serve HTTP until then
	}
	files := map[string][]byte{}
	conf, err := hosting.NginxSite(s)
	if err != nil {
		return nil, userErr(err.Error())
	}
	files[hosting.SiteConfPath(s)] = []byte(conf)
	zonePath := hosting.NginxCacheZones + "/" + strconv.FormatInt(s.ID, 10) + ".conf"
	var remove []string
	if s.Cache {
		if err := h.Sys.Mkdir(cache, 0o700, h.nginxUID(), 0); err != nil {
			return nil, err
		}
		z, err := hosting.CacheZoneConf(s)
		if err != nil {
			return nil, err
		}
		files[zonePath] = []byte(z)
	} else {
		remove = append(remove, zonePath)
	}
	// password files of protected folders (only nginx may read them)
	if err := h.Sys.Mkdir(hosting.NginxAuthDir, 0o750, 0, h.nginxGID()); err != nil {
		return nil, err
	}
	prefix := strconv.FormatInt(s.ID, 10) + "-"
	keep := map[string]bool{}
	for i, p := range s.Protected {
		f := hosting.HtpasswdPath(s.ID, i)
		keep[f] = true
		if err := h.Sys.WriteFile(f, []byte(hosting.Htpasswd(p)), 0o640, 0, h.nginxGID()); err != nil {
			return nil, err
		}
	}
	if ents, err := h.Sys.ReadDir(hosting.NginxAuthDir); err == nil {
		for _, e := range ents {
			f := hosting.NginxAuthDir + "/" + e.Name()
			if strings.HasPrefix(e.Name(), prefix) && !keep[f] {
				_ = h.Sys.Remove(f)
			}
		}
	}
	if s.WAF && !h.Sys.Exists(hosting.ModSecConf) {
		return nil, userErr("the web application firewall (ModSecurity) is not installed on this server")
	}
	if err := h.nginxApply(ctx, files, remove); err != nil {
		return nil, err
	}
	if !s.Cache {
		_ = h.Sys.RemoveAll(cache)
	}
	return map[string]any{"tls": s.TLS}, nil
}

type siteRef struct {
	Account string `json:"account"`
	ID      int64  `json:"id"`
	// RemoveFiles also deletes the site's folder (relative to the home).
	RemoveFiles string `json:"remove_files,omitempty"`
}

func (r siteRef) check() error {
	if err := hosting.ValidAccount(r.Account); err != nil {
		return userErr(err.Error())
	}
	if r.ID <= 0 {
		return userErr("site id missing")
	}
	return nil
}

func (h *Helper) siteDelete(ctx context.Context, r siteRef) (any, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	id := strconv.FormatInt(r.ID, 10)
	conf := fmt.Sprintf("%s/%s/%s.conf", hosting.NginxSitesDir, r.Account, id)
	if err := h.nginxApply(ctx, nil, []string{conf, hosting.NginxCacheZones + "/" + id + ".conf"}); err != nil {
		return nil, err
	}
	cache, logs, cert := siteDirs(r.ID)
	for _, p := range []string{cache, logs, cert} {
		_ = h.Sys.RemoveAll(p)
	}
	if r.RemoveFiles != "" {
		if p, err := hosting.CleanRelPath(r.RemoveFiles); err != nil || !strings.HasPrefix(p, "sites/") {
			return nil, userErr("only a folder inside sites/ can be removed")
		}
		if _, err := h.files(ctx, filesArgs{Account: r.Account, Req: WorkerReq{Op: "delete", Path: r.RemoveFiles}}); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// cachePurge empties the page cache of a site ("clear cache"). nginx
// treats a missing cache file as a miss and fetches the page again.
func (h *Helper) cachePurge(ctx context.Context, r siteRef) (any, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	cache, _, _ := siteDirs(r.ID)
	ents, err := h.Sys.ReadDir(cache)
	if err != nil {
		return map[string]int{"removed": 0}, nil
	}
	n := 0
	for _, e := range ents {
		if err := h.Sys.RemoveAll(cache + "/" + e.Name()); err == nil {
			n++
		}
	}
	return map[string]int{"removed": n}, nil
}

type logArgs struct {
	Account string `json:"account"`
	ID      int64  `json:"id"`
	Kind    string `json:"kind"` // access or error
	Lines   int    `json:"lines"`
}

// siteLog returns the last lines of a site's log.
func (h *Helper) siteLog(ctx context.Context, a logArgs) (any, error) {
	if err := (siteRef{Account: a.Account, ID: a.ID}).check(); err != nil {
		return nil, err
	}
	if a.Kind != "access" && a.Kind != "error" {
		return nil, userErr("unknown log")
	}
	if a.Lines < 1 || a.Lines > 5000 {
		a.Lines = 200
	}
	_, logs, _ := siteDirs(a.ID)
	out, err := h.Sys.Run(ctx, nil, "tail", "-n", strconv.Itoa(a.Lines), logs+"/"+a.Kind+".log")
	if err != nil {
		return map[string]string{"text": ""}, nil
	}
	return map[string]string{"text": string(out)}, nil
}

type certArgs struct {
	Account   string `json:"account"`
	ID        int64  `json:"id"`
	FullChain string `json:"fullchain"`
	Key       string `json:"key"`
}

// certInstall stores a site's certificate (root-only key) after checking
// that the key belongs to it. The site is applied again by the panel.
func (h *Helper) certInstall(_ context.Context, a certArgs) (any, error) {
	if err := (siteRef{Account: a.Account, ID: a.ID}).check(); err != nil {
		return nil, err
	}
	if len(a.FullChain) > 64<<10 || len(a.Key) > 16<<10 {
		return nil, userErr("the certificate is too large")
	}
	pair, err := tls.X509KeyPair([]byte(a.FullChain), []byte(a.Key))
	if err != nil {
		return nil, userErr("the certificate and the key do not match: " + err.Error())
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, userErr("invalid certificate")
	}
	if time.Now().After(leaf.NotAfter) {
		return nil, userErr("the certificate has expired")
	}
	if blk, _ := pem.Decode([]byte(a.Key)); blk == nil || !strings.Contains(blk.Type, "PRIVATE KEY") {
		return nil, userErr("the key must be a PEM private key")
	}
	_, _, cert := siteDirs(a.ID)
	if err := h.Sys.Mkdir(cert, 0o700, 0, 0); err != nil {
		return nil, err
	}
	if err := h.Sys.WriteFile(cert+"/privkey.pem", []byte(a.Key), 0o600, 0, 0); err != nil {
		return nil, err
	}
	if err := h.Sys.WriteFile(cert+"/fullchain.pem", []byte(a.FullChain), 0o644, 0, 0); err != nil {
		return nil, err
	}
	return map[string]any{"not_after": leaf.NotAfter, "names": leaf.DNSNames}, nil
}

func (h *Helper) nginxUID() int {
	if id, ok := h.lookupID(context.Background(), "passwd", "www-data"); ok {
		return id
	}
	return 33
}

func (h *Helper) admGID() int {
	if id, ok := h.lookupID(context.Background(), "group", "adm"); ok {
		return id
	}
	return 4
}

func (h *Helper) nginxGID() int {
	if id, ok := h.lookupID(context.Background(), "group", "www-data"); ok {
		return id
	}
	return 33
}
