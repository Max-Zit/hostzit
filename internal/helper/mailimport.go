package helper

import (
	"context"
	"encoding/json"
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

	"github.com/max-zit/hostzit/internal/tlsutil"
)

// The mail of a cPanel account (maildirs, mailboxes, forwarders) belongs to
// EmailZit: after HostZit's own part of a cPanel import the helper sends
// the archive from the root-only import folder to EmailZit's import API
// (POST /api/v1/customers/{id}/import?format=cpanel). EmailZit reads only
// the mail parts and never overwrites mail that is already there.

func init() {
	moreOps = append(moreOps, func(h *Helper) {
		h.ops["import.mail"] = op{handle(h.importMail), false}
	})
}

type mailImportArgs struct {
	File     string `json:"file"`     // a name in ImportDir
	URL      string `json:"url"`      // EmailZit, e.g. https://mail.example.com:8444
	Token    string `json:"token"`    // ezt_… with customers:write (never logged)
	Insecure bool   `json:"insecure"` // EmailZit has a self-signed certificate
	Pin      string `json:"pin"`      // SHA-256 of EmailZit's public key from the pairing code
	Customer string `json:"customer"` // the customer's UUID (the same in both products)
}

var customerUUIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (h *Helper) importMail(ctx context.Context, a mailImportArgs) (any, error) {
	if !importNameRE.MatchString(a.File) {
		return nil, userErr("invalid archive name")
	}
	if !customerUUIDRE.MatchString(a.Customer) {
		return nil, userErr("invalid customer id")
	}
	u, err := url.Parse(a.URL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return nil, userErr("invalid EmailZit address")
	}
	if !strings.HasPrefix(a.Token, "ezt_") || strings.ContainsAny(a.Token, " \r\n") {
		return nil, userErr("invalid EmailZit token")
	}
	f, err := os.OpenFile(h.hostPath(filepath.Join(ImportDir, a.File)), os.O_RDONLY|noFollowFile, 0) // #nosec G304 -- checked name in the root-only import folder
	if err != nil {
		return nil, userErr("archive not found")
	}
	defer f.Close()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(a.URL, "/")+"/api/v1/customers/"+a.Customer+"/import?format=cpanel", f)
	if err != nil {
		return nil, err
	}
	if st, err := f.Stat(); err == nil {
		req.ContentLength = st.Size()
	}
	req.Header.Set("Authorization", "Bearer "+a.Token)
	req.Header.Set("Content-Type", "application/gzip")
	cfg := tlsutil.PinnedConfig(u.Hostname(), a.Pin)
	if a.Pin == "" && a.Insecure {
		cfg.InsecureSkipVerify = true // #nosec G402 -- only when the administrator allowed a self-signed EmailZit (old links typed in by hand)
	}
	tr := &http.Transport{TLSClientConfig: cfg}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		// the address may carry nothing secret, but keep errors short
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("EmailZit: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return nil, userErr(fmt.Sprintf("EmailZit answered %d: %s", resp.StatusCode, strings.TrimSpace(string(body))))
	}
	var out struct {
		JobID string `json:"job_id"`
	}
	_ = json.Unmarshal(body, &out)
	return map[string]string{"job_id": out.JobID}, nil
}

// hostPath is a path on the real system (below the test root in tests).
func (h *Helper) hostPath(p string) string {
	if o, ok := h.Sys.(*OS); ok {
		return o.p(p)
	}
	return p
}
