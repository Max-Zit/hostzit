package web

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/hosting"
	"github.com/max-zit/hostzit/internal/store"
)

// The link to EmailZit (INTEGRATION.md P7): when the two products run for
// the same customers, EmailZit learns the Linux uids of each hosting
// account, so mail from the websites (emailzit-sendmail) is counted
// against the right customer. The sidebar shows a switch to EmailZit.

const settingEmailZit = "emailzit"

// EmailZitLink is where EmailZit's API is.
type EmailZitLink struct {
	URL      string `json:"url"`   // e.g. https://mail.example.com:8444
	Token    string `json:"token"` // sealed ezt_… token with customers:write
	Insecure bool   `json:"insecure"`
}

func init() {
	adminExtra = append(adminExtra, func(s *Server, mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc)) {
		admin("GET /settings/emailzit", s.handleEmailZit)
		admin("POST /settings/emailzit", s.handleEmailZitSave)
	})
}

func (s *Server) emailzitLink(ctx context.Context) EmailZitLink {
	var l EmailZitLink
	_ = s.store.GetSetting(ctx, settingEmailZit, &l)
	return l
}

func (s *Server) emailzitCall(ctx context.Context, method, path string, body any) error {
	l := s.emailzitLink(ctx)
	if l.URL == "" {
		return nil
	}
	tok, err := s.store.OpenSecret("emailzit.token", l.Token)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(l.URL, "/")+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: l.Insecure}} // #nosec G402 -- only when the administrator allows a self-signed EmailZit
	resp, err := (&http.Client{Timeout: 20 * time.Second, Transport: tr}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 500))
		return fmt.Errorf("EmailZit %s %s: %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

// syncWebUIDs tells EmailZit the uid of a hosting account (empty list when
// the account is gone or not active).
func (s *Server) syncWebUIDs(ctx context.Context, c *store.Customer) {
	if s.emailzitLink(ctx).URL == "" {
		return
	}
	uids := []int{}
	if c.Status == store.StatusActive {
		if u, err := hosting.UID(c.Number); err == nil {
			uids = append(uids, u)
		}
	}
	if err := s.emailzitCall(ctx, http.MethodPut, "/api/v1/customers/"+c.UUID+"/web-uids", map[string]any{"uids": uids}); err != nil {
		s.log.Warn("EmailZit web uids not sent", "customer", c.Username, "err", err)
	}
}

type emailzitData struct {
	L        EmailZitLink
	HasToken bool
}

func (s *Server) handleEmailZit(w http.ResponseWriter, r *http.Request) {
	l := s.emailzitLink(r.Context())
	s.render(w, r, http.StatusOK, "emailzit", &Page{Title: "EmailZit", Nav: "settings", Data: &emailzitData{L: l, HasToken: l.Token != ""}})
}

func (s *Server) handleEmailZitSave(w http.ResponseWriter, r *http.Request) {
	old := s.emailzitLink(r.Context())
	l := EmailZitLink{URL: strings.TrimRight(strings.TrimSpace(r.FormValue("url")), "/"), Insecure: r.FormValue("insecure") != "", Token: old.Token}
	if l.URL != "" && (!strings.HasPrefix(l.URL, "https://") || strings.ContainsAny(l.URL, " \"'<>") || len(l.URL) > 200) {
		s.redirectErr(w, r, "/settings/emailzit", "The address must start with https://")
		return
	}
	if t := strings.TrimSpace(r.FormValue("token")); t != "" {
		if !strings.HasPrefix(t, "ezt_") || len(t) > 200 {
			s.redirectErr(w, r, "/settings/emailzit", "An EmailZit API token starts with ezt_")
			return
		}
		l.Token = s.store.SealSecret("emailzit.token", t)
	}
	if l.URL == "" {
		l = EmailZitLink{}
	}
	if err := s.store.SetSetting(r.Context(), settingEmailZit, l); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.emailzit", "settings", "EmailZit link %q", l.URL)
	// send the uids of all active accounts once
	if l.URL != "" {
		list, _ := s.store.Customers(r.Context(), store.CustomerFilter{})
		for _, c := range list {
			s.syncWebUIDs(r.Context(), c)
		}
	}
	s.redirect(w, r, "/settings/emailzit", "Saved.")
}
