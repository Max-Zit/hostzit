package web

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// cspCache keeps the settings form-action depends on for a short time, so
// the header of every response does not read the database.
type cspCache struct {
	mu           sync.Mutex
	at           time.Time
	panelURL     string // Settings → Hosting → customer panel address
	oidcRedirect string // redirect URI of the OIDC client (EmailZit)
}

func (s *Server) cspSettings(ctx context.Context) (panelURL, oidcRedirect string) {
	c := &s.csp
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.at.IsZero() || time.Since(c.at) > 30*time.Second {
		c.panelURL = s.hostingSettings(ctx).PanelURL
		c.oidcRedirect = s.oidcClient(ctx).RedirectURI
		c.at = time.Now()
	}
	return c.panelURL, c.oidcRedirect
}

// formActionSrc is the form-action source list: 'self' and the origins a
// form may end up on through redirects. Chrome applies form-action to the
// whole redirect chain of a form submission, so up to 0.9.4 "Open the
// customer panel" (admin panel → customer panel port) and the EmailZit
// sign-in through HostZit (customer sign-in → EmailZit's redirect URI) did
// nothing in Chrome; found on h1.
func (s *Server) formActionSrc(r *http.Request) string {
	src := []string{"'self'"}
	add := func(u string) {
		p, err := url.Parse(u)
		if err != nil || p.Host == "" || p.Scheme != "https" && p.Scheme != "http" {
			return
		}
		o := p.Scheme + "://" + p.Host
		if strings.ContainsAny(o, " ;,'\"\r\n") || slices.Contains(src, o) {
			return
		}
		src = append(src, o)
	}
	panel, oidc := s.cspSettings(r.Context())
	switch {
	case r.TLS == nil && s.DevPanelHTTP != "":
		add("http://" + s.DevPanelHTTP)
	case panel != "":
		add(panel)
	default:
		add(s.panelURLOf(r))
	}
	if oidc != "" {
		add(oidc)
	}
	return strings.Join(src, " ")
}

// cspForget drops the cached settings after they changed.
func (s *Server) cspForget() {
	s.csp.mu.Lock()
	s.csp.at = time.Time{}
	s.csp.mu.Unlock()
}
