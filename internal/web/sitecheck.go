package web

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"time"
)

// siteProbes are where the website check connects, in order: the local
// web server over HTTPS (the site's own certificate, by SNI), then plain
// HTTP for sites without a certificate. Tests point them elsewhere.
var siteProbes = []string{"https://127.0.0.1", "http://127.0.0.1"}

// siteHealthy tells whether a website answers its home page without a
// server error or WordPress's "critical error" page. Redirects (to www,
// to another page) count as healthy; an unreachable site does not.
func (s *Server) siteHealthy(ctx context.Context, domain string) bool {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for _, base := range siteProbes {
		ok, answered := probeSite(ctx, base, domain)
		if answered {
			return ok
		}
	}
	return false
}

func probeSite(ctx context.Context, base, domain string) (ok, answered bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
	if err != nil {
		return false, false
	}
	req.Host = domain
	req.Header.Set("User-Agent", "HostZit site check")
	hc := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{TLSClientConfig: &tls.Config{ServerName: domain, MinVersion: tls.VersionTLS12,
			// #nosec G402 -- connection to this server itself (127.0.0.1); the certificate may still be pending, and only the answer of the page matters
			InsecureSkipVerify: true}},
	}
	resp, err := hc.Do(req)
	if err != nil {
		return false, false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return resp.StatusCode < 500 && !strings.Contains(string(b), "There has been a critical error on this website"), true
}
