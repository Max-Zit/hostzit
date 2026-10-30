package web

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/tlsutil"
)

// The panels get a certificate from the CA (Let's Encrypt) for the server
// name and the host of the customer panel address, like cPanel's
// hostname certificate, so customers see no browser warning. Until then,
// and for any other name (an IP address), the self-signed one answers.

const settingPanelCert = "panelcert"

// PanelCertState is shown under Settings → Hosting.
type PanelCertState struct {
	Names    []string  `json:"names"`
	NotAfter time.Time `json:"not_after"`
	Error    string    `json:"error"`
	Tried    time.Time `json:"tried"`
}

func (s *Server) panelCertFiles() (crt, key string) {
	d := filepath.Join(s.DataDir, "tls")
	return filepath.Join(d, "acme-panel.crt"), filepath.Join(d, "acme-panel.key")
}

// LoadPanelCert loads the CA certificate of the panels when there is one.
func (s *Server) LoadPanelCert() {
	crt, key := s.panelCertFiles()
	if c, err := tls.LoadX509KeyPair(crt, key); err == nil {
		s.panelCert.Store(&c)
	}
}

// PanelTLS is the TLS configuration of both panels: the CA certificate
// for its names, the self-signed one otherwise.
func (s *Server) PanelTLS(selfSigned tls.Certificate) *tls.Config {
	cfg := tlsutil.ServerConfig(selfSigned)
	cfg.GetCertificate = func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if c := s.panelCert.Load(); c != nil && h.ServerName != "" && c.Leaf != nil && c.Leaf.VerifyHostname(h.ServerName) == nil {
			return c, nil
		}
		return &selfSigned, nil
	}
	return cfg
}

// panelNames are the names the panels are reached by: the server name and
// the host of the customer panel address (IP addresses cannot get one).
func panelNames(hs HostingSettings) []string {
	var names []string
	add := func(n string) {
		n = strings.ToLower(strings.TrimSuffix(n, "."))
		if n != "" && net.ParseIP(n) == nil && strings.Contains(n, ".") && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	add(hs.ServerName)
	if u, err := url.Parse(hs.PanelURL); err == nil {
		add(u.Hostname())
	}
	return names
}

// panelCertRound gets or renews the panel certificate when it is due.
func (s *Server) panelCertRound(ctx context.Context, hs HostingSettings) {
	want := panelNames(hs)
	if hs.ACME == "" || len(want) == 0 {
		return
	}
	var st PanelCertState
	_ = s.store.GetSetting(ctx, settingPanelCert, &st)
	if c := s.panelCert.Load(); c != nil && c.Leaf != nil && time.Until(c.Leaf.NotAfter) > 30*24*time.Hour {
		ok := true
		for _, n := range want {
			ok = ok && c.Leaf.VerifyHostname(n) == nil
		}
		if ok {
			return
		}
	}
	// after a failure, try again every six hours (CA rate limits)
	if st.Error != "" && slices.Equal(st.Names, want) && time.Since(st.Tried) < 6*time.Hour {
		return
	}
	st = PanelCertState{Names: want, Tried: time.Now()}
	if err := s.issuePanelCert(ctx, hs, want, &st); err != nil {
		st.Error = err.Error()
		s.log.Warn("panel certificate not issued", "names", want, "err", err)
	}
	_ = s.store.SetSetting(ctx, settingPanelCert, st)
}

func (s *Server) issuePanelCert(ctx context.Context, hs HostingSettings, names []string, st *PanelCertState) error {
	s.acmeMu.Lock()
	defer s.acmeMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	if hs.IPv4 != "" || hs.IPv6 != "" {
		var r net.Resolver
		for _, n := range names {
			addrs, err := r.LookupHost(ctx, n)
			if err != nil || !slices.Contains(addrs, hs.IPv4) && (hs.IPv6 == "" || !slices.Contains(addrs, hs.IPv6)) {
				return &panelCertError{name: n, ip: hs.IPv4}
			}
		}
	}
	chain, keyPEM, leaf, err := s.obtainCert(ctx, hs, names)
	if err != nil {
		return err
	}
	crt, key := s.panelCertFiles()
	if err := os.WriteFile(key, keyPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(crt, chain, 0o600); err != nil {
		return err
	}
	c, err := tls.X509KeyPair(chain, keyPEM)
	if err != nil {
		return err
	}
	s.panelCert.Store(&c)
	st.NotAfter = leaf.NotAfter
	_ = s.store.Audit(ctx, "system", "local", "cert.panel", "server", "panel certificate for "+strings.Join(names, ", ")+" until "+leaf.NotAfter.Format("2006-01-02"))
	return nil
}

type panelCertError struct{ name, ip string }

func (e *panelCertError) Error() string {
	return e.name + " does not point to this server yet (DNS A record " + e.ip + ")"
}
