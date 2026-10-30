package web

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/max-zit/hostzit/internal/store"
)

// Websites get certificates from an ACME CA (Let's Encrypt) with HTTP-01:
// the panel writes the answer into the challenge folder nginx serves for
// every host name. The certificate key is made here, handed to the helper
// (which stores it where only root can read it) and then forgotten.

const (
	letsEncrypt        = "https://acme-v02.api.letsencrypt.org/directory"
	letsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

func acmeDirectory(setting string) string {
	switch setting {
	case "letsencrypt":
		return letsEncrypt
	case "letsencrypt-staging":
		return letsEncryptStaging
	}
	return setting
}

var certKick = make(chan struct{}, 1)

// kickCerts asks the certificate loop to look now.
func (s *Server) kickCerts() {
	select {
	case certKick <- struct{}{}:
	default:
	}
}

func (s *Server) runCerts(ctx context.Context) {
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for {
		s.certRound(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-certKick:
			// a new site: give nginx a moment to load it
			time.Sleep(3 * time.Second)
		}
	}
}

func (s *Server) certRound(ctx context.Context) {
	hs := s.hostingSettings(ctx)
	if hs.ACME == "" {
		return
	}
	s.panelCertRound(ctx, hs)
	sites, err := s.store.CertsDue(ctx)
	if err != nil {
		s.log.Warn("certificate check failed", "err", err)
		return
	}
	for i, x := range sites {
		if i >= 20 || ctx.Err() != nil {
			return // a few per round: stays inside the CA's rate limits
		}
		if err := s.issueCert(ctx, hs, x); err != nil {
			s.log.Warn("certificate not issued", "site", x.Domain, "err", err)
			_ = s.store.SetCert(ctx, x.ID, "failed", err.Error(), nil, nil)
		}
	}
}

// reachableNames keeps the names of a site that resolve to this server.
func (s *Server) reachableNames(ctx context.Context, hs HostingSettings, x *store.Site) ([]string, error) {
	names := x.Spec(false, 0).Names()
	if hs.IPv4 == "" && hs.IPv6 == "" {
		return names, nil
	}
	var ok []string
	var r net.Resolver
	for _, n := range names {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err := r.LookupHost(c, n)
		cancel()
		if err == nil && (slices.Contains(addrs, hs.IPv4) || hs.IPv6 != "" && slices.Contains(addrs, hs.IPv6)) {
			ok = append(ok, n)
		}
	}
	if !slices.Contains(ok, x.Domain) {
		return nil, fmt.Errorf("%s does not point to this server yet (DNS A record %s)", x.Domain, hs.IPv4)
	}
	return ok, nil
}

func (s *Server) acmeClient(ctx context.Context, hs HostingSettings) (*acme.Client, error) {
	dir := acmeDirectory(hs.ACME)
	key, err := s.acmeAccountKey()
	if err != nil {
		return nil, err
	}
	c := &acme.Client{Key: key, DirectoryURL: dir, UserAgent: "HostZit/" + s.Version}
	var contact []string
	if hs.ACMEEmail != "" {
		contact = []string{"mailto:" + hs.ACMEEmail}
	}
	_, err = c.Register(ctx, &acme.Account{Contact: contact}, acme.AcceptTOS)
	if err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("ACME account: %w", err)
	}
	return c, nil
}

func (s *Server) acmeAccountKey() (crypto.Signer, error) {
	p := filepath.Join(s.DataDir, "acme-account.key")
	if b, err := os.ReadFile(p); err == nil { // #nosec G304 -- our data directory
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, errors.New("invalid ACME account key")
		}
		return x509.ParseECPrivateKey(blk.Bytes)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

// issueCert gets and installs a certificate for a site.
func (s *Server) issueCert(ctx context.Context, hs HostingSettings, x *store.Site) error {
	s.acmeMu.Lock()
	defer s.acmeMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	names, err := s.reachableNames(ctx, hs, x)
	if err != nil {
		return err
	}
	_ = s.store.SetCert(ctx, x.ID, "pending", "", nil, nil)
	chain, keyPEM, leaf, err := s.obtainCert(ctx, hs, names)
	if err != nil {
		return err
	}
	if err := s.call(ctx, "system", "cert.install", map[string]any{"account": x.Account, "id": x.ID, "fullchain": string(chain),
		"key": string(keyPEM)}, nil); err != nil {
		return err
	}
	na := leaf.NotAfter
	if err := s.store.SetCert(ctx, x.ID, "ok", "", &na, names); err != nil {
		return err
	}
	x.CertStatus = "ok"
	if err := s.applySite(ctx, "system", x, false); err != nil {
		return err
	}
	_ = s.store.Audit(ctx, "system", "local", "cert.issue", "site:"+x.Domain, "certificate for "+strings.Join(names, ", ")+" until "+na.Format("2006-01-02"))
	return nil
}

// obtainCert gets a certificate for names from the CA (HTTP-01 through
// the shared challenge folder that nginx serves on port 80).
func (s *Server) obtainCert(ctx context.Context, hs HostingSettings, names []string) (chain, keyPEM []byte, leaf *x509.Certificate, err error) {
	cl, err := s.acmeClient(ctx, hs)
	if err != nil {
		return nil, nil, nil, err
	}
	order, err := cl.AuthorizeOrder(ctx, acme.DomainIDs(names...))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("order: %w", err)
	}
	var written []string
	defer func() {
		for _, f := range written {
			_ = os.Remove(f)
		}
	}()
	for _, u := range order.AuthzURLs {
		z, err := cl.GetAuthorization(ctx, u)
		if err != nil {
			return nil, nil, nil, err
		}
		if z.Status == acme.StatusValid {
			continue
		}
		var ch *acme.Challenge
		for _, c := range z.Challenges {
			if c.Type == "http-01" {
				ch = c
			}
		}
		if ch == nil {
			return nil, nil, nil, fmt.Errorf("%s: the CA offers no HTTP challenge", z.Identifier.Value)
		}
		resp, err := cl.HTTP01ChallengeResponse(ch.Token)
		if err != nil {
			return nil, nil, nil, err
		}
		if strings.ContainsAny(ch.Token, "/\\.") {
			return nil, nil, nil, errors.New("invalid challenge token")
		}
		f := filepath.Join(s.ACMEChallengeDir, ch.Token)
		if err := os.WriteFile(f, []byte(resp), 0o644); err != nil { // #nosec G306 -- nginx must read the answer
			return nil, nil, nil, fmt.Errorf("challenge file: %w", err)
		}
		written = append(written, f)
		if _, err := cl.Accept(ctx, ch); err != nil {
			return nil, nil, nil, err
		}
		if _, err := cl.WaitAuthorization(ctx, z.URI); err != nil {
			return nil, nil, nil, fmt.Errorf("%s: %w", z.Identifier.Value, err)
		}
	}
	if order, err = cl.WaitOrder(ctx, order.URI); err != nil {
		return nil, nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: names[0]}, DNSNames: names}, key)
	if err != nil {
		return nil, nil, nil, err
	}
	der, _, err := cl.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("certificate: %w", err)
	}
	for _, c := range der {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c})...)
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	if leaf, err = x509.ParseCertificate(der[0]); err != nil {
		return nil, nil, nil, err
	}
	return chain, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), leaf, nil
}
