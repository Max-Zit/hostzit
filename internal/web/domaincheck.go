package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/auth"
	"github.com/max-zit/hostzit/internal/store"
)

// Domain ownership check (Settings → Sign-in and security): when it is on,
// a customer can add a domain (website, alias, DNS zone) only after showing
// that it is theirs, like a certificate authority checks it:
//   - the domain already points at this server (A/AAAA record), or
//   - its name servers are this server's name servers, or
//   - the TXT record _hostzit-verify.<domain> holds the customer's token.
// Names below a zone the customer already has need no check, and
// administrators can always add any domain for a customer.

const settingDomainKey = "domain_verify_key"

// resolver is the part of net.Resolver the check uses (tests replace it).
type resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
}

var domainResolver resolver = net.DefaultResolver

// domainToken is the TXT value for one customer and domain; it stays the
// same until the key setting is removed.
func (s *Server) domainToken(ctx context.Context, c *store.Customer, dom string) (string, error) {
	var key string
	if err := s.store.GetSetting(ctx, settingDomainKey, &key); err != nil || key == "" {
		key = auth.RandomToken(32)
		if err := s.store.SetSetting(ctx, settingDomainKey, key); err != nil {
			return "", err
		}
	}
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte(strconv.FormatInt(c.ID, 10) + "|" + dom))
	return "hostzit-verify=" + hex.EncodeToString(m.Sum(nil))[:32], nil
}

// ownershipError tells the customer how to prove the domain is theirs.
type ownershipError struct {
	Domain, IP, Nameservers, Token string
}

func (e *ownershipError) Error() string { return e.text("en") }

func (e *ownershipError) text(lang string) string {
	return translate(lang, "To add %s, show that it is yours: point it at this server (%s), set its name servers to %s, or add the TXT record _hostzit-verify.%s with the value %s, then try again.",
		e.Domain, e.IP, e.Nameservers, e.Domain, e.Token)
}

// pageErr is an error for the page in the user's language.
func pageErr(lang string, err error) string {
	var oe *ownershipError
	if errors.As(err, &oe) {
		return oe.text(lang)
	}
	return translate(lang, err.Error())
}

// checkOwnership is nil when the check is off, the domain is below a zone
// of the customer, or DNS shows the domain is the customer's.
func (s *Server) checkOwnership(ctx context.Context, c *store.Customer, dom string) error {
	if !s.security(ctx).DomainCheck {
		return nil
	}
	if z, err := s.store.ZoneFor(ctx, dom); err == nil && z.CustomerID == c.ID {
		return nil
	}
	tok, err := s.domainToken(ctx, c, dom)
	if err != nil {
		return err
	}
	hs := s.hostingSettings(ctx)
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if txt, err := domainResolver.LookupTXT(ctx, "_hostzit-verify."+dom); err == nil && slices.Contains(txt, tok) {
		return nil
	}
	if addrs, err := domainResolver.LookupIPAddr(ctx, dom); err == nil {
		for _, a := range addrs {
			if (hs.IPv4 != "" && a.IP.Equal(net.ParseIP(hs.IPv4))) || (hs.IPv6 != "" && a.IP.Equal(net.ParseIP(hs.IPv6))) {
				return nil
			}
		}
	}
	if nss, err := domainResolver.LookupNS(ctx, dom); err == nil && len(nss) > 0 {
		ours := 0
		for _, ns := range nss {
			if slices.Contains(hs.Nameservers, strings.TrimSuffix(strings.ToLower(ns.Host), ".")) {
				ours++
			}
		}
		if ours == len(nss) {
			return nil
		}
	}
	ip := hs.IPv4
	if ip == "" {
		ip = hs.IPv6
	}
	return &ownershipError{Domain: dom, IP: ip, Nameservers: strings.Join(hs.Nameservers, ", "), Token: tok}
}
