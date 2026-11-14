package web

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"
)

// Warnings on a website's page (the same two EmailZit shows on its domain
// page): the name points at a proxy in front of the server instead of at
// the server, and the domain's mail (MX) goes elsewhere than the linked
// EmailZit.

// proxyNets are the published ranges of Cloudflare's proxy (orange cloud).
var proxyNets = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
		"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14",
		"172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
		"2a06:98c0::/29", "2c0f:f248::/32"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func behindProxy(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	for _, p := range proxyNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// mxLookup finds the MX of a domain (tests replace it).
var mxLookup = func(ctx context.Context, name string) ([]*net.MX, error) {
	return net.DefaultResolver.LookupMX(ctx, name)
}

// dnsWarning is one note: Kind "proxy" (Name points at a proxy) or "mx"
// (the mail of Name goes to MX, not to EmailZit's MailHost).
type dnsWarning struct {
	Kind, Name, MX, MailHost string
}

// dnsWarnings are the notes for a website's names.
func (s *Server) dnsWarnings(ctx context.Context, names []string, mailDomain, mailHost string) []dnsWarning {
	hs := s.hostingSettings(ctx)
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	var out []dnsWarning
	for _, n := range names {
		addrs, err := domainResolver.LookupIPAddr(ctx, n)
		if err != nil || len(addrs) == 0 {
			continue
		}
		here, proxy := false, false
		for _, a := range addrs {
			here = here || hs.IPv4 != "" && a.IP.Equal(net.ParseIP(hs.IPv4)) || hs.IPv6 != "" && a.IP.Equal(net.ParseIP(hs.IPv6))
			proxy = proxy || behindProxy(a.IP)
		}
		if proxy && !here {
			out = append(out, dnsWarning{Kind: "proxy", Name: n})
		}
	}
	if mailDomain != "" && mailHost != "" {
		if mx, err := mxLookup(ctx, mailDomain); err == nil && len(mx) > 0 {
			ours := false
			var hosts []string
			for _, m := range mx {
				h := strings.ToLower(strings.TrimSuffix(m.Host, "."))
				hosts = append(hosts, h)
				ours = ours || h == mailHost
			}
			if !ours {
				out = append(out, dnsWarning{Kind: "mx", Name: mailDomain, MX: strings.Join(hosts, ", "), MailHost: mailHost})
			}
		}
	}
	return out
}
