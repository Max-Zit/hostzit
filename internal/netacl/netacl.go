// Package netacl restricts which client addresses may reach a listener.
// The check runs when a TCP connection is accepted, before the TLS
// handshake, so a refused client learns nothing about the server.
package netacl

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
)

// DefaultManagement are the networks allowed to reach the management
// console after installation: the private (RFC 1918 / ULA) ranges.
// Loopback is always allowed in addition, see List.Allows.
var DefaultManagement = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"}

// MaxEntries limits the size of a list.
const MaxEntries = 200

// ParsePrefix accepts "10.0.0.0/8", "192.168.1.5" and IPv6 forms.
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return p, err
		}
		if p.Addr().Is4In6() {
			return netip.Prefix{}, errors.New("use the plain IPv4 form")
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Split reads networks from a text area (one per line, or separated by
// commas or spaces); "#" starts a comment.
func Split(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		out = append(out, strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\r' || r == '\t' || r == ';'
		})...)
	}
	return out
}

// Parse validates and normalizes a list of networks.
func Parse(list []string) ([]netip.Prefix, error) {
	if len(list) > MaxEntries {
		return nil, fmt.Errorf("at most %d networks", MaxEntries)
	}
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		p, err := ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address or network (example: 192.168.1.0/24)", s)
		}
		out = append(out, p)
	}
	return out, nil
}

// Strings formats prefixes; single addresses without the /32 or /128.
func Strings(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		if p.IsSingleIP() {
			out[i] = p.Addr().String()
		} else {
			out[i] = p.String()
		}
	}
	return out
}

// Contains reports whether a is in one of the prefixes.
func Contains(ps []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// List is an allow-list that can be replaced while listeners use it.
type List struct {
	p atomic.Pointer[policy]
}

type policy struct {
	nets []netip.Prefix
	// all allows every address (an empty agent list).
	all bool
	// loopback is always allowed for the management console, so the
	// server's own console (SSH tunnel, local browser) cannot be locked out.
	loopback bool
}

// NewManagement returns a list that always allows loopback and otherwise
// only nets. An empty nets list allows loopback only.
func NewManagement(nets []netip.Prefix) *List {
	l := &List{}
	l.p.Store(&policy{nets: nets, loopback: true})
	return l
}

// NewOptional returns a list where an empty nets list allows everyone
// (used for the agent endpoint, which is often public).
func NewOptional(nets []netip.Prefix) *List {
	l := &List{}
	l.SetOptional(nets)
	return l
}

// Set replaces the networks of a management list.
func (l *List) Set(nets []netip.Prefix) {
	l.p.Store(&policy{nets: nets, loopback: true})
}

// SetOptional replaces the networks of an optional list.
func (l *List) SetOptional(nets []netip.Prefix) {
	l.p.Store(&policy{nets: nets, all: len(nets) == 0})
}

// Allows reports whether the address may connect.
func (l *List) Allows(a netip.Addr) bool {
	p := l.p.Load()
	a = a.Unmap()
	switch {
	case p.all:
		return true
	case p.loopback && a.IsLoopback():
		return true
	}
	return Contains(p.nets, a)
}

// AllowsAddr is Allows for a "host:port" or bare host string.
func (l *List) AllowsAddr(hostport string) bool {
	a, ok := AddrOf(hostport)
	return ok && l.Allows(a)
}

// AddrOf parses the IP of a "host:port" or bare address.
func AddrOf(hostport string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	a, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// Listener closes connections from addresses the list does not allow.
type Listener struct {
	net.Listener
	List *List
	// OnRefuse is called with the remote address of a refused connection.
	OnRefuse func(remote string)
}

// Accept returns the next allowed connection.
func (l *Listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.List.AllowsAddr(c.RemoteAddr().String()) {
			return c, nil
		}
		if l.OnRefuse != nil {
			l.OnRefuse(c.RemoteAddr().String())
		}
		_ = c.Close()
	}
}
