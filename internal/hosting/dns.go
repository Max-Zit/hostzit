package hosting

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Record is one DNS record of a zone. Name is relative to the zone ("@"
// for the apex, "www", "_dmarc", "*.dev"); Owner is "" for the customer's
// own records and "emailzit" for record sets EmailZit manages.
type Record struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	TTL     int    `json:"ttl"`
	Content string `json:"content"`
	Owner   string `json:"owner,omitempty"`
}

// DNSTypes are the record types the editor offers.
var DNSTypes = []string{"A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA", "NS", "TLSA", "HTTPS", "SVCB", "PTR"}

var relNameRE = regexp.MustCompile(`^(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$`)
var hostRE = regexp.MustCompile(`^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{1,63}\.?$`)

// FQDN turns a relative record name into an absolute one with a dot.
func FQDN(name, zone string) string {
	if name == "@" || name == "" {
		return zone + "."
	}
	return name + "." + zone + "."
}

// RelName turns an absolute name back into the relative form.
func RelName(fqdn, zone string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	if fqdn == zone {
		return "@"
	}
	return strings.TrimSuffix(fqdn, "."+zone)
}

func cleanHost(h string) (string, error) {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "." {
		return h, nil
	}
	if !hostRE.MatchString(h) || len(h) > 254 {
		return "", fmt.Errorf("%q is not a host name", h)
	}
	if !strings.HasSuffix(h, ".") {
		h += "."
	}
	return h, nil
}

func quoteTXT(s string) (string, error) {
	if strings.ContainsAny(s, "\r\n\x00") {
		return "", errors.New("TXT records cannot contain line breaks")
	}
	if len(s) > 4000 {
		return "", errors.New("the TXT record is too long")
	}
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) && len(s) >= 2 {
		// already quoted by the user: check that quotes are balanced chunks
		inner := s[1 : len(s)-1]
		if !strings.Contains(strings.ReplaceAll(inner, `" "`, ""), `"`) {
			return s, nil
		}
		s = inner
	}
	s = strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`)
	// split into 255-byte strings
	var parts []string
	for len(s) > 250 {
		cut := 250
		for cut > 0 && s[cut-1] == '\\' {
			cut--
		}
		parts = append(parts, `"`+s[:cut]+`"`)
		s = s[cut:]
	}
	parts = append(parts, `"`+s+`"`)
	return strings.Join(parts, " "), nil
}

// CleanRecord checks a record for a zone and returns it in the form the
// DNS server stores (absolute host names, quoted TXT).
func CleanRecord(r Record, zone string) (Record, error) {
	r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
	r.Name = strings.ToLower(strings.TrimSpace(r.Name))
	r.Name = strings.TrimSuffix(strings.TrimSuffix(r.Name, "."), "."+zone)
	if r.Name == zone || r.Name == "" {
		r.Name = "@"
	}
	if r.Name != "@" && (!relNameRE.MatchString(r.Name) || len(FQDN(r.Name, zone)) > 254) {
		return r, fmt.Errorf("%q is not a valid record name", r.Name)
	}
	if r.TTL == 0 {
		r.TTL = 3600
	}
	if r.TTL < 60 || r.TTL > 604800 {
		return r, errors.New("TTL must be 60–604800 seconds")
	}
	c := strings.TrimSpace(r.Content)
	var err error
	switch r.Type {
	case "A":
		a, e := netip.ParseAddr(c)
		if e != nil || !a.Is4() {
			return r, fmt.Errorf("%q is not an IPv4 address", c)
		}
		c = a.String()
	case "AAAA":
		a, e := netip.ParseAddr(c)
		if e != nil || !a.Is6() || a.Is4In6() {
			return r, fmt.Errorf("%q is not an IPv6 address", c)
		}
		c = a.String()
	case "CNAME", "NS", "PTR":
		if r.Type == "CNAME" && r.Name == "@" {
			return r, errors.New("the zone apex cannot be a CNAME")
		}
		if r.Type == "NS" && r.Name == "@" {
			return r, errors.New("the name servers of the zone itself are set by the server")
		}
		c, err = cleanHost(c)
	case "MX":
		f := strings.Fields(c)
		if len(f) != 2 {
			return r, errors.New("MX: priority and host, e.g. 10 mail.example.com")
		}
		p, e := strconv.Atoi(f[0])
		if e != nil || p < 0 || p > 65535 {
			return r, errors.New("MX: the priority must be 0–65535")
		}
		h, e := cleanHost(f[1])
		if e != nil {
			return r, e
		}
		c = fmt.Sprintf("%d %s", p, h)
	case "SRV":
		f := strings.Fields(c)
		if len(f) != 4 {
			return r, errors.New("SRV: priority weight port target")
		}
		for _, n := range f[:3] {
			if v, e := strconv.Atoi(n); e != nil || v < 0 || v > 65535 {
				return r, errors.New("SRV: priority, weight and port must be 0–65535")
			}
		}
		h, e := cleanHost(f[3])
		if e != nil {
			return r, e
		}
		c = strings.Join(append(f[:3], h), " ")
	case "TXT":
		c, err = quoteTXT(c)
	case "CAA":
		f := strings.SplitN(c, " ", 3)
		if len(f) != 3 {
			return r, errors.New(`CAA: flags tag value, e.g. 0 issue "letsencrypt.org"`)
		}
		fl, e := strconv.Atoi(f[0])
		if e != nil || (fl != 0 && fl != 128) {
			return r, errors.New("CAA: flags must be 0 or 128")
		}
		if f[1] != "issue" && f[1] != "issuewild" && f[1] != "iodef" {
			return r, errors.New("CAA: the tag must be issue, issuewild or iodef")
		}
		v := strings.Trim(strings.TrimSpace(f[2]), `"`)
		if strings.ContainsAny(v, "\"\\\r\n") || len(v) > 255 {
			return r, errors.New("CAA: invalid value")
		}
		c = fmt.Sprintf(`%d %s "%s"`, fl, f[1], v)
	case "TLSA":
		f := strings.Fields(c)
		if len(f) != 4 || len(f[3]) < 2 || len(f[3]) > 1024 || !hexRE.MatchString(f[3]) {
			return r, errors.New("TLSA: usage selector type hex-data")
		}
		for _, n := range f[:3] {
			if v, e := strconv.Atoi(n); e != nil || v < 0 || v > 255 {
				return r, errors.New("TLSA: the first three values must be 0–255")
			}
		}
		c = strings.ToLower(strings.Join(f, " "))
	case "HTTPS", "SVCB":
		if strings.ContainsAny(c, "\r\n;\\") || len(c) > 1000 || !regexp.MustCompile(`^[0-9]{1,5} [a-z0-9.-]*\.?( [a-z0-9-]+(=[A-Za-z0-9.,:"/+=-]*)?)*$`).MatchString(c) {
			return r, errors.New(r.Type + ": priority target [key=value …]")
		}
	default:
		return r, fmt.Errorf("record type %q is not supported", r.Type)
	}
	if err != nil {
		return r, err
	}
	r.Content = c
	return r, nil
}

// emailzitNames are the names EmailZit may manage (agreed in INTEGRATION.md P6).
var emailzitNames = regexp.MustCompile(`^(@|_dmarc|[a-z0-9_-]+\._domainkey|_mta-sts|_smtp\._tls|mail|autoconfig|autodiscover|mta-sts|webmail|_imaps\._tcp|_submissions\._tcp|_submission\._tcp|_pop3s\._tcp|_autodiscover\._tcp|_acme-challenge(\.(mail|autoconfig|autodiscover|mta-sts|webmail))?)$`)

// AllowedForEmailZit checks a record EmailZit wants to publish.
func AllowedForEmailZit(r Record) error {
	if !emailzitNames.MatchString(r.Name) {
		return fmt.Errorf("EmailZit may not manage the name %q", r.Name)
	}
	switch {
	case r.Name == "@" && (r.Type == "MX" || r.Type == "TXT" && strings.Contains(strings.ToLower(r.Content), "v=spf1")):
	case r.Type == "TXT" && r.Name != "@":
	case (r.Type == "A" || r.Type == "AAAA" || r.Type == "CNAME") && regexp.MustCompile(`^(mail|autoconfig|autodiscover|mta-sts|webmail)$`).MatchString(r.Name):
	case r.Type == "SRV" && strings.HasPrefix(r.Name, "_") && strings.HasSuffix(r.Name, "._tcp"):
	default:
		return fmt.Errorf("EmailZit may not manage a %s record at %q", r.Type, r.Name)
	}
	return nil
}

var hexRE = regexp.MustCompile(`^[0-9a-fA-F]+$`)
