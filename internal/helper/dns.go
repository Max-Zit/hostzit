package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/hosting"
)

// PDNS is the PowerDNS Authoritative HTTP API (on loopback; the key is in a
// file only root can read).
type PDNS struct {
	URL     string // http://127.0.0.1:8081/api/v1/servers/localhost
	KeyFile string // /etc/hostzit/pdns-api.key
	Client  *http.Client
}

func (h *Helper) pdns(ctx context.Context, method, path string, body any, out any) error {
	if h.PDNS.URL == "" {
		return userErr("the DNS server is not set up")
	}
	key, err := h.Sys.ReadFile(h.PDNS.KeyFile)
	if err != nil {
		return userErr("the DNS server key is missing")
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, h.PDNS.URL+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", strings.TrimSpace(string(key)))
	req.Header.Set("Content-Type", "application/json")
	c := h.PDNS.Client
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("DNS server: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode == http.StatusNotFound {
		return errZoneMissing
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		return fmt.Errorf("DNS server %s %s: %d %s", method, path, resp.StatusCode, e.Error)
	}
	if out != nil && len(b) > 0 {
		return json.Unmarshal(b, out)
	}
	return nil
}

var errZoneMissing = errors.New("zone not found")

type pdnsRecord struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

type pdnsRRSet struct {
	Name       string       `json:"name"`
	Type       string       `json:"type"`
	TTL        int          `json:"ttl,omitempty"`
	ChangeType string       `json:"changetype,omitempty"`
	Records    []pdnsRecord `json:"records"`
}

type pdnsZone struct {
	ID          string      `json:"id,omitempty"`
	Name        string      `json:"name"`
	Kind        string      `json:"kind,omitempty"`
	Nameservers []string    `json:"nameservers,omitempty"`
	RRSets      []pdnsRRSet `json:"rrsets,omitempty"`
	DNSSEC      bool        `json:"dnssec,omitempty"`
	SOAEdit     string      `json:"soa_edit_api,omitempty"`
}

type zoneArgs struct {
	Zone        string           `json:"zone"`
	Nameservers []string         `json:"nameservers"`
	Records     []hosting.Record `json:"records"`
	// Hostmaster is the SOA contact (e.g. hostmaster.example.com).
	Hostmaster string `json:"hostmaster"`
}

// dnsApply makes the zone hold exactly the given records (desired state):
// the zone is created when missing, record sets that are not wanted any
// more are deleted, the rest replaced. The SOA serial is raised by
// PowerDNS (soa_edit_api) and secondaries are notified.
func (h *Helper) dnsApply(ctx context.Context, a zoneArgs) (any, error) {
	zone, err := hosting.NormalizeDomain(a.Zone)
	if err != nil {
		return nil, userErr(err.Error())
	}
	if len(a.Nameservers) == 0 || len(a.Nameservers) > 8 {
		return nil, userErr("the zone needs 1–8 name servers")
	}
	ns := make([]string, 0, len(a.Nameservers))
	for _, n := range a.Nameservers {
		d, err := hosting.NormalizeDomain(n)
		if err != nil {
			return nil, userErr("name server: " + err.Error())
		}
		ns = append(ns, d+".")
	}
	if len(a.Records) > 5000 {
		return nil, userErr("at most 5000 records per zone")
	}
	sets := map[string]*pdnsRRSet{}
	for _, r := range a.Records {
		c, err := hosting.CleanRecord(r, zone)
		if err != nil {
			return nil, userErr(err.Error())
		}
		k := hosting.FQDN(c.Name, zone) + "|" + c.Type
		s := sets[k]
		if s == nil {
			s = &pdnsRRSet{Name: hosting.FQDN(c.Name, zone), Type: c.Type, TTL: c.TTL, ChangeType: "REPLACE"}
			sets[k] = s
		}
		s.TTL = min(s.TTL, c.TTL)
		s.Records = append(s.Records, pdnsRecord{Content: c.Content})
	}
	// CNAME must stand alone at its name.
	names := map[string][]string{}
	for _, s := range sets {
		names[s.Name] = append(names[s.Name], s.Type)
	}
	for n, types := range names {
		if len(types) > 1 && contains(types, "CNAME") {
			return nil, userErr("a CNAME cannot share its name with other records: " + strings.TrimSuffix(n, "."))
		}
	}
	hm := "hostmaster." + zone + "."
	if a.Hostmaster != "" {
		d, err := hosting.NormalizeDomain(a.Hostmaster)
		if err != nil {
			return nil, userErr("SOA contact: " + err.Error())
		}
		hm = d + "."
	}
	soa := pdnsRRSet{Name: zone + ".", Type: "SOA", TTL: 3600, ChangeType: "REPLACE",
		Records: []pdnsRecord{{Content: fmt.Sprintf("%s %s 1 10800 3600 1209600 3600", ns[0], hm)}}}
	nsSet := pdnsRRSet{Name: zone + ".", Type: "NS", TTL: 86400, ChangeType: "REPLACE"}
	for _, n := range ns {
		nsSet.Records = append(nsSet.Records, pdnsRecord{Content: n})
	}

	var cur pdnsZone
	err = h.pdns(ctx, http.MethodGet, "/zones/"+zone+".", nil, &cur)
	created := false
	if errors.Is(err, errZoneMissing) {
		z := pdnsZone{Name: zone + ".", Kind: "Native", SOAEdit: "INCEPTION-INCREMENT", RRSets: []pdnsRRSet{soa, nsSet}}
		z.RRSets[0].ChangeType, z.RRSets[1].ChangeType = "", ""
		if err := h.pdns(ctx, http.MethodPost, "/zones", z, &cur); err != nil {
			return nil, err
		}
		created = true
	} else if err != nil {
		return nil, err
	}
	var patch []pdnsRRSet
	for _, s := range cur.RRSets {
		if s.Type == "SOA" || s.Type == "NS" && s.Name == zone+"." {
			continue
		}
		if _, ok := sets[s.Name+"|"+s.Type]; !ok && !strings.HasPrefix(s.Type, "TYPE") && s.Type != "DNSKEY" && s.Type != "CDS" && s.Type != "CDNSKEY" {
			patch = append(patch, pdnsRRSet{Name: s.Name, Type: s.Type, ChangeType: "DELETE", Records: []pdnsRecord{}})
		}
	}
	keys := make([]string, 0, len(sets))
	for k := range sets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		patch = append(patch, *sets[k])
	}
	if !created {
		patch = append(patch, nsSet)
	}
	if err := h.pdns(ctx, http.MethodPatch, "/zones/"+zone+".", pdnsZone{Name: zone + ".", RRSets: patch}, nil); err != nil {
		return nil, userErr(err.Error())
	}
	_ = h.pdns(ctx, http.MethodPut, "/zones/"+zone+"./notify", nil, nil)
	return map[string]any{"created": created, "sets": len(sets)}, nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

type zoneRef struct {
	Zone string `json:"zone"`
}

func (h *Helper) dnsDelete(ctx context.Context, a zoneRef) (any, error) {
	zone, err := hosting.NormalizeDomain(a.Zone)
	if err != nil {
		return nil, userErr(err.Error())
	}
	err = h.pdns(ctx, http.MethodDelete, "/zones/"+zone+".", nil, nil)
	if errors.Is(err, errZoneMissing) {
		return nil, nil
	}
	return nil, err
}

type dnssecArgs struct {
	Zone string `json:"zone"`
	On   bool   `json:"on"`
}

// dnsDNSSEC signs or unsigns a zone and returns the DS records for the
// registrar.
func (h *Helper) dnsDNSSEC(ctx context.Context, a dnssecArgs) (any, error) {
	zone, err := hosting.NormalizeDomain(a.Zone)
	if err != nil {
		return nil, userErr(err.Error())
	}
	if !a.On {
		if _, err := h.Sys.Run(ctx, nil, "pdnsutil", "zone", "dnssec-disable", zone); err != nil {
			if _, err2 := h.Sys.Run(ctx, nil, "pdnsutil", "disable-dnssec", zone); err2 != nil {
				return nil, err
			}
		}
		return map[string]any{"ds": []string{}}, nil
	}
	if _, err := h.Sys.Run(ctx, nil, "pdnsutil", "secure-zone", zone); err != nil && !strings.Contains(err.Error(), "already secure") {
		return nil, err
	}
	_, _ = h.Sys.Run(ctx, nil, "pdnsutil", "set-nsec3", zone, "1 0 0 -", "narrow")
	_, _ = h.Sys.Run(ctx, nil, "pdnsutil", "rectify-zone", zone)
	out, err := h.Sys.Run(ctx, nil, "pdnsutil", "export-zone-ds", zone)
	if err != nil {
		return nil, err
	}
	var ds []string
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		for i, x := range f {
			// "example.com. IN DS 12345 13 2 ab…": keep the SHA-256 digests
			if x == "DS" && len(f) == i+5 && f[i+3] == "2" {
				ds = append(ds, strings.Join(f[i+1:], " "))
			}
		}
	}
	return map[string]any{"ds": ds}, nil
}
