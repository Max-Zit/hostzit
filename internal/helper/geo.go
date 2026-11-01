package helper

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/hosting"
	"github.com/oschwald/maxminddb-golang/v2"
)

// Access by country: the database is DB-IP's "IP to Country Lite"
// (CC BY 4.0, monthly, https://db-ip.com). nginx reads it for the country
// rules of the websites (module geoip2); the helper turns the chosen
// countries into nftables sets for the sign-in services (panels, SSH).

const (
	geoDir       = "/var/lib/hostzit/geo"
	geoCountries = geoDir + "/countries.json"
	geoNft       = "/etc/hostzit/geo.nft"
	geoURL       = "https://download.db-ip.com/free/dbip-country-lite-%s.mmdb.gz"
	geoModule    = "libnginx-mod-http-geoip2"
)

// Country is a country of the database.
type Country struct {
	Code      string `json:"code"`
	Continent string `json:"continent"`
	Name      string `json:"name"` // English; the panel shows it in the viewer's language
}

// GeoStatus describes the country database.
type GeoStatus struct {
	Ready     bool      `json:"ready"`   // database and nginx module there
	Updated   time.Time `json:"updated"` // build date of the database
	Countries []Country `json:"countries"`
}

type geoRecord struct {
	Country struct {
		ISO   string            `maxminddb:"iso_code"`
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Continent struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"continent"`
}

func (h *Helper) geoReady() bool {
	return h.Sys.Exists(hosting.GeoDB) && h.Sys.Exists(hosting.NginxGeoConf)
}

func (h *Helper) geoStatus(_ context.Context, _ struct{}) (any, error) {
	st := GeoStatus{Ready: h.geoReady(), Countries: []Country{}}
	if b, err := h.Sys.ReadFile(geoCountries); err == nil {
		_ = json.Unmarshal(b, &st.Countries)
	}
	if r, err := h.geoOpen(); err == nil {
		st.Updated = r.Metadata.BuildTime()
		_ = r.Close()
	}
	return st, nil
}

// geoUpdate downloads this month's database (or last month's), installs
// the nginx module and loads the new data.
func (h *Helper) geoUpdate(ctx context.Context, _ struct{}) (any, error) {
	if err := h.Sys.Mkdir(geoDir, 0o755, 0, 0); err != nil {
		return nil, err
	}
	gz := geoDir + "/download.gz"
	defer h.Sys.Remove(gz) //nolint:errcheck
	var err error
	for _, m := range []time.Time{time.Now().UTC(), time.Now().UTC().AddDate(0, -1, 0)} {
		if _, err = h.Sys.Run(ctx, nil, "curl", "-fsSL", "--proto", "=https", "--max-time", "300", "-o", h.realPath(gz), fmt.Sprintf(geoURL, m.Format("2006-01"))); err == nil {
			break
		}
	}
	if err != nil {
		return nil, userErr("the country database could not be downloaded: " + err.Error())
	}
	zipped, err := h.Sys.ReadFile(gz)
	if err != nil {
		return nil, err
	}
	data, err := gunzip(zipped, 200<<20)
	if err != nil {
		return nil, userErr("the country database is damaged: " + err.Error())
	}
	r, err := maxminddb.OpenBytes(data)
	if err != nil {
		return nil, userErr("the country database is damaged: " + err.Error())
	}
	countries, err := readCountries(r)
	_ = r.Close()
	if err != nil || len(countries) < 100 {
		return nil, userErr(fmt.Sprintf("the country database is damaged (%v, %d countries)", err, len(countries)))
	}
	if err := h.Sys.WriteFile(hosting.GeoDB, data, 0o644, 0, 0); err != nil {
		return nil, err
	}
	b, _ := json.Marshal(countries)
	if err := h.Sys.WriteFile(geoCountries, b, 0o644, 0, 0); err != nil {
		return nil, err
	}
	if !h.Sys.Exists("/usr/share/nginx/modules-available/mod-http-geoip2.conf") && !h.Sys.Exists("/etc/nginx/modules-enabled/50-mod-http-geoip2.conf") {
		if out, err := h.apt(ctx, "install", geoModule); err != nil {
			return nil, userErr("the nginx module " + geoModule + " could not be installed: " + tail(string(out), 300))
		}
	}
	if !h.Sys.Exists(hosting.NginxGeoConf) {
		if err := h.nginxApply(ctx, map[string][]byte{hosting.NginxGeoConf: []byte(hosting.GeoConf(hosting.GeoDB))}, nil); err != nil {
			_ = h.Sys.Remove(hosting.NginxGeoConf)
			return nil, err
		}
	}
	// nginx reloads the database by itself (auto_reload); the sign-in
	// rules get the new networks now
	if h.Sys.Exists(geoNft) {
		if b, err := h.Sys.ReadFile(geoNft + ".json"); err == nil {
			var a geoFirewallArgs
			if json.Unmarshal(b, &a) == nil {
				_, _ = h.geoFirewall(ctx, a)
			}
		}
	}
	return map[string]int{"countries": len(countries)}, nil
}

func gunzip(b []byte, max int64) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	out, err := io.ReadAll(io.LimitReader(zr, max+1))
	if err == nil && int64(len(out)) > max {
		err = fmt.Errorf("larger than %d MB", max>>20)
	}
	return out, err
}

// realPath is a path on the machine (below the test root in tests).
func (h *Helper) realPath(p string) string {
	if o, ok := h.Sys.(*OS); ok {
		return o.p(p)
	}
	return p
}

func (h *Helper) geoOpen() (*maxminddb.Reader, error) {
	b, err := h.Sys.ReadFile(hosting.GeoDB)
	if err != nil {
		return nil, err
	}
	return maxminddb.OpenBytes(b)
}

// readCountries lists the countries of a database.
func readCountries(r *maxminddb.Reader) ([]Country, error) {
	seen := map[string]Country{}
	for res := range r.Networks() {
		var rec geoRecord
		if err := res.Decode(&rec); err != nil {
			return nil, err
		}
		if c := rec.Country.ISO; c != "" && seen[c].Code == "" {
			seen[c] = Country{Code: c, Continent: rec.Continent.Code, Name: rec.Country.Names["en"]}
		}
	}
	out := make([]Country, 0, len(seen))
	for _, c := range seen {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out, nil
}

// geoNetworks collects the networks of the chosen countries and continents.
func geoNetworks(r *maxminddb.Reader, list []string) (v4, v6 []string, err error) {
	for res := range r.Networks() {
		var rec geoRecord
		if err := res.Decode(&rec); err != nil {
			return nil, nil, err
		}
		if !slices.Contains(list, rec.Country.ISO) && !slices.Contains(list, "@"+rec.Continent.Code) {
			continue
		}
		p := res.Prefix()
		if p.Addr().Is4() || p.Addr().Is4In6() {
			v4 = append(v4, netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-max(0, p.Addr().BitLen()-32)).String())
		} else {
			v6 = append(v6, p.String())
		}
	}
	return v4, v6, nil
}

// geoFirewallArgs is the country rule of the sign-in services.
type geoFirewallArgs struct {
	Mode  string   `json:"mode"`  // "", block, allow
	List  []string `json:"list"`  // RS, @EU …
	Ports []int    `json:"ports"` // panels and SSH
	Allow []string `json:"allow"` // never refused (the brute-force allow list)
}

// GeoNft renders the nftables table of the country rule (exported for tests).
func GeoNft(a geoFirewallArgs, v4, v6 []string) string {
	ports := make([]string, len(a.Ports))
	for i, p := range a.Ports {
		ports[i] = fmt.Sprint(p)
	}
	var ex4, ex6 []string
	for _, s := range append([]string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"}, a.Allow...) {
		if strings.Contains(s, ":") {
			ex6 = append(ex6, s)
		} else {
			ex4 = append(ex4, s)
		}
	}
	elems := func(l []string) string {
		if len(l) == 0 {
			return ""
		}
		return "\n        elements = { " + strings.Join(l, ", ") + " }"
	}
	verdict4, verdict6 := "ip saddr @geo4 drop", "ip6 saddr @geo6 drop"
	if a.Mode == "allow" {
		verdict4, verdict6 = "meta nfproto ipv4 ip saddr != @geo4 drop", "meta nfproto ipv6 ip6 saddr != @geo6 drop"
	}
	return fmt.Sprintf(`# HostZit: country rule of the sign-in services (generated, do not edit)
table inet hostzit_geo {}
delete table inet hostzit_geo
table inet hostzit_geo {
    set exempt4 {
        type ipv4_addr
        flags interval
        auto-merge%s
    }
    set exempt6 {
        type ipv6_addr
        flags interval
        auto-merge%s
    }
    set geo4 {
        type ipv4_addr
        flags interval
        auto-merge%s
    }
    set geo6 {
        type ipv6_addr
        flags interval
        auto-merge%s
    }
    chain input {
        type filter hook input priority -6; policy accept;
        tcp dport != { %s } accept
        ip saddr @exempt4 accept
        ip6 saddr @exempt6 accept
        %s
        %s
    }
}
`, elems(ex4), elems(ex6), elems(v4), elems(v6), strings.Join(ports, ", "), verdict4, verdict6)
}

func (h *Helper) geoFirewall(ctx context.Context, a geoFirewallArgs) (any, error) {
	if a.Mode == "" {
		_, _ = h.Sys.Run(ctx, nil, "nft", "delete", "table", "inet", "hostzit_geo")
		_ = h.Sys.Remove(geoNft)
		_ = h.Sys.Remove(geoNft + ".json")
		return nil, nil
	}
	if err := hosting.ValidGeo(a.Mode, a.List); err != nil {
		return nil, userErr(err.Error())
	}
	if len(a.Ports) == 0 || len(a.Ports) > 10 {
		return nil, userErr("invalid ports")
	}
	for _, p := range a.Ports {
		if p < 1 || p > 65535 {
			return nil, userErr("invalid ports")
		}
	}
	allow, err := hosting.CleanNets(a.Allow)
	if err != nil {
		return nil, userErr(err.Error())
	}
	a.Allow = allow
	if !h.Sys.Exists(hosting.GeoDB) {
		return nil, userErr("download the country database first")
	}
	r, err := h.geoOpen()
	if err != nil {
		return nil, err
	}
	v4, v6, err := geoNetworks(r, a.List)
	_ = r.Close()
	if err != nil {
		return nil, err
	}
	if err := h.Sys.WriteFile(geoNft, []byte(GeoNft(a, v4, v6)), 0o600, 0, 0); err != nil {
		return nil, err
	}
	if out, err := h.Sys.Run(ctx, nil, "nft", "-f", geoNft); err != nil {
		return nil, userErr("the firewall did not accept the country rule: " + tail(string(out)+" "+err.Error(), 300))
	}
	b, _ := json.Marshal(a)
	_ = h.Sys.WriteFile(geoNft+".json", b, 0o600, 0, 0)
	return map[string]int{"networks": len(v4) + len(v6)}, nil
}

func init() {
	moreOps = append(moreOps, func(h *Helper) {
		h.ops["geo.status"] = op{handle(h.geoStatus), false}
		h.ops["geo.update"] = op{handle(h.geoUpdate), true}
		h.ops["geo.firewall"] = op{handle(h.geoFirewall), true}
		h.ops["geo.lookup"] = op{handle(h.geoLookup), false}
	})
}

type geoLookupArgs struct {
	IP string `json:"ip"`
}

// geoLookup tells the country and continent of an address ("" when unknown).
func (h *Helper) geoLookup(_ context.Context, a geoLookupArgs) (any, error) {
	ip, err := netip.ParseAddr(a.IP)
	if err != nil {
		return nil, userErr("not an IP address")
	}
	res := map[string]string{"country": "", "continent": ""}
	r, err := h.geoOpen()
	if err != nil {
		return res, nil
	}
	defer r.Close()
	var rec geoRecord
	if err := r.Lookup(ip.Unmap()).Decode(&rec); err == nil {
		res["country"], res["continent"] = rec.Country.ISO, rec.Continent.Code
	}
	return res, nil
}
