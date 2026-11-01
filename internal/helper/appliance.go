package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// The HostZit appliance (installed from the ISO, OVA or disk images) lets
// the admin panel change the network, host name and time zone of the
// server. On a server installed with install.sh these belong to its
// administrator, so the operations refuse to run there.
const (
	ApplianceMarker = "/var/lib/hostzit/.appliance"
	NetworkFile     = "/etc/systemd/network/50-hostzit.network"
)

// NetworkConfig is the wanted IPv4 configuration of the main interface.
type NetworkConfig struct {
	DHCP     bool     `json:"dhcp"`
	Address  string   `json:"address,omitempty"` // with prefix, e.g. 192.168.1.20/24
	Gateway  string   `json:"gateway,omitempty"`
	DNS      []string `json:"dns,omitempty"`
	Hostname string   `json:"hostname,omitempty"`
}

var hostLabelRE = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// Validate checks a configuration.
func (c *NetworkConfig) Validate() error {
	if c.Hostname != "" && !hostLabelRE.MatchString(c.Hostname) {
		return errors.New("the host name may contain letters, digits and hyphens (no dots)")
	}
	if c.DHCP {
		return nil
	}
	p, err := netip.ParsePrefix(c.Address)
	if err != nil || !p.Addr().Is4() || p.Bits() < 8 || p.Bits() > 30 {
		return errors.New("enter the address with its network size, e.g. 192.168.1.20/24")
	}
	g, err := netip.ParseAddr(c.Gateway)
	if err != nil || !g.Is4() || !p.Contains(g) || g == p.Addr() {
		return errors.New("the gateway must be another address in the same network")
	}
	if len(c.DNS) == 0 || len(c.DNS) > 3 {
		return errors.New("enter one to three DNS servers")
	}
	for _, d := range c.DNS {
		if a, err := netip.ParseAddr(d); err != nil || !a.Is4() {
			return errors.New("enter the DNS servers as IPv4 addresses")
		}
	}
	return nil
}

func (h *Helper) isAppliance() bool { return h.Sys.Exists(ApplianceMarker) }

var errNotAppliance = userErr("this works only on the HostZit appliance; on other servers the server's administrator sets it up")

// renderNetwork is the systemd-networkd file of the main interface.
func renderNetwork(iface string, c NetworkConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Written by HostZit (Settings → System).\n[Match]\nName=%s\n\n[Network]\n", iface)
	if c.DHCP {
		b.WriteString("DHCP=ipv4\n")
	} else {
		fmt.Fprintf(&b, "Address=%s\nGateway=%s\n", c.Address, c.Gateway)
		for _, d := range c.DNS {
			fmt.Fprintf(&b, "DNS=%s\n", d)
		}
	}
	return b.String()
}

// mainInterface is the interface of the default route, else the first
// Ethernet interface.
func (h *Helper) mainInterface(ctx context.Context) (string, error) {
	if out, err := h.Sys.Run(ctx, nil, "ip", "-j", "route", "show", "default"); err == nil {
		var routes []struct{ Dev string }
		if json.Unmarshal(out, &routes) == nil && len(routes) > 0 && routes[0].Dev != "" {
			return routes[0].Dev, nil
		}
	}
	out, err := h.Sys.Run(ctx, nil, "ip", "-j", "link", "show")
	if err != nil {
		return "", err
	}
	var links []struct {
		Ifname   string `json:"ifname"`
		LinkType string `json:"link_type"`
	}
	_ = json.Unmarshal(out, &links)
	for _, l := range links {
		if l.LinkType == "ether" {
			return l.Ifname, nil
		}
	}
	return "", errors.New("no network interface found")
}

// SystemState is what Settings → System shows.
type SystemState struct {
	Appliance bool          `json:"appliance"`
	Interface string        `json:"interface"`
	Network   NetworkConfig `json:"network"`
	// Current is the IPv4 address with prefix the interface has now.
	Current  string `json:"current"`
	TimeZone string `json:"time_zone"`
}

func (h *Helper) systemState(ctx context.Context, _ struct{}) (any, error) {
	st := SystemState{Appliance: h.isAppliance()}
	if out, err := h.Sys.Run(ctx, nil, "hostname"); err == nil {
		st.Network.Hostname = strings.TrimSpace(string(out))
	}
	if out, err := h.Sys.Run(ctx, nil, "timedatectl", "show", "-p", "Timezone", "--value"); err == nil {
		st.TimeZone = strings.TrimSpace(string(out))
	}
	iface, err := h.mainInterface(ctx)
	if err != nil {
		return st, nil
	}
	st.Interface = iface
	if out, err := h.Sys.Run(ctx, nil, "ip", "-j", "-4", "addr", "show", "dev", iface); err == nil {
		var addrs []struct {
			AddrInfo []struct {
				Local     string `json:"local"`
				Prefixlen int    `json:"prefixlen"`
			} `json:"addr_info"`
		}
		if json.Unmarshal(out, &addrs) == nil && len(addrs) > 0 && len(addrs[0].AddrInfo) > 0 {
			a := addrs[0].AddrInfo[0]
			st.Current = fmt.Sprintf("%s/%d", a.Local, a.Prefixlen)
		}
	}
	st.Network.DHCP = true
	if b, err := h.Sys.ReadFile(NetworkFile); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
			switch {
			case !ok:
			case k == "Address":
				st.Network.DHCP, st.Network.Address = false, v
			case k == "Gateway":
				st.Network.Gateway = v
			case k == "DNS":
				st.Network.DNS = append(st.Network.DNS, v)
			}
		}
	}
	return st, nil
}

// systemNetwork writes the network of the appliance. A static address whose
// gateway does not answer would cut the server off, so then the previous
// settings come back.
func (h *Helper) systemNetwork(ctx context.Context, c NetworkConfig) (any, error) {
	if !h.isAppliance() {
		return nil, errNotAppliance
	}
	if err := c.Validate(); err != nil {
		return nil, userErr(err.Error())
	}
	iface, err := h.mainInterface(ctx)
	if err != nil {
		return nil, err
	}
	old, oldErr := h.Sys.ReadFile(NetworkFile)
	if err := h.Sys.WriteFile(NetworkFile, []byte(renderNetwork(iface, c)), 0o644, 0, 0); err != nil {
		return nil, err
	}
	if c.Hostname != "" {
		if _, err := h.Sys.Run(ctx, nil, "hostnamectl", "set-hostname", c.Hostname); err != nil {
			return nil, err
		}
	}
	_, _ = h.Sys.Run(ctx, nil, "networkctl", "reload")
	_, rerr := h.Sys.Run(ctx, nil, "networkctl", "reconfigure", iface)
	if rerr == nil && !c.DHCP {
		rerr = h.waitGateway(ctx, c.Gateway)
	}
	if rerr != nil {
		if oldErr == nil {
			_ = h.Sys.WriteFile(NetworkFile, old, 0o644, 0, 0)
		} else {
			_ = h.Sys.Remove(NetworkFile)
		}
		_, _ = h.Sys.Run(ctx, nil, "networkctl", "reload")
		_, _ = h.Sys.Run(ctx, nil, "networkctl", "reconfigure", iface)
		return nil, userErr(fmt.Sprintf("the new settings did not work (%v); the previous ones are back", rerr))
	}
	return map[string]string{"interface": iface}, nil
}

func (h *Helper) waitGateway(ctx context.Context, gw string) error {
	for i := 0; i < 15; i++ {
		if _, err := h.Sys.Run(ctx, nil, "ping", "-c", "1", "-W", "2", gw); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return errors.New("the gateway " + gw + " does not answer")
}

type timeZoneArgs struct {
	Zone string `json:"zone"`
}

var tzRE = regexp.MustCompile(`^[A-Za-z]+(/[A-Za-z0-9_+-]+){0,2}$|^UTC$`)

// systemTimeZone sets the server's time zone (every server, not only the appliance).
func (h *Helper) systemTimeZone(ctx context.Context, a timeZoneArgs) (any, error) {
	if !tzRE.MatchString(a.Zone) || !h.Sys.Exists("/usr/share/zoneinfo/"+a.Zone) {
		return nil, userErr("unknown time zone")
	}
	if _, err := h.Sys.Run(ctx, nil, "timedatectl", "set-timezone", a.Zone); err != nil {
		return nil, err
	}
	return nil, nil
}

type powerArgs struct {
	Action string `json:"action"` // reboot | poweroff
}

// systemPower restarts or shuts down the appliance a few seconds later, so
// the panel can still answer.
func (h *Helper) systemPower(ctx context.Context, a powerArgs) (any, error) {
	if !h.isAppliance() {
		return nil, errNotAppliance
	}
	if a.Action != "reboot" && a.Action != "poweroff" {
		return nil, userErr("unknown action")
	}
	if _, err := h.Sys.Run(ctx, nil, "systemd-run", "--unit=hostzit-power", "--on-active=5", "systemctl", a.Action); err != nil {
		return nil, err
	}
	return nil, nil
}

func init() {
	moreOps = append(moreOps, func(h *Helper) {
		h.ops["system.state"] = op{handle(h.systemState), false}
		h.ops["system.network"] = op{handle(h.systemNetwork), true}
		h.ops["system.timezone"] = op{handle(h.systemTimeZone), true}
		h.ops["system.power"] = op{handle(h.systemPower), true}
	})
}
