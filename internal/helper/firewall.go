package helper

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/max-zit/hostzit/internal/hosting"
)

// Ports that are always open when the inbound firewall is on: SSH/SFTP,
// DNS, the websites. The panel ports come from the panel, the SSH ports
// the SSH server really uses are added by the helper, so a changed SSH
// port can never lock the administrator out.
var (
	inboundTCP = []int{22, 53, 80, 443}
	inboundUDP = []int{53}
	// EmailZit on the same server: SMTP, submission, IMAP and POP3 over
	// TLS, its panel
	emailzitTCP = []int{25, 465, 587, 993, 995, 8444}
)

// emailzitMarker is installed by EmailZit's server package.
const emailzitMarker = "/usr/sbin/emailzit-sendmail"

// Inbound is the default-deny rule for connections from outside: only
// the listed ports are open (plus answers to the server's own
// connections, ICMP and DHCP replies).
type Inbound struct {
	TCP []int
	UDP []int
}

// FirewallConf is the nftables table of HostZit: hosting accounts cannot
// send mail directly (spam from hacked websites), blocked addresses cannot
// reach the server and, with in set, everything else than the open ports
// is dropped.
func FirewallConf(blocked []string, in *Inbound) string {
	var v4, v6 []string
	for _, b := range blocked {
		if strings.Contains(b, ":") {
			v6 = append(v6, b)
		} else {
			v4 = append(v4, b)
		}
	}
	elems := func(l []string) string {
		if len(l) == 0 {
			return ""
		}
		return "\n        elements = { " + strings.Join(l, ", ") + " }"
	}
	policy, rules := "accept", ""
	if in != nil {
		policy = "drop"
		rules = `
        iif lo accept
        ct state established,related accept
        ct state invalid drop
        meta l4proto { icmp, ipv6-icmp } accept
        udp dport { 68, 546 } accept`
		if len(in.TCP) > 0 {
			rules += "\n        tcp dport { " + joinPorts(in.TCP) + " } accept"
		}
		if len(in.UDP) > 0 {
			rules += "\n        udp dport { " + joinPorts(in.UDP) + " } accept"
		}
	}
	return fmt.Sprintf(`# HostZit (generated, do not edit)
table inet hostzit {}
delete table inet hostzit
table inet hostzit {
    set blocked4 {
        type ipv4_addr
        flags interval%s
    }
    set blocked6 {
        type ipv6_addr
        flags interval%s
    }
    chain input {
        type filter hook input priority -5; policy %s;
        ip saddr @blocked4 drop
        ip6 saddr @blocked6 drop%s
    }
    chain output {
        type filter hook output priority 0; policy accept;
        meta skuid %d-%d tcp dport { 25, 465, 587 } counter reject with tcp reset
    }
}
`, elems(v4), elems(v6), policy, rules, hosting.UIDBase+1, hosting.UIDBase+hosting.MaxAccounts)
}

func joinPorts(l []int) string {
	s := make([]string, len(l))
	for i, p := range l {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ", ")
}

// portSet merges port lists into a sorted list without duplicates; ports
// outside 1–65535 are an error.
func portSet(lists ...[]int) ([]int, error) {
	var out []int
	for _, l := range lists {
		for _, p := range l {
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid port %d", p)
			}
			if !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

type firewallArgs struct {
	Blocked []string `json:"blocked"`
	// Inbound switches the default-deny rule on; TCP/UDP are the ports
	// opened in addition to the fixed ones (the panel ports among them)
	Inbound bool  `json:"inbound"`
	TCP     []int `json:"tcp"`
	UDP     []int `json:"udp"`
}

type firewallResult struct {
	Blocked int   `json:"blocked"`
	Inbound bool  `json:"inbound"`
	TCP     []int `json:"tcp,omitempty"`
	UDP     []int `json:"udp,omitempty"`
}

func (h *Helper) firewall(ctx context.Context, a firewallArgs) (any, error) {
	list, err := hosting.CleanNets(a.Blocked)
	if err != nil {
		return nil, userErr(err.Error())
	}
	res := firewallResult{Blocked: len(list), Inbound: a.Inbound}
	var in *Inbound
	if a.Inbound {
		var mail []int
		if h.Sys.Exists(emailzitMarker) {
			mail = emailzitTCP
		}
		tcp, err := portSet(inboundTCP, h.sshdPorts(ctx), mail, a.TCP)
		if err != nil {
			return nil, userErr(err.Error())
		}
		udp, err := portSet(inboundUDP, a.UDP)
		if err != nil {
			return nil, userErr(err.Error())
		}
		in = &Inbound{TCP: tcp, UDP: udp}
		res.TCP, res.UDP = tcp, udp
	}
	if err := h.Sys.WriteFile("/etc/hostzit/firewall.nft", []byte(FirewallConf(list, in)), 0o600, 0, 0); err != nil {
		return nil, err
	}
	if _, err := h.Sys.Run(ctx, nil, "nft", "-f", "/etc/hostzit/firewall.nft"); err != nil {
		return nil, err
	}
	return res, nil
}

// sshdPorts are the ports the SSH server listens on ("port N" lines of
// sshd -T); none when it cannot tell.
func (h *Helper) sshdPorts(ctx context.Context) []int {
	out, err := h.Sys.Run(ctx, nil, "sshd", "-T")
	if err != nil {
		return nil
	}
	return parseSSHDPorts(out)
}

func parseSSHDPorts(out []byte) []int {
	var l []int
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && f[0] == "port" {
			if p, err := strconv.Atoi(f[1]); err == nil && p > 0 && p < 65536 {
				l = append(l, p)
			}
		}
	}
	return l
}
