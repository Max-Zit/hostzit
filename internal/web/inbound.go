package web

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// The inbound firewall (Settings → Sign-in and security): when it is on,
// only the ports HostZit uses (SSH, DNS, websites, both panels, EmailZit's
// ports when it is on the server) and the administrator's extra ports
// accept connections from outside. New servers get it on at setup; servers
// set up before 0.9.3 keep everything open until the administrator turns
// it on.

const settingInbound = "inbound_firewall"

// InboundSettings are the administrator's choices.
type InboundSettings struct {
	On  bool  `json:"on"`
	TCP []int `json:"tcp,omitempty"`
	UDP []int `json:"udp,omitempty"`
}

func init() {
	adminExtra = append(adminExtra, func(s *Server, mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc)) {
		admin("POST /settings/security/inbound", s.handleInboundSave)
	})
}

func (s *Server) inboundSettings(ctx context.Context) InboundSettings {
	var in InboundSettings
	_ = s.store.GetSetting(ctx, settingInbound, &in)
	return in
}

// panelPorts are the ports of both panels: the saved ones and the running
// ones (they differ until the service restarts), so saving new ports never
// closes the panel the administrator is using.
func (s *Server) panelPorts(ctx context.Context) []int {
	var ports []int
	n, _ := s.Network(ctx)
	for _, l := range []string{n.AdminListen, n.PanelListen, s.RunningAdmin, s.RunningPanel} {
		if i := strings.LastIndex(l, ":"); i >= 0 {
			if p, err := strconv.Atoi(l[i+1:]); err == nil && p > 0 && !slices.Contains(ports, p) {
				ports = append(ports, p)
			}
		}
	}
	return ports
}

// firewallArgs is the helper's firewall request: the blocked addresses and
// the inbound rule.
func (s *Server) firewallArgs(ctx context.Context) map[string]any {
	a := map[string]any{"blocked": s.blockedList(ctx)}
	if in := s.inboundSettings(ctx); in.On {
		a["inbound"] = true
		a["tcp"] = append(s.panelPorts(ctx), in.TCP...)
		a["udp"] = in.UDP
	}
	return a
}

// parsePorts reads "3000 8080, 9000" into ports.
func parsePorts(v string) ([]int, error) {
	var l []int
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
		p, err := strconv.Atoi(f)
		if err != nil || p < 1 || p > 65535 {
			return nil, errBadPort
		}
		if !slices.Contains(l, p) {
			l = append(l, p)
		}
	}
	slices.Sort(l)
	return l, nil
}

type userError string

func (e userError) Error() string { return string(e) }

const errBadPort = userError("A port is a number from 1 to 65535.")

func joinInts(l []int) string {
	s := make([]string, len(l))
	for i, p := range l {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, " ")
}

func (s *Server) handleInboundSave(w http.ResponseWriter, r *http.Request) {
	tcp, err := parsePorts(r.FormValue("tcp"))
	if err == nil {
		var udp []int
		if udp, err = parsePorts(r.FormValue("udp")); err == nil {
			in := InboundSettings{On: r.FormValue("on") != "", TCP: tcp, UDP: udp}
			if err = s.store.SetSetting(r.Context(), settingInbound, in); err != nil {
				s.serverError(w, r, err)
				return
			}
			if err = s.applyFirewall(r.Context(), actor(r)); err != nil {
				s.redirectErr(w, r, "/settings/security", storeErr(err))
				return
			}
			s.audit(r, "firewall.inbound", "settings", "on %t, extra TCP %s, UDP %s", in.On, joinInts(tcp), joinInts(udp))
			s.redirect(w, r, "/settings/security", "Saved.")
			return
		}
	}
	s.redirectErr(w, r, "/settings/security", err.Error())
}

// inboundView is what the security page shows.
type inboundView struct {
	S InboundSettings
	// Open: ports that are always open (from the helper's last answer)
	Open string
	TCP  string
	UDP  string
}

func (s *Server) inboundView(ctx context.Context) inboundView {
	in := s.inboundSettings(ctx)
	v := inboundView{S: in, TCP: joinInts(in.TCP), UDP: joinInts(in.UDP)}
	open := append([]int{22, 53, 80, 443}, s.panelPorts(ctx)...)
	slices.Sort(open)
	v.Open = joinInts(slices.Compact(open))
	return v
}
