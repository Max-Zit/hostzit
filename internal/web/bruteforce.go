package web

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/helper"
	"github.com/max-zit/hostzit/internal/netacl"
)

// Settings → Brute-force protection (like cPanel's cPHulk): one list of
// every blocked address — the panels' own sign-in blocks and fail2ban's
// SSH/SFTP and WordPress bans — and addresses that are never blocked.

const settingBrute = "bruteforce"

// BruteSettings are the addresses never blocked by the brute-force protection.
type BruteSettings struct {
	Allow []string `json:"allow"`
}

func (s *Server) bruteSettings(ctx context.Context) BruteSettings {
	var b BruteSettings
	_ = s.store.GetSetting(ctx, settingBrute, &b)
	return b
}

// exempt: the server itself and the never-blocked addresses.
func (g *loginGuard) exempt(ctx context.Context, ip string) bool {
	a, ok := netacl.AddrOf(ip)
	if !ok {
		return false
	}
	if a.IsLoopback() {
		return true
	}
	var b BruteSettings
	if g.store.GetSetting(ctx, settingBrute, &b) != nil || len(b.Allow) == 0 {
		return false
	}
	nets, err := netacl.Parse(b.Allow)
	return err == nil && netacl.Contains(nets, a)
}

func init() {
	adminExtra = append(adminExtra, func(s *Server, mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc)) {
		admin("GET /settings/bruteforce", s.handleBrute)
		admin("POST /settings/bruteforce", s.handleBruteSave)
		admin("POST /settings/bruteforce/unblock", s.handleBruteUnblock)
	})
}

// blockRow is one blocked address in the list.
type blockRow struct {
	IP, Source, Reason string
	Since, Until       time.Time
	Strikes            int
}

type bruteData struct {
	X      SecuritySettings
	Allow  string
	Rows   []blockRow
	F2BErr string
}

// applyBrute writes fail2ban's jails with the panel's limits.
func (s *Server) applyBrute(ctx context.Context, by string) error {
	x := s.security(ctx)
	return s.call(ctx, by, "bruteforce.apply", map[string]any{"allow": s.bruteSettings(ctx).Allow,
		"max_retry": x.MaxAttempts, "find_minutes": x.WindowMinutes, "ban_minutes": x.BlockMinutes}, nil)
}

func (s *Server) handleBrute(w http.ResponseWriter, r *http.Request) {
	s.showBrute(w, r, "")
}

func (s *Server) showBrute(w http.ResponseWriter, r *http.Request, errMsg string) {
	ctx := r.Context()
	d := &bruteData{X: s.security(ctx), Allow: strings.Join(s.bruteSettings(ctx).Allow, "\n")}
	blocks, err := s.store.Blocks(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, b := range blocks {
		d.Rows = append(d.Rows, blockRow{IP: b.IP, Source: "panels", Reason: b.Reason, Until: b.Until, Strikes: b.Strikes})
	}
	var bans []helper.F2BBan
	if err := s.call(ctx, "system", "bruteforce.list", nil, &bans); err != nil {
		d.F2BErr = storeErr(err)
	}
	for _, b := range bans {
		d.Rows = append(d.Rows, blockRow{IP: b.IP, Source: b.Source, Since: b.Since, Until: b.Until})
	}
	sort.SliceStable(d.Rows, func(i, j int) bool { return d.Rows[i].Until.After(d.Rows[j].Until) })
	p := &Page{Title: "Brute-force protection", Nav: "settings", Data: d}
	if errMsg != "" {
		p.Error = translate(s.lang(r, userFrom(r)), errMsg)
	}
	s.render(w, r, http.StatusOK, "bruteforce", p)
}

func (s *Server) handleBruteSave(w http.ResponseWriter, r *http.Request) {
	list := netacl.Split(r.FormValue("allow"))
	nets, err := netacl.Parse(list)
	if err != nil {
		s.showBrute(w, r, err.Error())
		return
	}
	b := BruteSettings{Allow: netacl.Strings(nets)}
	if err := s.store.SetSetting(r.Context(), settingBrute, b); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.bruteforce", "settings", "%d addresses never blocked", len(b.Allow))
	if err := s.applyBrute(r.Context(), actor(r)); err != nil {
		s.redirectErr(w, r, "/settings/bruteforce", storeErr(err))
		return
	}
	s.redirect(w, r, "/settings/bruteforce", "Saved.")
}

// handleBruteUnblock lifts a block of the panels or of fail2ban.
func (s *Server) handleBruteUnblock(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.FormValue("ip"))
	if _, ok := netacl.AddrOf(ip); !ok {
		s.redirectErr(w, r, "/settings/bruteforce", "Not an IP address.")
		return
	}
	if r.FormValue("source") == "panels" {
		if _, err := s.store.Unblock(r.Context(), ip); err != nil {
			s.serverError(w, r, err)
			return
		}
	} else if err := s.call(r.Context(), actor(r), "bruteforce.unban", map[string]string{"ip": ip}, nil); err != nil {
		s.redirectErr(w, r, "/settings/bruteforce", storeErr(err))
		return
	}
	s.audit(r, "login.unblock", "ip:"+ip, "block lifted (%s)", r.FormValue("source"))
	s.redirect(w, r, "/settings/bruteforce", "Block lifted.")
}
