package web

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/max-zit/hostzit/internal/helper"
	"github.com/max-zit/hostzit/internal/netacl"
	"github.com/max-zit/hostzit/internal/store"
)

type securityData struct {
	X       SecuritySettings
	Blocks  []store.Block
	Blocked string
	Malware MalwareSettings
	ClamAV  helper.MalwareStatus
	WAF     bool
}

func (s *Server) handleSecurity(w http.ResponseWriter, r *http.Request) {
	s.showSecurity(w, r, http.StatusOK, s.security(r.Context()), "")
}

func (s *Server) showSecurity(w http.ResponseWriter, r *http.Request, status int, x SecuritySettings, errMsg string) {
	blocks, err := s.store.Blocks(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := &securityData{X: x, Blocks: blocks, Blocked: strings.Join(s.blockedList(r.Context()), "\n"), Malware: s.malwareSettings(r.Context())}
	_ = s.call(r.Context(), "system", "malware.status", struct{}{}, &d.ClamAV)
	if in, err := s.serverInfo(r.Context()); err == nil {
		d.WAF = in.WAF
	}
	p := &Page{Title: "Sign-in and security", Nav: "settings", Data: d}
	if errMsg != "" {
		p.Error = translate(s.lang(r, userFrom(r)), errMsg)
	}
	s.render(w, r, status, "security", p)
}

func formInt(r *http.Request, k string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(r.FormValue(k)))
	return n
}

func (s *Server) handleSecuritySave(w http.ResponseWriter, r *http.Request) {
	x := SecuritySettings{SessionHours: formInt(r, "session_hours"), IdleMinutes: formInt(r, "idle_minutes"), MaxAttempts: formInt(r, "max_attempts"),
		WindowMinutes: formInt(r, "window_minutes"), BlockMinutes: formInt(r, "block_minutes"), Customer2FA: r.FormValue("customer_2fa") != "", FourEyes: r.FormValue("four_eyes") != ""}
	if err := x.Validate(); err != nil {
		s.showSecurity(w, r, http.StatusBadRequest, x, err.Error())
		return
	}
	if x.FourEyes {
		admins := 0
		if us, err := s.store.Users(r.Context()); err == nil {
			for _, u := range us {
				if u.IsAdmin() && !u.Disabled {
					admins++
				}
			}
		}
		if admins < 2 {
			s.showSecurity(w, r, http.StatusBadRequest, x, "Four-eyes approval needs at least two administrators.")
			return
		}
	}
	if err := s.store.SetSetting(r.Context(), settingSecurity, x); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.security", "settings", "sessions %dh, idle %dmin; block after %d failures in %dmin for %dmin",
		x.SessionHours, x.IdleMinutes, x.MaxAttempts, x.WindowMinutes, x.BlockMinutes)
	s.redirect(w, r, "/settings/security", "Saved.")
}

func (s *Server) handleUnblock(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.FormValue("ip"))
	if _, ok := netacl.AddrOf(ip); !ok && ip != "all" {
		s.showSecurity(w, r, http.StatusBadRequest, s.security(r.Context()), "Not an IP address.")
		return
	}
	if _, err := s.store.Unblock(r.Context(), ip); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "login.unblock", "ip:"+ip, "sign-in block lifted")
	s.redirect(w, r, "/settings/security", "Block lifted.")
}

// ---- audit log

type auditData struct {
	Entries []store.AuditEntry
	Check   store.AuditCheck
	Q       string
	Next    int64
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	before, _ := strconv.ParseInt(r.FormValue("before"), 10, 64)
	q := strings.TrimSpace(r.FormValue("q"))
	if len(q) > 200 {
		q = q[:200]
	}
	list, err := s.store.AuditEntries(r.Context(), store.AuditFilter{Query: q, Before: before, Limit: 100})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	check, err := s.store.VerifyAudit(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := &auditData{Entries: list, Check: check, Q: q}
	if len(list) == 100 {
		d.Next = list[len(list)-1].ID
	}
	s.render(w, r, http.StatusOK, "audit", &Page{Title: "Audit log", Nav: "audit", Data: d})
}

func splitHostPort(h string) (string, string, error) { return net.SplitHostPort(h) }

func joinHostPort(h string, port int) string { return net.JoinHostPort(h, strconv.Itoa(port)) }
