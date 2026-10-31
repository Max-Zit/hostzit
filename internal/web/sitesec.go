package web

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/max-zit/hostzit/internal/auth"
	"github.com/max-zit/hostzit/internal/hosting"
	"github.com/max-zit/hostzit/internal/netacl"
)

// Access rules of a site: IP allow/deny lists, hotlink protection, the web
// application firewall and folders protected with a password.

func init() {
	customerExtra = append(customerExtra, func(s *Server, mux *http.ServeMux, c func(string, http.HandlerFunc)) {
		c("POST /sites/{id}/access", s.handleSiteAccess)
		c("POST /sites/{id}/waf-rule", s.handleWAFRuleOff)
		c("POST /sites/{id}/protect", s.handleSiteProtect)
		c("POST /sites/{id}/protect/{n}/delete", s.handleSiteUnprotect)
	})
}

func (s *Server) handleSiteAccess(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	x := s.mySite(w, r, c)
	if x == nil {
		return
	}
	back := "/sites/" + strconv.FormatInt(x.ID, 10) + "#access"
	allow, err := hosting.CleanNets(netacl.Split(r.FormValue("ip_allow")))
	if err != nil {
		s.redirectErr(w, r, back, err.Error())
		return
	}
	deny, err := hosting.CleanNets(netacl.Split(r.FormValue("ip_deny")))
	if err != nil {
		s.redirectErr(w, r, back, err.Error())
		return
	}
	// the customer must not lock out the address they are using now
	if len(allow) > 0 {
		ok := false
		if a, okA := netacl.AddrOf(r.RemoteAddr); okA {
			if l, err := netacl.Parse(allow); err == nil {
				ok = netacl.NewOptional(l).Allows(a)
			}
		}
		if !ok && r.FormValue("lockout_ok") == "" {
			s.redirectErr(w, r, back, "Your own address is not in the allowed list. Add it, or tick the box if you really want this.")
			return
		}
	}
	x.IPAllow, x.IPDeny = allow, deny
	x.Hotlink, x.WAF = r.FormValue("hotlink") != "", r.FormValue("waf") != ""
	x.WAFDetect = r.FormValue("waf_detect") != ""
	if x.WAFExclude, err = parseRuleIDs(r.FormValue("waf_exclude")); err != nil {
		s.redirectErr(w, r, back, err.Error())
		return
	}
	if err := s.store.SaveSite(r.Context(), x); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	if err := s.applySite(r.Context(), actor(r), x, false); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.audit(r, "site.access", "site:"+x.Domain, "allow %v, deny %v, hotlink %v, firewall %v (only log %v, rules off %v)", allow, deny, x.Hotlink, x.WAF, x.WAFDetect, x.WAFExclude)
	s.redirect(w, r, back, "Saved.")
}

var protPathRE = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{1,200}$`)

func (s *Server) handleSiteProtect(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	x := s.mySite(w, r, c)
	if x == nil {
		return
	}
	back := "/sites/" + strconv.FormatInt(x.ID, 10) + "#access"
	path := "/" + strings.Trim(strings.TrimSpace(r.FormValue("path")), "/")
	user := strings.TrimSpace(r.FormValue("user"))
	if !protPathRE.MatchString(path) || strings.Contains(path, "..") {
		s.redirectErr(w, r, back, "Enter a folder of the website, e.g. /private")
		return
	}
	if err := auth.CheckPasswordPolicy(r.FormValue("password")); err != nil {
		s.redirectErr(w, r, back, err.Error())
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(r.FormValue("password")), 11)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	u := hosting.HTUser{Name: user, Hash: string(hash)}
	found := false
	for i := range x.Protected {
		if x.Protected[i].Path == path {
			found = true
			users := x.Protected[i].Users[:0]
			for _, o := range x.Protected[i].Users {
				if o.Name != user {
					users = append(users, o)
				}
			}
			x.Protected[i].Users = append(users, u)
		}
	}
	if !found {
		x.Protected = append(x.Protected, hosting.Protected{Path: path, Users: []hosting.HTUser{u}})
	}
	if err := s.store.SaveSite(r.Context(), x); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	if err := s.applySite(r.Context(), actor(r), x, false); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.audit(r, "site.protect", "site:"+x.Domain, "folder %s: user %s", path, user)
	s.redirect(w, r, back, "The folder is protected.")
}

func (s *Server) handleSiteUnprotect(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	x := s.mySite(w, r, c)
	if x == nil {
		return
	}
	back := "/sites/" + strconv.FormatInt(x.ID, 10) + "#access"
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil || n < 0 || n >= len(x.Protected) {
		s.notFound(w, r)
		return
	}
	path := x.Protected[n].Path
	x.Protected = append(x.Protected[:n], x.Protected[n+1:]...)
	if err := s.store.SaveSite(r.Context(), x); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	if err := s.applySite(r.Context(), actor(r), x, false); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.audit(r, "site.unprotect", "site:"+x.Domain, "folder %s open again", path)
	s.redirect(w, r, back, "The folder is open again.")
}
