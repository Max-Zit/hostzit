package web

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// Tuning of a site's web application firewall: the events come from the
// helper (ModSecurity's audit log); a customer switches off rules that
// block legitimate requests.

// parseRuleIDs reads rule numbers separated by spaces or commas.
func parseRuleIDs(s string) ([]int, error) {
	var out []int
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
		n, err := strconv.Atoi(f)
		if err != nil || n < 1 || n > 99999999 {
			return nil, errBadRule(f)
		}
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out, nil
}

type errBadRule string

func (e errBadRule) Error() string { return "invalid rule number " + strconv.Quote(string(e)) }

// handleWAFRuleOff switches one rule off for a site (from the event list).
func (s *Server) handleWAFRuleOff(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	x := s.mySite(w, r, c)
	if x == nil {
		return
	}
	back := "/sites/" + strconv.FormatInt(x.ID, 10) + "#access"
	add, err := parseRuleIDs(r.FormValue("rule"))
	if err != nil || len(add) != 1 {
		s.redirectErr(w, r, back, "invalid rule number")
		return
	}
	if !slices.Contains(x.WAFExclude, add[0]) {
		x.WAFExclude = append(x.WAFExclude, add[0])
		slices.Sort(x.WAFExclude)
	}
	if err := s.store.SaveSite(r.Context(), x); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	if err := s.applySite(r.Context(), actor(r), x, false); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.audit(r, "site.waf", "site:"+x.Domain, "firewall rule %d switched off", add[0])
	s.redirect(w, r, back, "The rule is off for this website.")
}
