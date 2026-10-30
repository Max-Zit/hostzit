package web

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/helper"
	"github.com/max-zit/hostzit/internal/hosting"
	"github.com/max-zit/hostzit/internal/netacl"
	"github.com/max-zit/hostzit/internal/store"
)

// Security pages: the customer's malware scan and mail queue, the
// administrator's server-wide blocked addresses.

func init() {
	customerExtra = append(customerExtra, func(s *Server, mux *http.ServeMux, c func(string, http.HandlerFunc)) {
		c("GET /security", s.handleMySecurity)
		c("POST /security/scan", s.handleMyScan)
	})
	adminExtra = append(adminExtra, func(s *Server, mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc)) {
		admin("POST /settings/security/blocked", s.handleBlockedSave)
		write("POST /customers/{id}/scan", s.handleCustomerScan)
	})
}

// ScanResult is the last malware scan of a customer.
type ScanResult struct {
	Running bool               `json:"running"`
	At      time.Time          `json:"at"`
	Found   []helper.Infection `json:"found"`
	Error   string             `json:"error,omitempty"`
}

func scanKey(id int64) string { return "malware:" + strconv.FormatInt(id, 10) }

func (s *Server) lastScan(ctx context.Context, id int64) *ScanResult {
	var r ScanResult
	if err := s.store.GetSetting(ctx, scanKey(id), &r); err != nil || (r.At.IsZero() && !r.Running) {
		return nil
	}
	return &r
}

// startScan scans a customer's files in the background.
func (s *Server) startScan(by string, c *store.Customer) error {
	ctx := context.Background()
	if r := s.lastScan(ctx, c.ID); r != nil && r.Running && time.Since(r.At) < time.Hour {
		return nil
	}
	_ = s.store.SetSetting(ctx, scanKey(c.ID), ScanResult{Running: true, At: s.now()})
	_, err := s.runJob("malware.scan", &c.ID, c.Username, func(ctx context.Context) error {
		var res struct {
			Found []helper.Infection `json:"found"`
		}
		err := s.call(ctx, by, "malware.scan", map[string]string{"account": c.Username}, &res)
		r := ScanResult{At: s.now(), Found: res.Found}
		if err != nil {
			r.Error = storeErr(err)
		}
		_ = s.store.SetSetting(ctx, scanKey(c.ID), r)
		if len(res.Found) > 0 {
			var b strings.Builder
			for _, f := range res.Found {
				b.WriteString("  " + f.Path + " — " + f.Signature + "\n")
			}
			s.notify(ctx, "malware:"+c.Username, c, "Malware found in "+c.Username, "The malware scan found these files in the hosting account "+c.Username+":\n\n"+b.String()+"\nRemove or replace them, change the passwords of the websites and update WordPress and its plugins.\n")
		}
		_ = s.store.Audit(ctx, by, "local", "malware.scan", "customer:"+c.Username, strconv.Itoa(len(res.Found))+" infected files")
		return err
	})
	return err
}

type securityPageData struct {
	Scan  *ScanResult
	Queue []helper.QueueItem
}

func (s *Server) handleMySecurity(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	d := &securityPageData{Scan: s.lastScan(r.Context(), c.ID)}
	_ = s.call(r.Context(), actor(r), "mail.queue", map[string]string{"account": c.Username}, &d.Queue)
	s.render(w, r, http.StatusOK, "mysecurity", &Page{Title: "Security", Nav: "security", Customer: c, Data: d})
}

func (s *Server) handleMyScan(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	if err := s.startScan(actor(r), c); err != nil {
		s.redirectErr(w, r, "/security", storeErr(err))
		return
	}
	s.redirect(w, r, "/security", "The scan was started. It takes a few minutes; this page shows the result.")
}

func (s *Server) handleCustomerScan(w http.ResponseWriter, r *http.Request) {
	c := s.loadCustomer(w, r)
	if c == nil {
		return
	}
	back := "/customers/" + strconv.FormatInt(c.ID, 10)
	if err := s.startScan(actor(r), c); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.redirect(w, r, back, "The malware scan was started.")
}

const settingFirewall = "firewall"

func (s *Server) blockedList(ctx context.Context) []string {
	var l []string
	_ = s.store.GetSetting(ctx, settingFirewall, &l)
	return l
}

// applyFirewall loads the server-wide block list into the firewall.
func (s *Server) applyFirewall(ctx context.Context, by string) error {
	return s.call(ctx, by, "firewall", map[string]any{"blocked": s.blockedList(ctx)}, nil)
}

func (s *Server) handleBlockedSave(w http.ResponseWriter, r *http.Request) {
	list, err := hosting.CleanNets(netacl.Split(r.FormValue("blocked")))
	if err != nil {
		s.redirectErr(w, r, "/settings/security", err.Error())
		return
	}
	if a, ok := netacl.AddrOf(r.RemoteAddr); ok {
		if l, err := netacl.Parse(list); err == nil && netacl.NewOptional(l).Allows(a) && len(list) > 0 {
			s.redirectErr(w, r, "/settings/security", "Your own address is in the list.")
			return
		}
	}
	if err := s.store.SetSetting(r.Context(), settingFirewall, list); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.applyFirewall(r.Context(), actor(r)); err != nil {
		s.redirectErr(w, r, "/settings/security", storeErr(err))
		return
	}
	s.audit(r, "firewall.blocked", "settings", "%d blocked addresses: %s", len(list), strings.Join(list, " "))
	s.redirect(w, r, "/settings/security", "Saved.")
}
