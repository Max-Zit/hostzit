package web

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/hostzit/internal/helper"
)

// Servers (admin → Servers): one overview of several HostZit servers. Each
// other server is read through its REST API (GET /api/v1/server/status,
// a token with customers:read); a certificate that is not publicly trusted
// is pinned by its SHA-256 fingerprint, which the administrator confirms
// once. There is no reseller level: every server keeps its own
// administrators, the overview only reads.

const settingServers = "servers"

// RemoteServer is another HostZit server in the overview.
type RemoteServer struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`   // https://host:8442 (its admin panel and API)
	Token       string `json:"token"` // sealed hzt_… token with customers:read
	Fingerprint string `json:"fingerprint,omitempty"`
}

func init() {
	adminExtra = append(adminExtra, func(s *Server, mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc)) {
		app("GET /servers", s.handleServers)
		admin("POST /servers", s.handleServerAdd)
		admin("POST /servers/{id}/delete", s.handleServerDelete)
	})
}

func (s *Server) remoteServers(ctx context.Context) []RemoteServer {
	var l []RemoteServer
	_ = s.store.GetSetting(ctx, settingServers, &l)
	return l
}

// serverRow is one line of the overview.
type serverRow struct {
	S         RemoteServer
	Local     bool
	OK        bool
	Error     string
	Version   string
	Customers map[string]int
	Load      string
	MemTotal  int64
	MemAvail  int64
	DiskPct   int // fullest disk
	MemPct    int
	Down      []string
	Pinned    bool
}

type serverStatus struct {
	Version   string            `json:"version"`
	Customers map[string]int    `json:"customers"`
	Services  map[string]string `json:"services"` // unit → state
	Load      string            `json:"load"`
	Memory    struct {
		Total int64 `json:"total_mb"`
		Avail int64 `json:"available_mb"`
	} `json:"memory"`
	Disks       []helper.Disk `json:"disks"`
	HelperError string        `json:"helper_error"`
}

func (st serverStatus) row(r *serverRow) {
	r.OK, r.Version, r.Customers, r.Load = st.HelperError == "", st.Version, st.Customers, st.Load
	r.MemTotal, r.MemAvail = st.Memory.Total, st.Memory.Avail
	if r.MemTotal > 0 {
		r.MemPct = int((r.MemTotal - r.MemAvail) * 100 / r.MemTotal)
	}
	for _, d := range st.Disks {
		if d.SizeMB > 0 {
			r.DiskPct = max(r.DiskPct, int(d.UsedMB*100/d.SizeMB))
		}
	}
	for unit, state := range st.Services {
		if state == "failed" {
			r.Down = append(r.Down, unit)
		}
	}
	slices.Sort(r.Down)
	if st.HelperError != "" {
		r.Error = st.HelperError
	}
}

// fetchStatus asks another server for its status.
func (s *Server) fetchStatus(ctx context.Context, rs RemoteServer) (serverStatus, error) {
	var st serverStatus
	tok, err := s.store.OpenSecret("server.token", rs.Token)
	if err != nil {
		return st, err
	}
	err = targetCall(ctx, rs.URL, tok, rs.Fingerprint, http.MethodGet, "/api/v1/server/status", nil, &st)
	return st, err
}

type serversData struct {
	Rows []serverRow
	// Confirm: the certificate of a server being added is not trusted;
	// the administrator compares this fingerprint and saves again.
	Confirm     string
	Name, URL   string
	CanEdit     bool
	TokenNeeded string
}

func (s *Server) handleServers(w http.ResponseWriter, r *http.Request) {
	s.showServers(w, r, http.StatusOK, &serversData{})
}

func (s *Server) showServers(w http.ResponseWriter, r *http.Request, status int, d *serversData) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	// this server first, from its own data
	local := serverRow{Local: true, S: RemoteServer{Name: s.hostingSettings(ctx).ServerName}}
	if counts, err := s.store.CustomerCounts(ctx); err == nil {
		local.Customers = counts
	}
	local.Version, local.OK = s.Version, true
	if in, err := s.serverInfo(ctx); err == nil {
		st := serverStatus{Version: local.Version, Customers: local.Customers, Services: in.Services, Load: in.Load, Disks: in.Disks}
		st.Memory.Total, st.Memory.Avail = in.MemTotalMB, in.MemAvailMB
		st.row(&local)
	} else {
		local.OK, local.Error = false, storeErr(err)
	}
	d.Rows = []serverRow{local}
	list := s.remoteServers(ctx)
	rows := make([]serverRow, len(list))
	var wg sync.WaitGroup
	for i, rs := range list {
		wg.Add(1)
		go func(i int, rs RemoteServer) {
			defer wg.Done()
			rows[i] = serverRow{S: rs, Pinned: rs.Fingerprint != ""}
			st, err := s.fetchStatus(ctx, rs)
			if err != nil {
				rows[i].Error = err.Error()
				return
			}
			st.row(&rows[i])
		}(i, rs)
	}
	wg.Wait()
	d.Rows = append(d.Rows, rows...)
	d.CanEdit = userFrom(r).IsAdmin()
	s.render(w, r, status, "servers", &Page{Title: "Servers", Nav: "servers", Data: d})
}

func (s *Server) handleServerAdd(w http.ResponseWriter, r *http.Request) {
	d := &serversData{Name: strings.TrimSpace(r.FormValue("name")), URL: strings.TrimSpace(r.FormValue("url"))}
	fail := func(msg string) {
		s.showServersErr(w, r, d, msg)
	}
	base, err := helper.CheckTargetURL(d.URL)
	if err != nil {
		fail(err.Error())
		return
	}
	token := strings.TrimSpace(r.FormValue("token"))
	if !strings.HasPrefix(token, "hzt_") || strings.ContainsAny(token, " \r\n") {
		fail("An API token of HostZit starts with hzt_ (on the other server: My account → API tokens, scope customers:read).")
		return
	}
	if d.Name == "" {
		d.Name = strings.TrimPrefix(base, "https://")
	}
	if len(d.Name) > 60 {
		d.Name = d.Name[:60]
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	fp, trusted, err := targetCert(ctx, base)
	if err != nil {
		fail(translate(s.lang(r, userFrom(r)), "The server cannot be reached: %s", err.Error()))
		return
	}
	pin := ""
	if !trusted {
		// a self-signed certificate: the token is sent only after the
		// administrator confirmed the fingerprint
		if strings.ToLower(strings.ReplaceAll(r.FormValue("fingerprint"), ":", "")) != fp {
			d.Confirm = fp
			s.showServers(w, r, http.StatusOK, d)
			return
		}
		pin = fp
	}
	list := s.remoteServers(r.Context())
	for _, x := range list {
		if x.URL == base {
			fail("This server is already in the list.")
			return
		}
	}
	rs := RemoteServer{Name: d.Name, URL: base, Token: s.store.SealSecret("server.token", token), Fingerprint: pin}
	if _, err := s.fetchStatus(ctx, rs); err != nil {
		fail(err.Error())
		return
	}
	for _, x := range list {
		rs.ID = max(rs.ID, x.ID)
	}
	rs.ID++
	list = append(list, rs)
	if err := s.store.SetSetting(r.Context(), settingServers, list); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "servers.add", "server:"+base, "%s added to the overview (pinned %t)", rs.Name, pin != "")
	s.redirect(w, r, "/servers", "Saved.")
}

func (s *Server) showServersErr(w http.ResponseWriter, r *http.Request, d *serversData, msg string) {
	s.flash(w, r, "!"+translate(s.lang(r, userFrom(r)), msg))
	http.Redirect(w, r, "/servers", http.StatusSeeOther)
}

func (s *Server) handleServerDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	list := s.remoteServers(r.Context())
	i := slices.IndexFunc(list, func(x RemoteServer) bool { return x.ID == id })
	if i < 0 {
		s.notFound(w, r)
		return
	}
	gone := list[i]
	list = slices.Delete(list, i, i+1)
	if err := s.store.SetSetting(r.Context(), settingServers, list); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "servers.delete", "server:"+gone.URL, "%s removed from the overview", gone.Name)
	s.redirect(w, r, "/servers", "Removed.")
}
