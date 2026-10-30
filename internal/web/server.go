// Package web serves the two HostZit panels: the admin panel (server
// administrators, like WHM) and the customer panel (one hosting account,
// like cPanel), plus the REST API for billing systems. Both panels run in
// one process on separate listeners, so the admin panel can be kept behind
// its own allow-list or firewall.
package web

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/hostzit/internal/helper"
	"github.com/max-zit/hostzit/internal/hosting"
	"github.com/max-zit/hostzit/internal/netacl"
	"github.com/max-zit/hostzit/internal/store"
)

// Panel kinds.
const (
	PanelAdmin    = "admin"
	PanelCustomer = "customer"
)

// Helper is what the panel asks the root helper (helper.Client or a fake
// in tests).
type Helper interface {
	CallAs(ctx context.Context, by, reqID, op string, args, result any) error
}

// Server serves the panels.
type Server struct {
	store *store.Store
	log   *slog.Logger
	tmpl  map[string]*template.Template
	now   func() time.Time
	guard *loginGuard
	help  Helper

	// AdminACL and PanelACL guard the listeners.
	AdminACL *netacl.List
	PanelACL *netacl.List
	// RunningAdmin / RunningPanel are the listen addresses in use.
	RunningAdmin, RunningPanel string
	ListenOverride             bool
	Version                    string
	SetupTokenFile             string
	DevNo2FA                   bool
	setupToken                 string
	DataDir                    string
	// ACMEChallengeDir is where HTTP-01 answers are written (shared with nginx).
	ACMEChallengeDir string

	acmeMu  sync.Mutex
	jobs    sync.WaitGroup
	applyMu sync.Map // customer id → *sync.Mutex (one change at a time per account)
}

// New creates the server.
func New(ctx context.Context, st *store.Store, h Helper, log *slog.Logger) (*Server, error) {
	t, err := loadTemplates()
	if err != nil {
		return nil, err
	}
	s := &Server{store: st, help: h, log: log, tmpl: t, now: time.Now, Version: "dev", ACMEChallengeDir: hosting.ACMEChallengeDir}
	s.guard = newLoginGuard(st, func() time.Time { return s.now() })
	n, err := s.Network(ctx)
	if err != nil {
		return nil, err
	}
	ad, _ := netacl.Parse(n.AdminAllowed)
	s.AdminACL = netacl.NewManagement(ad)
	pa, _ := netacl.Parse(n.PanelAllowed)
	s.PanelACL = netacl.NewOptional(pa)
	return s, nil
}

// SetClock replaces the clock (tests).
func (s *Server) SetClock(now func() time.Time) { s.now = now }

// SetSetupToken sets the token the first-run setup requires.
func (s *Server) SetSetupToken(tok string) { s.setupToken = tok }

// Wait waits for background jobs (shutdown, tests).
func (s *Server) Wait() { s.jobs.Wait() }

// ---- network settings

const settingNetwork = "network"

// NetworkSettings are the two listeners and who may reach them.
type NetworkSettings struct {
	AdminListen  string   `json:"admin_listen"`
	AdminAllowed []string `json:"admin_allowed"`
	PanelListen  string   `json:"panel_listen"`
	PanelAllowed []string `json:"panel_allowed"` // empty = everyone
}

func defaultNetwork() NetworkSettings {
	return NetworkSettings{AdminListen: ":8442", PanelListen: ":8443", AdminAllowed: append([]string(nil), netacl.DefaultManagement...)}
}

// Validate checks the addresses and networks.
func (n *NetworkSettings) Validate() error {
	ah, ap, err := splitListen(n.AdminListen)
	if err != nil {
		return fmt.Errorf("admin panel address: %w", err)
	}
	ph, pp, err := splitListen(n.PanelListen)
	if err != nil {
		return fmt.Errorf("customer panel address: %w", err)
	}
	if ap == pp && (ah == ph || ah == "" || ph == "") {
		return errors.New("the admin panel and the customer panel must use different ports")
	}
	if _, err := netacl.Parse(n.AdminAllowed); err != nil {
		return err
	}
	if _, err := netacl.Parse(n.PanelAllowed); err != nil {
		return err
	}
	return nil
}

func splitListen(a string) (host string, port int, err error) {
	h, p, err := net.SplitHostPort(strings.TrimSpace(a))
	if err != nil {
		return "", 0, errors.New("use host:port or :port, e.g. :8443")
	}
	port, err = strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, errors.New("the port must be 1–65535")
	}
	if h != "" {
		if _, err := netip.ParseAddr(h); err != nil {
			return "", 0, errors.New("the host must be an IP address of this server (or empty for all)")
		}
	}
	return h, port, nil
}

// Network loads the network settings.
func (s *Server) Network(ctx context.Context) (NetworkSettings, error) {
	n := defaultNetwork()
	if err := s.store.GetSetting(ctx, settingNetwork, &n); err != nil {
		return n, err
	}
	if n.Validate() != nil {
		s.log.Warn("invalid network settings in the database; using defaults")
		n = defaultNetwork()
	}
	return n, nil
}

// SaveNetwork stores the settings and applies the allow-lists.
func (s *Server) SaveNetwork(ctx context.Context, n NetworkSettings) error {
	if err := n.Validate(); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingNetwork, n); err != nil {
		return err
	}
	ad, _ := netacl.Parse(n.AdminAllowed)
	s.AdminACL.Set(ad)
	pa, _ := netacl.Parse(n.PanelAllowed)
	s.PanelACL.Set(pa)
	return nil
}

// ResetMgmtAllowList restores the default admin networks (CLI).
func ResetMgmtAllowList(ctx context.Context, st *store.Store) error {
	n := defaultNetwork()
	if err := st.GetSetting(ctx, settingNetwork, &n); err != nil {
		return err
	}
	n.AdminAllowed = append([]string(nil), netacl.DefaultManagement...)
	if n.Validate() != nil {
		n = defaultNetwork()
	}
	return st.SetSetting(ctx, settingNetwork, n)
}

// ---- security settings

const settingSecurity = "security"

// SecuritySettings control sessions and the brute-force protection.
type SecuritySettings struct {
	SessionHours  int  `json:"session_hours"`
	IdleMinutes   int  `json:"idle_minutes"`
	MaxAttempts   int  `json:"max_attempts"`
	WindowMinutes int  `json:"window_minutes"`
	BlockMinutes  int  `json:"block_minutes"`
	Customer2FA   bool `json:"customer_2fa"` // customers must use two-factor sign-in too
}

// DefaultSecurity: short admin sessions, customers may choose 2FA.
var DefaultSecurity = SecuritySettings{SessionHours: 8, IdleMinutes: 30, MaxAttempts: 5, WindowMinutes: 15, BlockMinutes: 30}

// Validate checks the ranges.
func (x SecuritySettings) Validate() error {
	switch {
	case x.SessionHours < 1 || x.SessionHours > 24:
		return errors.New("the session length must be 1–24 hours")
	case x.IdleMinutes < 5 || x.IdleMinutes > 1440:
		return errors.New("the inactivity timeout must be 5–1440 minutes")
	case x.MaxAttempts < 3 || x.MaxAttempts > 50:
		return errors.New("failed attempts must be 3–50")
	case x.WindowMinutes < 1 || x.WindowMinutes > 1440:
		return errors.New("the counting period must be 1–1440 minutes")
	case x.BlockMinutes < 1 || x.BlockMinutes > 10080:
		return errors.New("the block must last 1–10080 minutes")
	}
	return nil
}

func (s *Server) security(ctx context.Context) SecuritySettings {
	x := DefaultSecurity
	if err := s.store.GetSetting(ctx, settingSecurity, &x); err != nil || x.Validate() != nil {
		return DefaultSecurity
	}
	return x
}

// ---- handlers

func (s *Server) staticRoutes(mux *http.ServeMux) {
	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(gzipStatic(sub, http.FileServer(http.FS(sub))))))
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/favicon.svg", http.StatusMovedPermanently)
	})
	mux.HandleFunc("POST /lang", s.handleLang)
	mux.HandleFunc("POST /logout", s.handleLogout)
}

// AdminHandler is the admin panel and the REST API.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	s.staticRoutes(mux)
	mux.HandleFunc("GET /setup", s.handleSetup)
	mux.HandleFunc("POST /setup", s.handleSetup)
	mux.HandleFunc("GET /login", s.handleLogin)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("GET /login/2fa", s.handleLogin2FA)
	mux.HandleFunc("POST /login/2fa", s.handleLogin2FA)
	mux.HandleFunc("GET /login/enroll", s.handleEnroll)
	mux.HandleFunc("POST /login/enroll", s.handleEnroll)

	app := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.requireUser(h)) }
	write := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.requireUser(s.requireWrite(h))) }
	admin := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.requireUser(s.requireAdmin(h))) }
	app("GET /{$}", s.handleAdminOverview)
	app("GET /customers", s.handleCustomers)
	write("GET /customers/new", s.handleCustomerForm)
	write("POST /customers/new", s.handleCustomerCreate)
	app("GET /customers/{id}", s.handleCustomer)
	write("POST /customers/{id}", s.handleCustomerUpdate)
	write("POST /customers/{id}/status", s.handleCustomerStatus)
	write("POST /customers/{id}/apply", s.handleCustomerReapply)
	write("POST /customers/{id}/password", s.handleCustomerPassword)
	write("POST /customers/{id}/reset-2fa", s.handleCustomerReset2FA)
	write("POST /customers/{id}/login", s.handleCustomerLoginAs)
	admin("POST /customers/{id}/delete", s.handleCustomerDelete)
	app("GET /packages", s.handlePackages)
	admin("GET /packages/new", s.handlePackageForm)
	admin("POST /packages/new", s.handlePackageSave)
	admin("GET /packages/{id}", s.handlePackageForm)
	admin("POST /packages/{id}", s.handlePackageSave)
	admin("POST /packages/{id}/delete", s.handlePackageDelete)
	app("GET /sites", s.handleAllSites)
	app("GET /dns", s.handleAllZones)
	app("GET /jobs", s.handleJobs)
	app("GET /server", s.handleServer)
	admin("POST /server/service", s.handleService)
	app("GET /docs", s.handleDocs)
	app("GET /docs/search", s.handleDocsSearch)
	app("GET /docs/{page}", s.handleDocs)
	app("GET /account", s.handleAccount)
	app("POST /account/password", s.handleAccountPassword)
	app("POST /account/recovery", s.handleAccountRecovery)
	app("POST /account/sessions/signout", s.handleAccountSignout)
	admin("POST /account/tokens", s.handleAPITokenCreate)
	admin("POST /account/tokens/{id}/delete", s.handleAPITokenDelete)
	admin("GET /users", s.handleUsers)
	admin("POST /users", s.handleUserCreate)
	admin("GET /users/{id}", s.handleUser)
	admin("POST /users/{id}", s.handleUserUpdate)
	admin("POST /users/{id}/password", s.handleUserPassword)
	admin("POST /users/{id}/reset-2fa", s.handleUserReset2FA)
	admin("GET /audit", s.handleAudit)
	admin("GET /settings", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/settings/hosting", http.StatusFound)
	})
	admin("GET /settings/hosting", s.handleHostingSettings)
	admin("POST /settings/hosting", s.handleHostingSettingsSave)
	admin("GET /settings/network", s.handleNetwork)
	admin("POST /settings/network", s.handleNetworkSave)
	admin("GET /settings/security", s.handleSecurity)
	admin("POST /settings/security", s.handleSecuritySave)
	admin("POST /settings/security/unblock", s.handleUnblock)
	s.adminMore(mux, app, write, admin)

	top := http.NewServeMux()
	top.Handle("/api/", s.apiHandler())
	top.Handle("/", s.csrf(s.loadSession(PanelAdmin, mux)))
	return s.secure(s.aclCheck(s.AdminACL, top))
}

// CustomerHandler is the customer panel.
func (s *Server) CustomerHandler() http.Handler {
	mux := http.NewServeMux()
	s.staticRoutes(mux)
	mux.HandleFunc("GET /login", s.handleLogin)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("GET /login/2fa", s.handleLogin2FA)
	mux.HandleFunc("POST /login/2fa", s.handleLogin2FA)
	mux.HandleFunc("GET /login/enroll", s.handleEnroll)
	mux.HandleFunc("POST /login/enroll", s.handleEnroll)
	mux.HandleFunc("GET /sso/{token}", s.handleSSO)
	c := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.requireUser(s.requireCustomer(h))) }
	c("GET /{$}", s.handleCustomerHome)
	c("GET /sites", s.handleMySites)
	c("GET /sites/new", s.handleSiteForm)
	c("POST /sites/new", s.handleSiteCreate)
	c("GET /sites/{id}", s.handleSite)
	c("POST /sites/{id}", s.handleSiteUpdate)
	c("POST /sites/{id}/cache/purge", s.handleSitePurge)
	c("POST /sites/{id}/cert", s.handleSiteCert)
	c("POST /sites/{id}/delete", s.handleSiteDelete)
	c("GET /sites/{id}/logs", s.handleSiteLogs)
	c("GET /dns", s.handleMyZones)
	c("POST /dns", s.handleZoneCreate)
	c("GET /dns/{id}", s.handleZone)
	c("POST /dns/{id}/records", s.handleRecordAdd)
	c("POST /dns/{id}/records/{rid}", s.handleRecordUpdate)
	c("POST /dns/{id}/records/{rid}/delete", s.handleRecordDelete)
	c("POST /dns/{id}/dnssec", s.handleZoneDNSSEC)
	c("POST /dns/{id}/delete", s.handleZoneDelete)
	c("GET /databases", s.handleDatabases)
	c("POST /databases", s.handleDatabaseCreate)
	c("POST /databases/{name}/delete", s.handleDatabaseDelete)
	c("POST /databases/users", s.handleDBUserSave)
	c("POST /databases/users/{name}/delete", s.handleDBUserDelete)
	c("GET /files", s.handleFiles)
	c("GET /files/download", s.handleFileDownload)
	c("POST /files", s.handleFileAction)
	c("GET /files/edit", s.handleFileEdit)
	c("POST /files/edit", s.handleFileSave)
	c("GET /access", s.handleAccess)
	c("POST /access/password", s.handleAccessPassword)
	c("GET /usage", s.handleUsage)
	c("GET /docs", s.handleDocs)
	c("GET /docs/search", s.handleDocsSearch)
	c("GET /docs/{page}", s.handleDocs)
	c("GET /account", s.handleAccount)
	c("POST /account/password", s.handleAccountPassword)
	c("POST /account/recovery", s.handleAccountRecovery)
	c("POST /account/sessions/signout", s.handleAccountSignout)
	c("POST /account/2fa/off", s.handleAccount2FAOff)
	c("GET /account/2fa", s.handleAccount2FA)
	c("POST /account/2fa", s.handleAccount2FA)
	s.customerMore(mux, c)
	return s.secure(s.aclCheck(s.PanelACL, s.csrf(s.loadSession(PanelCustomer, mux))))
}

// adminMore and customerMore add the pages of later versions.
var (
	adminExtra    []func(s *Server, mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc))
	customerExtra []func(s *Server, mux *http.ServeMux, c func(string, http.HandlerFunc))
)

func (s *Server) adminMore(mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc)) {
	for _, f := range adminExtra {
		f(s, mux, app, write, admin)
	}
}

func (s *Server) customerMore(mux *http.ServeMux, c func(string, http.HandlerFunc)) {
	for _, f := range customerExtra {
		f(s, mux, c)
	}
}

func cacheStatic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		next.ServeHTTP(w, r)
	})
}

// secure sets the security headers of every response.
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cross-Origin-Embedder-Policy", "require-corp")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) aclCheck(l *netacl.List, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.AllowsAddr(r.RemoteAddr) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// csrf refuses state-changing requests that do not come from a page of
// this panel (Origin or Referer must match the host, Sec-Fetch-Site must
// be same-origin).
func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		if !sameOrigin(r) {
			s.log.Warn("cross-site request refused", "ip", clientIP(r), "path", r.URL.Path, "origin", r.Header.Get("Origin"))
			http.Error(w, "cross-site request refused", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func sameOrigin(r *http.Request) bool {
	if sf := r.Header.Get("Sec-Fetch-Site"); sf != "" && sf != "same-origin" {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	want := scheme + "://" + r.Host
	if o := r.Header.Get("Origin"); o != "" {
		return o == want
	}
	ref := r.Header.Get("Referer")
	return ref != "" && (ref == want || strings.HasPrefix(ref, want+"/"))
}

func clientIP(r *http.Request) string {
	if a, ok := netacl.AddrOf(r.RemoteAddr); ok {
		return a.String()
	}
	return r.RemoteAddr
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("request failed", "path", r.URL.Path, "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusNotFound, "notfound", &Page{Title: "Not found"})
}

func (s *Server) forbidden(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusForbidden, "forbidden", &Page{Title: "Not allowed"})
}

func pathID(r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	return id, err == nil && id > 0
}

// actor names who did something (for the audit log and the helper).
func actor(r *http.Request) string {
	u := userFrom(r)
	if u == nil {
		return "-"
	}
	if x := sessionFrom(r); x != nil && x.ActingAdmin != "" {
		return x.ActingAdmin + " as " + u.Username
	}
	return u.Username
}

func (s *Server) audit(r *http.Request, action, target, format string, args ...any) {
	s.auditAs(r, actor(r), action, target, format, args...)
}

func (s *Server) auditAs(r *http.Request, user, action, target, format string, args ...any) {
	detail := format
	if len(args) > 0 {
		detail = fmt.Sprintf(format, args...)
	}
	if err := s.store.Audit(r.Context(), user, clientIP(r), action, target, detail); err != nil {
		s.log.Error("audit log write failed", "action", action, "err", err)
	}
}

// storeErr turns an error into a message for the user.
func storeErr(err error) string {
	var ue *helper.UserError
	switch {
	case errors.Is(err, store.ErrConflict):
		return "The name is already used."
	case errors.Is(err, store.ErrNotFound):
		return "Not found."
	case errors.Is(err, helper.ErrHelperDown):
		return "The HostZit system service (hostzit-helper) is not running."
	case errors.As(err, &ue):
		return ue.Msg
	}
	return err.Error()
}
