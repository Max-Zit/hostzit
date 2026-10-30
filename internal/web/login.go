package web

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/hostzit/internal/auth"
	"github.com/max-zit/hostzit/internal/netacl"
	"github.com/max-zit/hostzit/internal/store"
)

type ctxKey int

const (
	ctxUser ctxKey = iota
	ctxSession
	ctxPanel
)

// panelOf is the panel a request belongs to.
func panelOf(r *http.Request) string {
	p, _ := r.Context().Value(ctxPanel).(string)
	return p
}

func userFrom(r *http.Request) *store.User {
	u, _ := r.Context().Value(ctxUser).(*store.User)
	return u
}

func sessionFrom(r *http.Request) *store.Session {
	x, _ := r.Context().Value(ctxSession).(*store.Session)
	return x
}

// cookieName: the __Host- prefix makes browsers refuse the cookie unless
// it is Secure, host-only and for path / (not possible on the dev HTTP listener).
func cookieName(r *http.Request) string {
	n := "hzpanel"
	if panelOf(r) == PanelAdmin {
		n = "hzadmin" // the two panels share the host name (cookies ignore ports)
	}
	if r.TLS != nil {
		return "__Host-" + n
	}
	return n
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, tok string, life time.Duration) {
	// #nosec G124 -- Secure whenever the request came over TLS; plain HTTP is only the loopback dev listener
	http.SetCookie(w, &http.Cookie{Name: cookieName(r), Value: tok, Path: "/", MaxAge: int(life.Seconds()),
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	// #nosec G124 -- Secure whenever the request came over TLS; plain HTTP is only the loopback dev listener
	http.SetCookie(w, &http.Cookie{Name: cookieName(r), Path: "/", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
}

// loadSession puts the user of a full session into the request context
// (and the session of any stage).
func (s *Server) loadSession(panel string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), ctxPanel, panel))
		c, err := r.Cookie(cookieName(r))
		if err != nil || strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}
		sec := s.security(r.Context())
		x, err := s.store.SessionByToken(r.Context(), c.Value, time.Duration(sec.IdleMinutes)*time.Minute)
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				s.serverError(w, r, err)
				return
			}
			s.clearSessionCookie(w, r)
			next.ServeHTTP(w, r)
			return
		}
		ctx := context.WithValue(r.Context(), ctxSession, x)
		if x.Stage == store.StageFull {
			u, err := s.store.UserByID(r.Context(), x.UserID)
			if err != nil || u.Disabled || !rightPanel(panel, u) {
				_ = s.store.DeleteSession(r.Context(), x.Hash)
				s.clearSessionCookie(w, r)
				next.ServeHTTP(w, r)
				return
			}
			_ = s.store.TouchSession(r.Context(), x)
			ctx = context.WithValue(ctx, ctxUser, u)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireUser sends visitors without a full session to the sign-in, and
// users who must change their password to their account page.
func (s *Server) requireUser(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := userFrom(r)
		if u == nil {
			if n, err := s.store.UserCount(r.Context()); err == nil && n == 0 && panelOf(r) == PanelAdmin {
				http.Redirect(w, r, "/setup", http.StatusSeeOther)
				return
			}
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/login?next="+url.QueryEscape(safeNext(r.URL.RequestURI())), http.StatusSeeOther)
				return
			}
			http.Error(w, "signed out", http.StatusUnauthorized)
			return
		}
		if u.MustChangePassword && r.URL.Path != "/account" && r.URL.Path != "/account/password" {
			http.Redirect(w, r, "/account", http.StatusSeeOther)
			return
		}
		next(w, r)
	})
}

// requireWrite refuses viewers.
// rightPanel: staff sign in to the admin panel, customers to the customer panel.
func rightPanel(panel string, u *store.User) bool {
	if panel == PanelAdmin {
		return u.IsStaff()
	}
	return u.IsCustomer()
}

// requireCustomer refuses anything but a customer session.
func (s *Server) requireCustomer(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !userFrom(r).IsCustomer() {
			s.forbidden(w, r)
			return
		}
		next(w, r)
	}
}

func (s *Server) requireWrite(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !userFrom(r).CanWrite() {
			s.forbidden(w, r)
			return
		}
		next(w, r)
	}
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !userFrom(r).IsAdmin() {
			s.forbidden(w, r)
			return
		}
		next(w, r)
	}
}

// safeNext keeps only local paths (no open redirects).
func safeNext(p string) string {
	// Browsers drop tabs and newlines from URLs, so "/<TAB>/evil.example"
	// would become "//evil.example": refuse every control character.
	if strings.IndexFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return "/"
	}
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") {
		return "/"
	}
	return p
}

// ---- first-run setup

type setupData struct {
	Username  string
	NeedToken bool
}

// handleSetup creates the first administrator. It works only while there
// are no users, and asks for the one-time token from the server's data
// directory, so nobody else on the network can claim a fresh server.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.UserCount(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if n > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	p := &Page{Title: "Set up HostZit", Data: &setupData{NeedToken: s.setupToken != ""}}
	if r.Method == http.MethodGet {
		s.render(w, r, http.StatusOK, "setup", p)
		return
	}
	d := p.Data.(*setupData)
	d.Username = strings.TrimSpace(r.FormValue("username"))
	fail := func(msg string) {
		p.Error = translate(s.lang(r, nil), msg)
		s.render(w, r, http.StatusBadRequest, "setup", p)
	}
	ip := clientIP(r)
	if until := s.guard.blocked(r.Context(), ip); !until.IsZero() {
		fail("Too many failed attempts from your address. Try again later.")
		return
	}
	if s.setupToken != "" && subtle.ConstantTimeCompare([]byte(strings.TrimSpace(r.FormValue("token"))), []byte(s.setupToken)) != 1 {
		s.guard.fail(r.Context(), ip, "", "setup token")
		fail("The setup token is wrong. It is in the file setup-token.txt in the server's data directory.")
		return
	}
	if r.FormValue("password") != r.FormValue("password2") {
		fail("The passwords do not match.")
		return
	}
	u, err := s.store.CreateUser(r.Context(), store.NewUser{Username: d.Username, Password: r.FormValue("password"), Role: store.RoleAdmin, DisplayName: r.FormValue("display_name")})
	if err != nil {
		fail(err.Error())
		return
	}
	s.setupToken = ""
	if s.SetupTokenFile != "" {
		_ = os.Remove(s.SetupTokenFile)
	}
	s.auditAs(r, u.Username, "setup", "user:"+u.Username, "first administrator created")
	s.log.Info("first administrator created", "user", u.Username, "ip", ip)
	// The administrator must set up the second factor before the session is full.
	tok, _, err := s.store.CreateSession(r.Context(), u.ID, store.StageMFA, store.MFATimeout, ip, r.UserAgent())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.setSessionCookie(w, r, tok, store.MFATimeout)
	http.Redirect(w, r, "/login/enroll", http.StatusSeeOther)
}

// ---- sign-in

type loginData struct {
	Username string
	Next     string
	OIDC     string // label of the company sign-in button ("" = none)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if n, err := s.store.UserCount(r.Context()); err == nil && n == 0 && panelOf(r) == PanelAdmin {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	d := &loginData{Next: safeNext(r.FormValue("next"))}
	if c := s.oidcSettings(r.Context()); c.enabled() && panelOf(r) == PanelAdmin {
		d.OIDC = orDefault(c.Label, "Company sign-in")
	}
	p := &Page{Title: "Sign in", Data: d}
	if r.Method == http.MethodGet {
		if userFrom(r) != nil {
			http.Redirect(w, r, d.Next, http.StatusSeeOther)
			return
		}
		s.render(w, r, http.StatusOK, "login", p)
		return
	}
	d.Username = strings.TrimSpace(r.FormValue("username"))
	ip := clientIP(r)
	lang := s.lang(r, nil)
	if until := s.guard.blocked(r.Context(), ip); !until.IsZero() {
		p.Error = translate(lang, "Too many failed attempts from your address. Try again after %s.", until.Local().Format("15:04"))
		s.render(w, r, http.StatusTooManyRequests, "login", p)
		return
	}
	if s.guard.userThrottled(d.Username) {
		auth.BurnTime(r.FormValue("password"))
		p.Error = translate(lang, "Too many failed attempts for this user. Try again later.")
		s.render(w, r, http.StatusTooManyRequests, "login", p)
		return
	}
	u, err := s.store.CheckPassword(r.Context(), d.Username, r.FormValue("password"))
	if err == nil && !rightPanel(panelOf(r), u) {
		err = store.ErrNotFound // the other panel's users do not exist here
	}
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.serverError(w, r, err)
			return
		}
		s.guard.fail(r.Context(), ip, d.Username, "password")
		s.auditAs(r, d.Username, "login.failed", "user:"+d.Username, "wrong username or password")
		p.Error = translate(lang, "Wrong username or password.")
		s.render(w, r, http.StatusUnauthorized, "login", p)
		return
	}
	if s.DevNo2FA || (u.IsCustomer() && !u.TOTPEnabled && !s.security(r.Context()).Customer2FA) {
		x := &store.Session{UserID: u.ID, IP: ip, UserAgent: r.UserAgent()}
		how := "password only"
		if s.DevNo2FA {
			how = "password only, development mode"
		}
		if s.finishLogin(w, r, x, u, how) {
			http.Redirect(w, r, d.Next, http.StatusSeeOther)
		}
		return
	}
	// Password ok: the second factor follows (setup if it does not exist yet).
	tok, _, err := s.store.CreateSession(r.Context(), u.ID, store.StageMFA, store.MFATimeout, ip, r.UserAgent())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.setSessionCookie(w, r, tok, store.MFATimeout)
	next := "/login/2fa"
	if !u.TOTPEnabled {
		next = "/login/enroll"
	}
	http.Redirect(w, r, next+"?next="+url.QueryEscape(d.Next), http.StatusSeeOther)
}

// mfaUser is the user of a password-verified sign-in waiting for its code.
func (s *Server) mfaUser(r *http.Request) (*store.Session, *store.User) {
	x := sessionFrom(r)
	if x == nil || x.Stage != store.StageMFA {
		return nil, nil
	}
	u, err := s.store.UserByID(r.Context(), x.UserID)
	if err != nil || u.Disabled {
		return nil, nil
	}
	return x, u
}

func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, x *store.Session, u *store.User, how string) bool {
	sec := s.security(r.Context())
	life := time.Duration(sec.SessionHours) * time.Hour
	tok, err := s.store.PromoteSession(r.Context(), x, life)
	if err != nil {
		s.serverError(w, r, err)
		return false
	}
	s.setSessionCookie(w, r, tok, life)
	_ = s.store.MarkLogin(r.Context(), u.ID)
	s.guard.success(clientIP(r), u.Username)
	s.auditAs(r, u.Username, "login", "user:"+u.Username, "signed in (%s)", how)
	return true
}

type twoFAData struct{ Next string }

func (s *Server) handleLogin2FA(w http.ResponseWriter, r *http.Request) {
	x, u := s.mfaUser(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !u.TOTPEnabled {
		http.Redirect(w, r, "/login/enroll", http.StatusSeeOther)
		return
	}
	d := &twoFAData{Next: safeNext(r.FormValue("next"))}
	p := &Page{Title: "Two-factor sign-in", Data: d, Lang: s.lang(r, u)}
	if r.Method == http.MethodGet {
		s.render(w, r, http.StatusOK, "login2fa", p)
		return
	}
	ip := clientIP(r)
	if until := s.guard.blocked(r.Context(), ip); !until.IsZero() || s.guard.userThrottled(u.Username) {
		_ = s.store.DeleteSession(r.Context(), x.Hash)
		s.clearSessionCookie(w, r)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	ok, how := false, "authenticator code"
	if len(strings.ReplaceAll(code, " ", "")) == 6 {
		tf, err := s.store.GetTwoFactor(r.Context(), u.ID)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if step, good := auth.TOTPVerify(tf.Secret, code, s.now(), tf.LastStep); good {
			ok, _ = s.store.UseTOTPStep(r.Context(), u.ID, step)
		}
	} else if code != "" {
		ok, _ = s.store.UseRecoveryCode(r.Context(), u.ID, code)
		how = "recovery code"
	}
	if !ok {
		s.guard.fail(r.Context(), ip, u.Username, "second factor")
		s.auditAs(r, u.Username, "login.failed", "user:"+u.Username, "wrong second-factor code")
		p.Error = p.T("The code is wrong or was already used.")
		s.render(w, r, http.StatusUnauthorized, "login2fa", p)
		return
	}
	if s.finishLogin(w, r, x, u, how) {
		http.Redirect(w, r, d.Next, http.StatusSeeOther)
	}
}

type enrollData struct {
	Secret string
	QR     *auth.QR
	Codes  []string
	Next   string
}

// handleEnroll sets up the mandatory authenticator app.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	x, u := s.mfaUser(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if u.TOTPEnabled {
		http.Redirect(w, r, "/login/2fa", http.StatusSeeOther)
		return
	}
	d := &enrollData{Next: safeNext(r.FormValue("next"))}
	p := &Page{Title: "Set up two-factor sign-in", Data: d, Lang: s.lang(r, u)}
	show := func(status int) {
		tf, err := s.store.GetTwoFactor(r.Context(), u.ID)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if tf.Secret == "" {
			tf.Secret = auth.NewTOTPSecret()
			if err := s.store.SetPendingTOTP(r.Context(), u.ID, tf.Secret); err != nil {
				s.serverError(w, r, err)
				return
			}
		}
		d.Secret = tf.Secret
		d.QR, _ = auth.QRFor(auth.TOTPURI(tf.Secret, u.Username))
		s.render(w, r, status, "enroll", p)
	}
	if r.Method == http.MethodGet {
		show(http.StatusOK)
		return
	}
	tf, err := s.store.GetTwoFactor(r.Context(), u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	step, ok := auth.TOTPVerify(tf.Secret, r.FormValue("code"), s.now(), 0)
	if tf.Secret == "" || !ok {
		s.guard.fail(r.Context(), clientIP(r), u.Username, "second factor setup")
		p.Error = p.T("The code is wrong. Check that the time of your phone is correct and try again.")
		show(http.StatusBadRequest)
		return
	}
	plain, hashed := auth.NewRecoveryCodes()
	if err := s.store.EnableTOTP(r.Context(), u.ID, step, hashed); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.auditAs(r, u.Username, "2fa.enable", "user:"+u.Username, "authenticator app set up")
	if !s.finishLogin(w, r, x, u, "new authenticator") {
		return
	}
	d.Codes = plain
	p.User = nil // the page is shown in the guest layout
	s.render(w, r, http.StatusOK, "recoverycodes", p)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if x := sessionFrom(r); x != nil {
		_ = s.store.DeleteSession(r.Context(), x.Hash)
		if u := userFrom(r); u != nil {
			s.audit(r, "logout", "user:"+u.Username, "signed out")
		}
	}
	s.clearSessionCookie(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleLang(w http.ResponseWriter, r *http.Request) {
	l := r.FormValue("lang")
	if !validLang(l) {
		http.Error(w, "unknown language", http.StatusBadRequest)
		return
	}
	// #nosec G124 -- Secure whenever the request came over TLS; plain HTTP is only the loopback dev listener
	http.SetCookie(w, &http.Cookie{Name: "lang", Value: l, Path: "/", MaxAge: 365 * 86400, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode, HttpOnly: true})
	if u := userFrom(r); u != nil {
		_ = s.store.SetLang(r.Context(), u.ID, l)
	}
	back := "/"
	if ref, err := urlPath(r.Referer()); err == nil {
		back = safeNext(ref)
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// ---- brute-force protection

// loginGuard counts failed sign-ins per address and per username in
// memory. An address that reaches the limit is blocked in the database
// (so a restart does not release it), each repeated block within a day
// twice as long. A username that fails too often from many addresses is
// only throttled for the window, so a guesser cannot lock an
// administrator out for long. Loopback is never blocked: the server's own
// console must always work.
type loginGuard struct {
	store *store.Store
	now   func() time.Time
	cfg   func(ctx context.Context) SecuritySettings

	mu    sync.Mutex
	ips   map[string][]time.Time
	users map[string][]time.Time
}

const maxBlock = 7 * 24 * time.Hour

func newLoginGuard(st *store.Store, now func() time.Time) *loginGuard {
	return &loginGuard{store: st, now: now, ips: map[string][]time.Time{}, users: map[string][]time.Time{}}
}

func (g *loginGuard) settings(ctx context.Context) SecuritySettings {
	if g.cfg != nil {
		return g.cfg(ctx)
	}
	x := DefaultSecurity
	if err := g.store.GetSetting(ctx, settingSecurity, &x); err != nil || x.Validate() != nil {
		return DefaultSecurity
	}
	return x
}

func isLoopback(ip string) bool {
	a, ok := netacl.AddrOf(ip)
	return ok && a.IsLoopback()
}

func prune(list []time.Time, since time.Time) []time.Time {
	out := list[:0]
	for _, t := range list {
		if t.After(since) {
			out = append(out, t)
		}
	}
	return out
}

func (g *loginGuard) blocked(ctx context.Context, ip string) time.Time {
	if isLoopback(ip) {
		return time.Time{}
	}
	until, err := g.store.BlockedUntil(ctx, ip)
	if err != nil {
		return time.Time{}
	}
	return until
}

func (g *loginGuard) userThrottled(username string) bool {
	if username == "" {
		return false
	}
	cfg := g.settings(context.Background())
	g.mu.Lock()
	defer g.mu.Unlock()
	k := strings.ToLower(username)
	g.users[k] = prune(g.users[k], g.now().Add(-time.Duration(cfg.WindowMinutes)*time.Minute))
	return len(g.users[k]) >= 4*cfg.MaxAttempts
}

func (g *loginGuard) fail(ctx context.Context, ip, username, reason string) {
	cfg := g.settings(ctx)
	since := g.now().Add(-time.Duration(cfg.WindowMinutes) * time.Minute)
	g.mu.Lock()
	if username != "" {
		k := strings.ToLower(username)
		g.users[k] = append(prune(g.users[k], since), g.now())
	}
	var block bool
	if !isLoopback(ip) {
		g.ips[ip] = append(prune(g.ips[ip], since), g.now())
		if len(g.ips[ip]) >= cfg.MaxAttempts {
			block = true
			delete(g.ips, ip)
		}
	}
	g.mu.Unlock()
	if block {
		d := func(strikes int) time.Duration {
			b := time.Duration(cfg.BlockMinutes) * time.Minute
			for i := 1; i < strikes && b < maxBlock; i++ {
				b *= 2
			}
			return min(b, maxBlock)
		}
		_, _ = g.store.BlockIP(ctx, ip, d, reason)
		_ = g.store.Audit(ctx, "-", ip, "login.blocked", "ip:"+ip, "address blocked after failed sign-ins ("+reason+")")
	}
}

func (g *loginGuard) success(ip, username string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.ips, ip)
	delete(g.users, strings.ToLower(username))
}

// urlPath returns the path and query of a same-site URL (the Referer).
func urlPath(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.RawQuery != "" {
		return u.Path + "?" + u.RawQuery, nil
	}
	return u.Path, nil
}
