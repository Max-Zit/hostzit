package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

//go:embed i18n/*.json
var i18nFS embed.FS

// Language is a console language.
type Language struct{ Code, Name string }

// Languages the console offers, by their own names; English is the source
// language.
var Languages = []Language{
	{"en", "English"}, {"de", "Deutsch"}, {"fr", "Français"}, {"es", "Español"}, {"it", "Italiano"},
	{"pt", "Português"}, {"nl", "Nederlands"}, {"pl", "Polski"}, {"cs", "Čeština"}, {"sr", "Srpski"},
	{"tr", "Türkçe"}, {"ru", "Русский"}, {"zh", "中文（简体）"}, {"ja", "日本語"},
}

// catalogs maps language → English text → translation.
var catalogs = map[string]map[string]string{}

func init() {
	for _, l := range Languages[1:] {
		raw, err := i18nFS.ReadFile("i18n/" + l.Code + ".json")
		if err != nil {
			panic(err)
		}
		m := map[string]string{}
		if err := json.Unmarshal(raw, &m); err != nil {
			panic(fmt.Sprintf("i18n/%s.json: %v", l.Code, err))
		}
		catalogs[l.Code] = m
	}
}

func validLang(code string) bool {
	for _, l := range Languages {
		if l.Code == code {
			return true
		}
	}
	return false
}

// translate returns the text in lang; with args it is a format string.
func translate(lang, key string, args ...any) string {
	if t, ok := catalogs[lang][key]; ok && t != "" {
		key = t
	}
	if len(args) > 0 {
		return fmt.Sprintf(key, args...)
	}
	return key
}

// Page is what every template gets.
type Page struct {
	Title    string
	Nav      string
	Lang     string
	User     *store.User
	Flash    string
	FlashErr bool // the flash message reports a failure
	Error    string
	Version  string
	DevNo2FA bool
	Asset    string
	Path     string
	Host     string // the console host as the browser sees it
	Refresh  int    // seconds until the page reloads itself (0 = never)
	// Panel is "admin" or "customer".
	Panel string
	// Customer is the account of the customer panel.
	Customer *store.Customer
	// Acting is the administrator working in this customer panel.
	Acting string
	// Crumb is an optional link above the title.
	Crumb, CrumbURL string
	Data            any
}

// T translates a text for the page language.
func (p *Page) T(key string, args ...any) string { return translate(p.Lang, key, args...) }

// Languages lists the console languages (for the language menu).
func (p *Page) Languages() []Language { return Languages }

// Time formats a time in the server's zone.
func (p *Page) Time(t any) string {
	switch v := t.(type) {
	case time.Time:
		if v.IsZero() {
			return "—"
		}
		return v.Local().Format("2006-01-02 15:04")
	case *time.Time:
		if v == nil || v.IsZero() {
			return "—"
		}
		return v.Local().Format("2006-01-02 15:04")
	}
	return ""
}

// Ago is a short relative time ("5 min ago").
func (p *Page) Ago(t any) string {
	var tt time.Time
	switch v := t.(type) {
	case time.Time:
		tt = v
	case *time.Time:
		if v == nil {
			return "—"
		}
		tt = *v
	}
	if tt.IsZero() {
		return "—"
	}
	d := time.Since(tt)
	switch {
	case d < time.Minute:
		return p.T("just now")
	case d < time.Hour:
		return p.T("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return p.T("%d h ago", int(d.Hours()))
	}
	return p.T("%d days ago", int(d.Hours()/24))
}

// Since is a duration up to now, for "down for 3 h 5 min".
func (p *Page) Since(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return p.T("%d s", int(d.Seconds()))
	case d < time.Hour:
		return p.T("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return p.T("%d h %d min", int(d.Hours()), int(d.Minutes())%60)
	}
	return p.T("%d d %d h", int(d.Hours())/24, int(d.Hours())%24)
}

// RoleName is the display name of a role.
func (p *Page) RoleName(r string) string {
	switch r {
	case store.RoleAdmin:
		return p.T("Administrator")
	case store.RoleOperator:
		return p.T("Operator")
	case store.RoleViewer:
		return p.T("Viewer")
	}
	return r
}

// StatusName is the display name of a customer status.
func (p *Page) StatusName(st string) string {
	switch st {
	case store.StatusActive:
		return p.T("Active")
	case store.StatusSuspended:
		return p.T("Suspended")
	case store.StatusTerminated:
		return p.T("Terminated")
	}
	return st
}

// IsAdminPanel reports the admin panel.
func (p *Page) IsAdminPanel() bool { return p.Panel == PanelAdmin }

// Zone names the server's time zone, e.g. "CEST, UTC+02:00"; times in the
// console are shown in it.
func (p *Page) Zone() string { return time.Now().Format("MST, UTC-07:00") }

// ClockInfo feeds the sidebar clock.
type ClockInfo struct {
	Text string
	MS   int64
	Off  int
}

// Clock is the server's time; app.js keeps it ticking from this value, so
// a wrong clock of the viewer's PC does not matter.
func (p *Page) Clock() ClockInfo {
	now := time.Now()
	_, off := now.Zone()
	return ClockInfo{Text: now.Format("2006-01-02 15:04:05"), MS: now.UnixMilli(), Off: off}
}

var funcs = template.FuncMap{
	"initial": func(s string) string {
		for _, r := range s {
			return strings.ToUpper(string(r))
		}
		return "?"
	},
	"join": strings.Join,
	"fval": func(p *float64) string {
		if p == nil {
			return ""
		}
		return strconv.FormatFloat(*p, 'g', -1, 64)
	},
	"deref64": func(p *int64) int64 {
		if p == nil {
			return 0
		}
		return *p
	},
}

// loadTemplates parses each page together with the layout.
func loadTemplates() (map[string]*template.Template, error) {
	base, err := template.New("").Funcs(funcs).ParseFS(templateFS, "templates/_*.html")
	if err != nil {
		return nil, err
	}
	pages, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	out := map[string]*template.Template{}
	for _, p := range pages {
		name := strings.TrimSuffix(strings.TrimPrefix(p, "templates/"), ".html")
		if strings.HasPrefix(name, "_") {
			continue
		}
		t, err := template.Must(base.Clone()).ParseFS(templateFS, p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		out[name] = t
	}
	return out, nil
}

// render writes a page; the layout is chosen by the page itself
// ({{template "app" .}} or {{template "guest" .}}).
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, p *Page) {
	t, ok := s.tmpl[name]
	if !ok {
		s.serverError(w, r, fmt.Errorf("no template %q", name))
		return
	}
	if p.User == nil {
		p.User = userFrom(r)
	}
	if p.Lang == "" {
		p.Lang = s.lang(r, p.User) // the user's own language first
	}
	p.Version = s.Version
	p.DevNo2FA = s.DevNo2FA
	p.Asset = assetVersion
	p.Path = r.URL.RequestURI()
	p.Host = r.Host
	p.Panel = panelOf(r)
	if x := sessionFrom(r); x != nil {
		p.Acting = x.ActingAdmin
	}
	if p.Customer == nil && p.User.IsCustomer() {
		if c, err := s.store.CustomerByID(r.Context(), *p.User.CustomerID); err == nil {
			p.Customer = c
		}
	}
	if f := s.takeFlash(w, r); f != "" && p.Flash == "" {
		// An error message (redirectErr) starts with "!".
		p.Flash, p.FlashErr = strings.TrimPrefix(f, "!"), strings.HasPrefix(f, "!")
	}
	var b strings.Builder
	if err := t.ExecuteTemplate(&b, name+".html", p); err != nil {
		s.serverError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(b.String()))
}

// lang picks the console language: the user's choice, the lang cookie,
// then the browser's preference.
func (s *Server) lang(r *http.Request, u *store.User) string {
	if u != nil && validLang(u.Lang) {
		return u.Lang
	}
	if c, err := r.Cookie("lang"); err == nil && validLang(c.Value) {
		return c.Value
	}
	for _, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		code := strings.ToLower(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]))
		code = strings.SplitN(code, "-", 2)[0]
		if code == "sr" || code == "hr" || code == "bs" || code == "sh" {
			return "sr"
		}
		if validLang(code) {
			return code
		}
	}
	return "en"
}

// ---- flash messages: a short-lived cookie carries the message (in
// English, translated when shown) across the redirect after a POST.

func flashCookie(r *http.Request) string {
	if panelOf(r) == PanelAdmin {
		return "hzaflash"
	}
	return "hzflash"
}

func (s *Server) flash(w http.ResponseWriter, r *http.Request, msg string) {
	// #nosec G124 -- Secure whenever the request came over TLS; plain HTTP is only the loopback dev listener
	http.SetCookie(w, &http.Cookie{Name: flashCookie(r), Value: url.QueryEscape(msg), Path: "/", MaxAge: 60,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
}

func (s *Server) takeFlash(w http.ResponseWriter, r *http.Request) string {
	c, err := r.Cookie(flashCookie(r))
	if err != nil {
		return ""
	}
	// #nosec G124 -- Secure whenever the request came over TLS; plain HTTP is only the loopback dev listener
	http.SetCookie(w, &http.Cookie{Name: flashCookie(r), Path: "/", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
	msg, _ := url.QueryUnescape(c.Value)
	if len(msg) > 300 {
		return ""
	}
	if strings.HasPrefix(msg, "!") {
		return msg // an error, translated when it was set
	}
	return translate(s.lang(r, userFrom(r)), msg)
}

// redirect answers a POST with 303 See Other and an optional message.
func (s *Server) redirect(w http.ResponseWriter, r *http.Request, to, msg string) {
	if msg != "" {
		s.flash(w, r, msg)
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// redirectErr answers a POST with an error message shown on the next page.
func (s *Server) redirectErr(w http.ResponseWriter, r *http.Request, to, msg string) {
	s.flash(w, r, "!"+translate(s.lang(r, userFrom(r)), msg))
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// assetVersion changes with the static files, so browsers do not keep an
// old app.css or app.js from their cache after an update.
var assetVersion = func() string {
	h := sha256.New()
	for _, f := range []string{"static/app.css", "static/app.js", "static/chart.js"} {
		b, _ := staticFS.ReadFile(f)
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}()

func init() {
	funcs["list"] = func(xs ...string) []string { return xs }
	funcs["inStrings"] = func(xs []string, x string) bool { return slices.Contains(xs, x) }
	funcs["kb"] = func(kb int64) string { return humanBytes(kb * 1024) }
	funcs["bytes"] = func(v any) string {
		switch x := v.(type) {
		case int64:
			return humanBytes(x)
		case int:
			return humanBytes(int64(x))
		}
		return ""
	}
	funcs["mb"] = func(mb int) string {
		if mb <= 0 {
			return "∞"
		}
		return humanBytes(int64(mb) << 20)
	}
	funcs["pct"] = func(used, limit int64) int {
		if limit <= 0 {
			return 0
		}
		return int(min(100, used*100/limit))
	}
	funcs["mul"] = func(a, b int64) int64 { return a * b }
	funcs["i64"] = func(n int) int64 { return int64(n) }
	funcs["statusClass"] = func(st string) string {
		switch st {
		case store.StatusActive, "ok", "done", "uploaded":
			return "ok"
		case store.StatusSuspended, "pending", "queued", "running":
			return "warn"
		case store.StatusTerminated, "failed":
			return "bad"
		}
		return ""
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// badgeCtx is the argument of the badge template.
type badgeCtx struct {
	P *Page
	V string
}

func init() {
	funcs["st"] = func(p *Page, v string) badgeCtx { return badgeCtx{P: p, V: v} }
	// pct5 rounds a share to 5 % steps (the meter classes w0 … w100).
	funcs["pct5"] = func(used, limit int64) int {
		if limit <= 0 {
			return 0
		}
		v := min(100, used*100/limit)
		return int((v + 2) / 5 * 5)
	}
}

func init() {
	funcs["scopes"] = func() []string { return store.Scopes }
}

// rowCtx is a value of a shared template together with its page.
type rowCtx struct {
	P   *Page
	Row string
}

func init() {
	funcs["rowOf"] = func(p *Page, v string) rowCtx { return rowCtx{P: p, Row: v} }
}

// spark draws a small line graph of numbers (server-side SVG, no script).
func spark(vals []int64) template.HTML {
	if len(vals) < 2 {
		return ""
	}
	var mx int64 = 1
	for _, v := range vals {
		mx = max(mx, v)
	}
	var b strings.Builder
	b.WriteString(`<svg class="spark" viewBox="0 0 400 60" preserveAspectRatio="none" role="img" aria-hidden="true"><polyline points="`)
	for i, v := range vals {
		x := float64(i) * 400 / float64(len(vals)-1)
		y := 58 - float64(v)*56/float64(mx)
		fmt.Fprintf(&b, "%.1f,%.1f ", x, y)
	}
	b.WriteString(`"/></svg>`)
	return template.HTML(b.String()) // #nosec G203 -- numbers only
}

func init() { funcs["spark"] = spark }
