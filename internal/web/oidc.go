package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/max-zit/hostzit/internal/auth"
	"github.com/max-zit/hostzit/internal/store"
)

// Company sign-in for administrators with OpenID Connect (Microsoft Entra
// ID, Google Workspace, Keycloak, Authentik …). The identity provider
// proves the e-mail address; an administrator with that address must
// already exist in HostZit (no accounts are made). The second factor is
// asked by HostZit unless the administrator trusts the provider's own.

const settingOIDC = "oidc"

// OIDCSettings configure the identity provider.
type OIDCSettings struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"` // sealed
	Label        string `json:"label"`
	TrustMFA     bool   `json:"trust_mfa"` // the provider asks the second factor
}

func (c OIDCSettings) enabled() bool { return c.Issuer != "" && c.ClientID != "" }

func (s *Server) oidcSettings(ctx context.Context) OIDCSettings {
	var c OIDCSettings
	_ = s.store.GetSetting(ctx, settingOIDC, &c)
	return c
}

func init() {
	adminExtra = append(adminExtra, func(s *Server, mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc)) {
		mux.HandleFunc("GET /login/oidc", s.handleOIDCStart)
		mux.HandleFunc("GET /login/oidc/callback", s.handleOIDCCallback)
		admin("GET /settings/signin", s.handleOIDCSettings)
		admin("POST /settings/signin", s.handleOIDCSettingsSave)
	})
}

var oidcCache struct {
	sync.Mutex
	key      string
	provider *oidc.Provider
	at       time.Time
}

func (s *Server) oidcConfig(ctx context.Context, r *http.Request) (*oauth2.Config, *oidc.IDTokenVerifier, error) {
	c := s.oidcSettings(ctx)
	if !c.enabled() {
		return nil, nil, errors.New("company sign-in is not set up")
	}
	oidcCache.Lock()
	defer oidcCache.Unlock()
	if oidcCache.provider == nil || oidcCache.key != c.Issuer || time.Since(oidcCache.at) > time.Hour {
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		p, err := oidc.NewProvider(cctx, c.Issuer)
		if err != nil {
			return nil, nil, err
		}
		oidcCache.provider, oidcCache.key, oidcCache.at = p, c.Issuer, time.Now()
	}
	secret, _ := s.store.OpenSecret("oidc.secret", c.ClientSecret)
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	conf := &oauth2.Config{ClientID: c.ClientID, ClientSecret: secret, Endpoint: oidcCache.provider.Endpoint(),
		RedirectURL: scheme + "://" + r.Host + "/login/oidc/callback", Scopes: []string{oidc.ScopeOpenID, "email", "profile"}}
	return conf, oidcCache.provider.Verifier(&oidc.Config{ClientID: c.ClientID}), nil
}

// The state cookie carries state, nonce and the PKCE verifier, signed
// with a key derived from the server's secret.
func (s *Server) stateMAC(v string) string {
	m := hmac.New(sha256.New, []byte(s.stateKey()))
	m.Write([]byte(v))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

var stateKeyOnce sync.Once
var stateKeyVal string

func (s *Server) stateKey() string {
	stateKeyOnce.Do(func() { stateKeyVal = auth.RandomToken(32) })
	return stateKeyVal
}

func (s *Server) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	conf, _, err := s.oidcConfig(r.Context(), r)
	if err != nil {
		s.redirectErr(w, r, "/login", "Company sign-in is not available: "+err.Error())
		return
	}
	state, nonce, verifier := auth.RandomToken(24), auth.RandomToken(24), oauth2.GenerateVerifier()
	v := state + "|" + nonce + "|" + verifier + "|" + safeNext(r.FormValue("next"))
	// #nosec G124 -- Secure whenever the request came over TLS
	http.SetCookie(w, &http.Cookie{Name: "hzoidc", Value: url.QueryEscape(v + "|" + s.stateMAC(v)), Path: "/login/oidc", MaxAge: 600, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, conf.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusSeeOther)
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	fail := func(msg string) {
		s.guard.fail(r.Context(), ip, "", "company sign-in")
		s.log.Warn("company sign-in failed", "ip", ip, "reason", msg)
		s.redirectErr(w, r, "/login", "Company sign-in failed: "+msg)
	}
	if until := s.guard.blocked(r.Context(), ip); !until.IsZero() {
		s.redirectErr(w, r, "/login", "Too many failed attempts from your address. Try again later.")
		return
	}
	ck, err := r.Cookie("hzoidc")
	http.SetCookie(w, &http.Cookie{Name: "hzoidc", Path: "/login/oidc", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode}) // #nosec G124
	if err != nil {
		fail("the sign-in took too long, try again")
		return
	}
	raw, _ := url.QueryUnescape(ck.Value)
	i := strings.LastIndex(raw, "|")
	if i < 0 || !hmac.Equal([]byte(raw[i+1:]), []byte(s.stateMAC(raw[:i]))) {
		fail("invalid state")
		return
	}
	parts := strings.SplitN(raw[:i], "|", 4)
	if len(parts) != 4 || r.FormValue("state") != parts[0] {
		fail("invalid state")
		return
	}
	if e := r.FormValue("error"); e != "" {
		fail(e)
		return
	}
	conf, verifier, err := s.oidcConfig(r.Context(), r)
	if err != nil {
		fail(err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	tok, err := conf.Exchange(ctx, r.FormValue("code"), oauth2.VerifierOption(parts[2]))
	if err != nil {
		fail("the code was refused")
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	idt, err := verifier.Verify(ctx, rawID)
	if err != nil || idt.Nonce != parts[1] {
		fail("invalid identity token")
		return
	}
	var claims struct {
		Email    string `json:"email"`
		Verified *bool  `json:"email_verified"`
		UPN      string `json:"preferred_username"`
	}
	_ = idt.Claims(&claims)
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" && strings.Contains(claims.UPN, "@") {
		email = strings.ToLower(claims.UPN)
	}
	if email == "" || claims.Verified != nil && !*claims.Verified {
		fail("the provider sent no verified e-mail address")
		return
	}
	u, err := s.store.StaffByEmail(r.Context(), email)
	if err != nil || u.Disabled {
		fail("no administrator with the address " + email)
		return
	}
	next := safeNext(parts[3])
	x := &store.Session{UserID: u.ID, IP: ip, UserAgent: r.UserAgent()}
	if s.oidcSettings(r.Context()).TrustMFA || s.DevNo2FA {
		if s.finishLogin(w, r, x, u, "company sign-in") {
			http.Redirect(w, r, next, http.StatusSeeOther)
		}
		return
	}
	t, _, err := s.store.CreateSession(r.Context(), u.ID, store.StageMFA, store.MFATimeout, ip, r.UserAgent())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.setSessionCookie(w, r, t, store.MFATimeout)
	step := "/login/2fa"
	if !u.TOTPEnabled {
		step = "/login/enroll"
	}
	http.Redirect(w, r, step+"?next="+url.QueryEscape(next), http.StatusSeeOther)
}

type oidcData struct {
	C         OIDCSettings
	HasSecret bool
	Redirect  string
}

func (s *Server) handleOIDCSettings(w http.ResponseWriter, r *http.Request) {
	c := s.oidcSettings(r.Context())
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	s.render(w, r, http.StatusOK, "signin", &Page{Title: "Company sign-in", Nav: "settings", Data: &oidcData{C: c, HasSecret: c.ClientSecret != "", Redirect: scheme + "://" + r.Host + "/login/oidc/callback"}})
}

func (s *Server) handleOIDCSettingsSave(w http.ResponseWriter, r *http.Request) {
	old := s.oidcSettings(r.Context())
	c := OIDCSettings{Issuer: strings.TrimRight(strings.TrimSpace(r.FormValue("issuer")), "/"), ClientID: strings.TrimSpace(r.FormValue("client_id")),
		Label: strings.TrimSpace(r.FormValue("label")), TrustMFA: r.FormValue("trust_mfa") != "", ClientSecret: old.ClientSecret}
	if sec := r.FormValue("client_secret"); sec != "" {
		c.ClientSecret = s.store.SealSecret("oidc.secret", sec)
	}
	if c.Issuer != "" && (!strings.HasPrefix(c.Issuer, "https://") && !strings.HasPrefix(c.Issuer, "http://127.0.0.1") || strings.ContainsAny(c.Issuer, " \"'<>")) {
		s.redirectErr(w, r, "/settings/signin", "The issuer must start with https://")
		return
	}
	if len(c.Label) > 60 || len(c.ClientID) > 200 {
		s.redirectErr(w, r, "/settings/signin", "Too long.")
		return
	}
	if c.Issuer == "" {
		c = OIDCSettings{}
	}
	if err := s.store.SetSetting(r.Context(), settingOIDC, c); err != nil {
		s.serverError(w, r, err)
		return
	}
	oidcCache.Lock()
	oidcCache.provider = nil
	oidcCache.Unlock()
	s.audit(r, "settings.oidc", "settings", "company sign-in %q (provider asks the second factor: %v)", c.Issuer, c.TrustMFA)
	s.redirect(w, r, "/settings/signin", "Saved.")
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
